package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Setting keys. They are constants so a typo is a compile error rather than a
// silently missing value.
const (
	// SettingBranding is the subscription page's look and the branding block
	// in the subscription JSON.
	SettingBranding = "branding"
	// SettingDomains is the panel and subscription host names and the agent
	// endpoint written into install commands.
	SettingDomains = "domains"
	// SettingUserDefaults is what a new user gets when the form is left
	// empty.
	SettingUserDefaults = "user_defaults"
	// SettingSubscription is the refresh interval and the rate limit.
	SettingSubscription = "subscription"
	// SettingCAName is the name of the CA row in `ca_keys`.
	SettingCAName = "node-ca"
)

// Branding is what an operator can change without a new app build.
type Branding struct {
	AppName     string `json:"app_name"`
	LogoURL     string `json:"logo_url"`
	SupportURL  string `json:"support_url"`
	Message     string `json:"message"`
	AccentColor string `json:"accent_color"`
	// Download links shown on the subscription page.
	AndroidURL string `json:"android_url"`
	IOSURL     string `json:"ios_url"`
	WindowsURL string `json:"windows_url"`
	MacOSURL   string `json:"macos_url"`
	LinuxURL   string `json:"linux_url"`
	// InstructionsHTML is shown under the download buttons. It is rendered as
	// trusted HTML, because only an admin can set it.
	InstructionsHTML string `json:"instructions_html"`
}

// DefaultBranding is what a fresh panel shows.
func DefaultBranding() Branding {
	return Branding{
		AppName:     "WhiteNetVPN",
		AccentColor: "#3b82f6",
	}
}

// Domains is where the panel answers.
type Domains struct {
	// PanelURL is the panel's public base URL, used in install commands.
	PanelURL string `json:"panel_url"`
	// SubBaseURL is the base of subscription links. Keeping it apart from the
	// panel means a blocked subscription domain does not take the panel with
	// it.
	SubBaseURL string `json:"sub_base_url"`
	// AgentEndpoint is the host:port agents connect to.
	AgentEndpoint string `json:"agent_endpoint"`
}

// UserDefaults is what a new user gets.
type UserDefaults struct {
	TrafficLimitBytes uint64   `json:"traffic_limit_bytes"`
	ValidDays         int      `json:"valid_days"`
	DevicesLimit      uint32   `json:"devices_limit"`
	GroupIDs          []uint64 `json:"group_ids"`
}

// SubscriptionSettings controls the subscription endpoint.
type SubscriptionSettings struct {
	UpdateIntervalHours int `json:"update_interval_hours"`
	// RateLimitPerMinute bounds requests per client address, so the token
	// space cannot be walked.
	RateLimitPerMinute int `json:"rate_limit_per_minute"`
	// CacheSeconds is how long a rendered subscription is reused. A fetch
	// every few minutes from every device would otherwise be a query storm.
	CacheSeconds int `json:"cache_seconds"`
	// IncludeOfflineNodes serves nodes that are down. Off by default: handing
	// a client a dead server is worse than handing it one fewer.
	IncludeOfflineNodes bool `json:"include_offline_nodes"`
}

// DefaultSubscriptionSettings is what a fresh panel uses.
func DefaultSubscriptionSettings() SubscriptionSettings {
	return SubscriptionSettings{
		UpdateIntervalHours: 12,
		RateLimitPerMinute:  30,
		CacheSeconds:        30,
	}
}

// GetSetting reads one key into out. A missing key leaves out untouched and
// returns false, so a caller can keep its defaults.
func (s *Store) GetSetting(ctx context.Context, key string, out any) (bool, error) {
	var raw []byte
	err := s.DB.GetContext(ctx, &raw, `SELECT v FROM settings WHERE k = ?`, key)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read setting %s: %w", key, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("store: parse setting %s: %w", key, err)
	}
	return true, nil
}

// SetSetting writes one key.
func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("store: marshal setting %s: %w", key, err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO settings (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)`,
		key, string(raw)); err != nil {
		return fmt.Errorf("store: write setting %s: %w", key, err)
	}
	return nil
}

// Branding reads the branding settings, falling back to the defaults.
func (s *Store) Branding(ctx context.Context) (Branding, error) {
	branding := DefaultBranding()
	if _, err := s.GetSetting(ctx, SettingBranding, &branding); err != nil {
		return branding, err
	}
	return branding, nil
}

// Domains reads the domain settings.
func (s *Store) Domains(ctx context.Context) (Domains, error) {
	var domains Domains
	if _, err := s.GetSetting(ctx, SettingDomains, &domains); err != nil {
		return domains, err
	}
	return domains, nil
}

// UserDefaults reads the defaults for new users.
func (s *Store) UserDefaults(ctx context.Context) (UserDefaults, error) {
	var defaults UserDefaults
	if _, err := s.GetSetting(ctx, SettingUserDefaults, &defaults); err != nil {
		return defaults, err
	}
	return defaults, nil
}

// SubscriptionSettings reads the subscription settings.
func (s *Store) SubscriptionSettings(ctx context.Context) (SubscriptionSettings, error) {
	settings := DefaultSubscriptionSettings()
	if _, err := s.GetSetting(ctx, SettingSubscription, &settings); err != nil {
		return settings, err
	}
	// A zero interval would make an app refetch in a tight loop.
	if settings.UpdateIntervalHours <= 0 {
		settings.UpdateIntervalHours = DefaultSubscriptionSettings().UpdateIntervalHours
	}
	return settings, nil
}

// ---------------------------------------------------------------------------
// The node CA
// ---------------------------------------------------------------------------

// StoredCA is the CA row.
type StoredCA struct {
	Name     string    `db:"name"`
	CertPEM  string    `db:"cert_pem"`
	KeyPEM   []byte    `db:"key_pem"`
	NotAfter time.Time `db:"not_after"`
}

// LoadCA reads the node CA, or nil when the panel has not made one yet.
func (s *Store) LoadCA(ctx context.Context, name string) (*StoredCA, error) {
	var ca StoredCA
	err := s.DB.GetContext(ctx, &ca,
		`SELECT name, cert_pem, key_pem, not_after FROM ca_keys WHERE name = ?`, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: load CA %s: %w", name, err)
	}
	return &ca, nil
}

// SaveCA stores the node CA. The key arrives encrypted: this layer never sees
// the master key.
func (s *Store) SaveCA(ctx context.Context, name, certPEM string, encryptedKeyPEM []byte, notAfter time.Time) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO ca_keys (name, cert_pem, key_pem, not_after) VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE cert_pem = VALUES(cert_pem), key_pem = VALUES(key_pem), not_after = VALUES(not_after)`,
		name, certPEM, encryptedKeyPEM, notAfter.UTC()); err != nil {
		return fmt.Errorf("store: save CA %s: %w", name, err)
	}
	return nil
}
