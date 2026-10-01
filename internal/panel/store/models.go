package store

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// The row types mirror the schema. They are deliberately plain: the API layer
// maps them to its own shapes, so a column rename does not leak into a JSON
// field name the app depends on.

// Node status values, matching the enum in the schema.
const (
	NodeOnline   = "online"
	NodeOffline  = "offline"
	NodeDegraded = "degraded"
)

// User status values.
const (
	UserActive   = "active"
	UserDisabled = "disabled"
	UserExpired  = "expired"
	UserLimited  = "limited"
)

// Protocol values, matching the enum in the schema and the subscription
// format.
const (
	ProtoVLESS           = "vless"
	ProtoVMess           = "vmess"
	ProtoTrojan          = "trojan"
	ProtoShadowsocks     = "shadowsocks"
	ProtoShadowsocks2022 = "shadowsocks2022"
	ProtoHysteria2       = "hysteria2"
	ProtoWNDNS           = "wndns"
)

// Node is a row of `nodes`.
type Node struct {
	ID      uint64 `db:"id"`
	UUID    string `db:"uuid"`
	Name    string `db:"name"`
	Address string `db:"address"`

	CountryCode sql.NullString `db:"country_code"`
	DisplayName sql.NullString `db:"display_name"`
	Notes       sql.NullString `db:"notes"`

	Enabled      bool           `db:"enabled"`
	Status       string         `db:"status"`
	StatusReason sql.NullString `db:"status_reason"`
	LastSeenAt   sql.NullTime   `db:"last_seen_at"`
	ConnectedAt  sql.NullTime   `db:"connected_at"`

	ConfigVersion  uint64         `db:"config_version"`
	AppliedVersion uint64         `db:"applied_version"`
	ApplyError     sql.NullString `db:"apply_error"`

	AgentVersion    sql.NullString `db:"agent_version"`
	XrayVersion     sql.NullString `db:"xray_version"`
	WNDNSVersion    sql.NullString `db:"wndns_version"`
	OpenFluxVersion sql.NullString `db:"openflux_version"`

	Hostname      sql.NullString `db:"hostname"`
	OS            sql.NullString `db:"os"`
	Arch          sql.NullString `db:"arch"`
	CPUCores      sql.NullInt64  `db:"cpu_cores"`
	MemTotalBytes sql.NullInt64  `db:"mem_total_bytes"`
	OnlineUsers   uint32         `db:"online_users"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// Country returns the country code or an empty string.
func (n Node) Country() string { return n.CountryCode.String }

// Label is what a client shows: the display name if set, otherwise the name.
func (n Node) Label() string {
	if n.DisplayName.Valid && n.DisplayName.String != "" {
		return n.DisplayName.String
	}
	return n.Name
}

// InSync reports whether the node has applied the configuration it was given.
func (n Node) InSync() bool { return n.AppliedVersion == n.ConfigVersion }

// Group is a row of `node_groups`.
type Group struct {
	ID          uint64         `db:"id"`
	UUID        string         `db:"uuid"`
	Name        string         `db:"name"`
	Description sql.NullString `db:"description"`
	SortOrder   int            `db:"sort_order"`
	CreatedAt   time.Time      `db:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"`
}

// NodeToken is a row of `node_tokens`.
type NodeToken struct {
	ID        uint64         `db:"id"`
	NodeID    uint64         `db:"node_id"`
	CreatedBy sql.NullInt64  `db:"created_by"`
	ExpiresAt time.Time      `db:"expires_at"`
	UsedAt    sql.NullTime   `db:"used_at"`
	UsedIP    sql.NullString `db:"used_ip"`
	CreatedAt time.Time      `db:"created_at"`
}

// NodeCert is a row of `node_certs`.
type NodeCert struct {
	ID          uint64       `db:"id"`
	NodeID      uint64       `db:"node_id"`
	Serial      string       `db:"serial"`
	Fingerprint []byte       `db:"fingerprint"`
	CertPEM     string       `db:"cert_pem"`
	NotBefore   time.Time    `db:"not_before"`
	NotAfter    time.Time    `db:"not_after"`
	RevokedAt   sql.NullTime `db:"revoked_at"`
	CreatedAt   time.Time    `db:"created_at"`
}

// InboundTemplate is a row of `inbound_templates`.
type InboundTemplate struct {
	ID         uint64        `db:"id"`
	UUID       string        `db:"uuid"`
	Name       string        `db:"name"`
	Protocol   string        `db:"protocol"`
	Network    string        `db:"network"`
	Security   string        `db:"security"`
	ListenPort sql.NullInt64 `db:"listen_port"`
	Params     JSONMap       `db:"params"`
	Secrets    []byte        `db:"secrets"`
	Enabled    bool          `db:"enabled"`
	CreatedAt  time.Time     `db:"created_at"`
	UpdatedAt  time.Time     `db:"updated_at"`
}

// NodeInbound is a row of `node_inbounds`.
type NodeInbound struct {
	ID         uint64        `db:"id"`
	NodeID     uint64        `db:"node_id"`
	TemplateID sql.NullInt64 `db:"template_id"`
	Tag        string        `db:"tag"`
	Protocol   string        `db:"protocol"`
	Network    string        `db:"network"`
	Security   string        `db:"security"`

	ListenAddress string `db:"listen_address"`
	ListenPort    uint32 `db:"listen_port"`

	Overrides JSONMap `db:"overrides"`
	Params    JSONMap `db:"params"`
	Secrets   []byte  `db:"secrets"`

	ForwardToTag sql.NullString `db:"forward_to_tag"`
	Published    bool           `db:"published"`
	Enabled      bool           `db:"enabled"`
	SortOrder    int            `db:"sort_order"`
	CreatedAt    time.Time      `db:"created_at"`
	UpdatedAt    time.Time      `db:"updated_at"`
}

// NodeOpenFlux is a row of `node_openflux`.
type NodeOpenFlux struct {
	NodeID    uint64    `db:"node_id"`
	Enabled   bool      `db:"enabled"`
	Mode      string    `db:"mode"`
	Params    JSONMap   `db:"params"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// OpenFluxChannel is a row of `openflux_channels`.
type OpenFluxChannel struct {
	ID        uint64  `db:"id"`
	UUID      string  `db:"uuid"`
	NodeID    uint64  `db:"node_id"`
	Name      string  `db:"name"`
	Transport string  `db:"transport"`
	URL       string  `db:"url"`
	Params    JSONMap `db:"params"`

	EncryptionKey  []byte         `db:"encryption_key"`
	SessionContext sql.NullString `db:"session_context"`
	Credentials    []byte         `db:"credentials"`

	Enabled       bool           `db:"enabled"`
	SessionActive bool           `db:"session_active"`
	LastError     sql.NullString `db:"last_error"`
	CreatedAt     time.Time      `db:"created_at"`
	UpdatedAt     time.Time      `db:"updated_at"`
}

// OpenFluxLease is a row of `openflux_leases`.
type OpenFluxLease struct {
	ID            uint64         `db:"id"`
	ChannelID     uint64         `db:"channel_id"`
	UserID        uint64         `db:"user_id"`
	DeviceID      sql.NullInt64  `db:"device_id"`
	Active        sql.NullBool   `db:"active"`
	AcquiredAt    time.Time      `db:"acquired_at"`
	RenewedAt     time.Time      `db:"renewed_at"`
	ExpiresAt     time.Time      `db:"expires_at"`
	ReleasedAt    sql.NullTime   `db:"released_at"`
	ReleaseReason sql.NullString `db:"release_reason"`
}

// User is a row of `users`.
type User struct {
	ID      uint64         `db:"id"`
	UUID    string         `db:"uuid"`
	Name    string         `db:"name"`
	Comment sql.NullString `db:"comment"`

	SubToken         string    `db:"sub_token"`
	SubTokenIssuedAt time.Time `db:"sub_token_issued_at"`

	VLESSUUID  string `db:"vless_uuid"`
	Password   []byte `db:"password"`
	SSPassword []byte `db:"ss_password"`

	ExpiresAt    sql.NullTime `db:"expires_at"`
	TrafficLimit uint64       `db:"traffic_limit"`
	TrafficUsed  uint64       `db:"traffic_used"`
	DevicesLimit uint32       `db:"devices_limit"`

	ResetStrategy string       `db:"reset_strategy"`
	NextResetAt   sql.NullTime `db:"next_reset_at"`
	LastResetAt   sql.NullTime `db:"last_reset_at"`

	Status string `db:"status"`

	LastSubFetchAt sql.NullTime `db:"last_sub_fetch_at"`
	CreatedAt      time.Time    `db:"created_at"`
	UpdatedAt      time.Time    `db:"updated_at"`
}

// Usable reports whether the user may connect right now. Only `active` may:
// the other three statuses all mean "not now", and the panel writes them so
// the reason survives in the list.
func (u User) Usable() bool { return u.Status == UserActive }

// OverTrafficLimit reports whether the user has used their allowance. A limit
// of 0 is unlimited.
func (u User) OverTrafficLimit() bool {
	return u.TrafficLimit > 0 && u.TrafficUsed >= u.TrafficLimit
}

// Expired reports whether the user's time is up. A null expiry never expires.
func (u User) Expired(now time.Time) bool {
	return u.ExpiresAt.Valid && !u.ExpiresAt.Time.After(now)
}

// Device is a row of `user_devices`.
type Device struct {
	ID          uint64         `db:"id"`
	UserID      uint64         `db:"user_id"`
	HWID        string         `db:"hwid"`
	Model       sql.NullString `db:"model"`
	Platform    sql.NullString `db:"platform"`
	AppVersion  sql.NullString `db:"app_version"`
	FirstSeenAt time.Time      `db:"first_seen_at"`
	LastSeenAt  time.Time      `db:"last_seen_at"`
	LastIP      sql.NullString `db:"last_ip"`
}

// Admin is a row of `admins`.
type Admin struct {
	ID           uint64         `db:"id"`
	Username     string         `db:"username"`
	PasswordHash string         `db:"password_hash"`
	TOTPSecret   []byte         `db:"totp_secret"`
	TOTPEnabled  bool           `db:"totp_enabled"`
	Role         string         `db:"role"`
	IsActive     bool           `db:"is_active"`
	FailedLogins uint32         `db:"failed_logins"`
	LockedUntil  sql.NullTime   `db:"locked_until"`
	LastLoginAt  sql.NullTime   `db:"last_login_at"`
	LastLoginIP  sql.NullString `db:"last_login_ip"`
	CreatedAt    time.Time      `db:"created_at"`
	UpdatedAt    time.Time      `db:"updated_at"`
}

// Locked reports whether the account is temporarily barred from logging in.
func (a Admin) Locked(now time.Time) bool {
	return a.LockedUntil.Valid && a.LockedUntil.Time.After(now)
}

// Event is a row of `events`.
type Event struct {
	ID       uint64         `db:"id"`
	At       time.Time      `db:"at"`
	Severity string         `db:"severity"`
	Type     string         `db:"type"`
	Core     sql.NullString `db:"core"`
	NodeID   sql.NullInt64  `db:"node_id"`
	UserID   sql.NullInt64  `db:"user_id"`
	Message  string         `db:"message"`
	Details  JSONDoc        `db:"details"`
}

// AuditEntry is a row of `admin_audit`.
type AuditEntry struct {
	ID            uint64         `db:"id"`
	At            time.Time      `db:"at"`
	AdminID       sql.NullInt64  `db:"admin_id"`
	AdminUsername sql.NullString `db:"admin_username"`
	Action        string         `db:"action"`
	ObjectType    sql.NullString `db:"object_type"`
	ObjectID      sql.NullString `db:"object_id"`
	IP            sql.NullString `db:"ip"`
	Details       JSONDoc        `db:"details"`
}

// MetricSample is a row of `node_metrics`.
type MetricSample struct {
	NodeID         uint64          `db:"node_id"`
	At             time.Time       `db:"at"`
	CPUPercent     sql.NullFloat64 `db:"cpu_percent"`
	Load1          sql.NullFloat64 `db:"load1"`
	MemUsedBytes   sql.NullInt64   `db:"mem_used_bytes"`
	MemTotalBytes  sql.NullInt64   `db:"mem_total_bytes"`
	DiskUsedBytes  sql.NullInt64   `db:"disk_used_bytes"`
	DiskTotalBytes sql.NullInt64   `db:"disk_total_bytes"`
	NetRxBytes     sql.NullInt64   `db:"net_rx_bytes"`
	NetTxBytes     sql.NullInt64   `db:"net_tx_bytes"`
	UptimeSeconds  sql.NullInt64   `db:"uptime_seconds"`
	OnlineUsers    sql.NullInt64   `db:"online_users"`
	TCPConnections sql.NullInt64   `db:"tcp_connections"`
}

// JSONDoc is an arbitrary JSON document from a JSON column.
//
// It exists because the event and audit details are not a flat map: they hold
// numbers, lists and nested objects - a restarted core's list, a bulk action's
// user ids, a traffic figure. Typing them as strings looked fine until the
// first event carried a number.
type JSONDoc []byte

// Scan implements sql.Scanner.
func (d *JSONDoc) Scan(src any) error {
	switch value := src.(type) {
	case nil:
		*d = nil
		return nil
	case []byte:
		*d = append((*d)[:0], value...)
		return nil
	case string:
		*d = []byte(value)
		return nil
	default:
		return fmt.Errorf("store: cannot scan %T into a JSON document", src)
	}
}

// Value implements driver.Valuer. The return type has to be driver.Value
// rather than any: they have the same underlying type, but the interface is
// satisfied only by the exact signature, and getting it wrong fails at run
// time with "unsupported type" rather than at compile time.
func (d JSONDoc) Value() (driver.Value, error) {
	if len(d) == 0 {
		return nil, nil
	}
	return string(d), nil
}

// MarshalJSON passes the stored document through unchanged, so the API returns
// what was recorded rather than a re-encoding of it. An empty or malformed
// value becomes null, because a broken detail must not break a list.
func (d JSONDoc) MarshalJSON() ([]byte, error) {
	if len(d) == 0 {
		return []byte("null"), nil
	}
	if !json.Valid(d) {
		return []byte("null"), nil
	}
	return d, nil
}

// UnmarshalJSON stores the document as given.
func (d *JSONDoc) UnmarshalJSON(raw []byte) error {
	*d = append((*d)[:0], raw...)
	return nil
}

// Map decodes the document into a map, for the few callers that want to read a
// field out of it.
func (d JSONDoc) Map() map[string]any {
	if len(d) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(d, &out); err != nil {
		return nil
	}
	return out
}

// JSONMap is a map of strings stored in a JSON column.
//
// The protocol-specific knobs are flat strings everywhere - in the schema, on
// the wire to the agent, in the subscription - so there is one shape to reason
// about rather than a different one per layer.
type JSONMap map[string]string

// Scan implements sql.Scanner.
func (m *JSONMap) Scan(src any) error {
	*m = JSONMap{}
	switch value := src.(type) {
	case nil:
		return nil
	case []byte:
		if len(value) == 0 {
			return nil
		}
		return json.Unmarshal(value, m)
	case string:
		if value == "" {
			return nil
		}
		return json.Unmarshal([]byte(value), m)
	default:
		return errUnsupportedScan(src)
	}
}

// Value implements driver.Valuer. An empty map is stored as {} rather than
// NULL, so a reader never has to handle both.
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(raw), nil
}

// Get returns a key or an empty string, so callers do not need the two-value
// form everywhere.
func (m JSONMap) Get(key string) string { return m[key] }

// Merge returns a copy of m with other's keys applied on top. This is how a
// template's parameters and a node's overrides become one effective set.
func (m JSONMap) Merge(other JSONMap) JSONMap {
	out := make(JSONMap, len(m)+len(other))
	for k, v := range m {
		out[k] = v
	}
	for k, v := range other {
		// An override to the empty string removes the key, which is how a
		// node turns off something a template set.
		if v == "" {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

// These assertions exist because a Valuer with the wrong signature compiles
// cleanly and then fails at run time with "unsupported type". Stating the
// interfaces here turns that into a build error.
var (
	_ driver.Valuer = JSONMap{}
	_ driver.Valuer = JSONDoc{}
	_ sql.Scanner   = (*JSONMap)(nil)
	_ sql.Scanner   = (*JSONDoc)(nil)
)
