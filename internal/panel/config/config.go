// Package config loads the Main server's configuration.
//
// A TOML file holds the layout, and environment variables override any value
// in it. Nothing in the file is required to be a secret: the master key, the
// database password and the initial admin password can all come from the
// environment instead, which is what keeps them out of the repository and out
// of an image layer.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/thehavlok/whitenet/internal/panel/secret"
)

// EnvPrefix prefixes every environment override, e.g. WN_DB_PASSWORD.
const EnvPrefix = "WN_"

// Config is the whole Main configuration.
type Config struct {
	// MasterKey protects every secret in the database. Losing it means
	// losing every Reality key and user password; changing it invalidates
	// them. Env: WN_MASTER_KEY.
	MasterKey string `toml:"master_key"`

	Database  Database  `toml:"database"`
	HTTP      HTTP      `toml:"http"`
	GRPC      GRPC      `toml:"grpc"`
	Node      Node      `toml:"node"`
	Retention Retention `toml:"retention"`
	Log       Log       `toml:"log"`
}

type Database struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Name     string `toml:"name"`
	User     string `toml:"user"`
	Password string `toml:"password"` // env: WN_DB_PASSWORD
	// Params are appended to the DSN. multiStatements is forced on because
	// the migration files contain more than one statement each.
	Params          map[string]string `toml:"params"`
	MaxOpenConns    int               `toml:"max_open_conns"`
	MaxIdleConns    int               `toml:"max_idle_conns"`
	ConnMaxLifetime Duration          `toml:"conn_max_lifetime"`
}

type HTTP struct {
	// Listen is the address the REST API, the admin UI and the subscription
	// endpoint share. TLS is terminated by the reverse proxy in front.
	Listen string `toml:"listen"`
	// PanelPath lets the admin UI live somewhere unguessable, e.g. /_p/9f3c.
	PanelPath string `toml:"panel_path"`
	// PanelDomain and SubDomain let the panel and the subscriptions be
	// served on different host names. Empty means "any host".
	PanelDomain string `toml:"panel_domain"`
	SubDomain   string `toml:"sub_domain"`
	// TrustedProxies are the CIDRs whose X-Forwarded-For is believed. Rate
	// limiting and the device ledger depend on a truthful client address.
	TrustedProxies []string `toml:"trusted_proxies"`
	ReadTimeout    Duration `toml:"read_timeout"`
	WriteTimeout   Duration `toml:"write_timeout"`
}

type GRPC struct {
	// Listen is where agents connect. A separate port from HTTP because it
	// needs mutual TLS and must not sit behind an HTTP proxy.
	Listen string `toml:"listen"`
	// Advertise is the host:port written into the install command. Defaults
	// to the panel's own host.
	Advertise string `toml:"advertise"`
	// ServerCert and ServerKey are the certificate agents verify. Empty
	// means Main issues one from its own node CA, which is enough because
	// agents pin that CA at enrolment.
	ServerCert string `toml:"server_cert"`
	ServerKey  string `toml:"server_key"`
}

type Node struct {
	// HeartbeatInterval is pushed to agents; a node is late after
	// OfflineAfter and then counted offline.
	HeartbeatInterval     Duration `toml:"heartbeat_interval"`
	OfflineAfter          Duration `toml:"offline_after"`
	MetricsInterval       Duration `toml:"metrics_interval"`
	TrafficReportInterval Duration `toml:"traffic_report_interval"`
	// CertTTL is how long an agent's client certificate is valid.
	CertTTL Duration `toml:"cert_ttl"`
	// TokenTTL is how long an unused enrolment token stays usable.
	TokenTTL Duration `toml:"token_ttl"`
	// OpenFluxLeaseTTL is how long a channel stays leased without a renewal.
	// Short enough that a client that vanished frees its channel quickly.
	OpenFluxLeaseTTL Duration `toml:"openflux_lease_ttl"`
}

// Retention controls how long observability data is kept. Metrics are the
// only table that grows on its own, so this is where disk use is bounded.
type Retention struct {
	RawMetrics    Duration `toml:"raw_metrics"`
	HourlyMetrics Duration `toml:"hourly_metrics"`
	Events        Duration `toml:"events"`
	TrafficDaily  Duration `toml:"traffic_daily"`
	AdminAudit    Duration `toml:"admin_audit"`
}

type Log struct {
	// Level: debug, info, warn, error. Format: text or json.
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Duration is a time.Duration that reads as a TOML string ("30s", "7d").
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalText accepts Go duration syntax plus a "d" suffix for days, which
// Go itself does not parse but a retention setting really wants.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// ParseDuration understands "90d" as well as everything time.ParseDuration
// accepts.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		// Reject "1m30d" and friends: only a plain number of days.
		days, err := strconv.ParseFloat(rest, 64)
		if err == nil {
			return time.Duration(days * 24 * float64(time.Hour)), nil
		}
	}
	return time.ParseDuration(s)
}

// Default returns a configuration that runs, apart from the secrets.
func Default() Config {
	return Config{
		Database: Database{
			Host:            "127.0.0.1",
			Port:            3306,
			Name:            "whitenet",
			User:            "whitenet",
			Params:          map[string]string{},
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: Duration(30 * time.Minute),
		},
		HTTP: HTTP{
			Listen:       "127.0.0.1:8080",
			PanelPath:    "/admin",
			ReadTimeout:  Duration(30 * time.Second),
			WriteTimeout: Duration(30 * time.Second),
		},
		GRPC: GRPC{
			Listen: "0.0.0.0:8443",
		},
		Node: Node{
			HeartbeatInterval:     Duration(15 * time.Second),
			OfflineAfter:          Duration(60 * time.Second),
			MetricsInterval:       Duration(30 * time.Second),
			TrafficReportInterval: Duration(60 * time.Second),
			CertTTL:               Duration(365 * 24 * time.Hour),
			TokenTTL:              Duration(24 * time.Hour),
			OpenFluxLeaseTTL:      Duration(5 * time.Minute),
		},
		Retention: Retention{
			RawMetrics:    Duration(48 * time.Hour),
			HourlyMetrics: Duration(90 * 24 * time.Hour),
			Events:        Duration(30 * 24 * time.Hour),
			TrafficDaily:  Duration(365 * 24 * time.Hour),
			AdminAudit:    Duration(365 * 24 * time.Hour),
		},
		Log: Log{Level: "info", Format: "text"},
	}
}

// Load reads the file at path, applies environment overrides and validates
// the result. An empty path means defaults plus the environment, which is how
// the Docker image runs.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			return cfg, fmt.Errorf("config: read %s: %w", path, err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// applyEnv overrides the fields an operator is most likely to supply through
// the environment. Only these: a config file is easier to read than thirty
// generated variable names, and the ones here are exactly the secrets and the
// values Docker Compose has to set.
func applyEnv(cfg *Config) {
	envString(&cfg.MasterKey, "MASTER_KEY")
	envString(&cfg.Database.Host, "DB_HOST")
	envInt(&cfg.Database.Port, "DB_PORT")
	envString(&cfg.Database.Name, "DB_NAME")
	envString(&cfg.Database.User, "DB_USER")
	envString(&cfg.Database.Password, "DB_PASSWORD")
	envString(&cfg.HTTP.Listen, "HTTP_LISTEN")
	envString(&cfg.HTTP.PanelPath, "PANEL_PATH")
	envString(&cfg.HTTP.PanelDomain, "PANEL_DOMAIN")
	envString(&cfg.HTTP.SubDomain, "SUB_DOMAIN")
	envList(&cfg.HTTP.TrustedProxies, "TRUSTED_PROXIES")
	envString(&cfg.GRPC.Listen, "GRPC_LISTEN")
	envString(&cfg.GRPC.Advertise, "GRPC_ADVERTISE")
	envString(&cfg.Log.Level, "LOG_LEVEL")
	envString(&cfg.Log.Format, "LOG_FORMAT")
}

func envString(target *string, key string) {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok {
		*target = v
	}
}

// envList reads a comma-separated list. Compose needs it: the reverse proxy's
// address inside a Docker network is assigned at run time, so the trusted
// proxy range cannot be baked into a config file.
func envList(target *[]string, key string) {
	v, ok := os.LookupEnv(EnvPrefix + key)
	if !ok {
		return
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	// An explicitly empty value means "trust nothing", which is different
	// from "not set", so the result is assigned either way.
	*target = out
}

func envInt(target *int, key string) {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			*target = n
		}
	}
}

// Validate rejects a configuration that would fail later, at a point where
// the cause is harder to see.
func (c Config) Validate() error {
	if _, err := secret.ParseKey(c.MasterKey); err != nil {
		return fmt.Errorf("config: master_key: %w", err)
	}
	// A short passphrase is accepted by ParseKey (it hashes anything), so
	// the length floor lives here, where it is a policy decision.
	if len(c.MasterKey) < 32 {
		return errors.New("config: master_key must be at least 32 characters (64 hex characters is the expected form)")
	}
	if c.Database.Host == "" || c.Database.Name == "" || c.Database.User == "" {
		return errors.New("config: database host, name and user are required")
	}
	if c.HTTP.Listen == "" {
		return errors.New("config: http.listen is required")
	}
	if c.GRPC.Listen == "" {
		return errors.New("config: grpc.listen is required")
	}
	if !strings.HasPrefix(c.HTTP.PanelPath, "/") {
		return fmt.Errorf("config: http.panel_path must start with /, got %q", c.HTTP.PanelPath)
	}
	if c.Node.OfflineAfter.Duration() <= c.Node.HeartbeatInterval.Duration() {
		return errors.New("config: node.offline_after must be longer than node.heartbeat_interval")
	}
	return nil
}

// DSN builds the MariaDB data source name.
//
// multiStatements is forced on for the migration files, parseTime so DATETIME
// columns scan into time.Time, and loc/time_zone are pinned to UTC because
// every timestamp in the schema is UTC by convention.
func (d Database) DSN() string {
	params := url.Values{}
	params.Set("parseTime", "true")
	params.Set("multiStatements", "true")
	params.Set("loc", "UTC")
	params.Set("time_zone", "'+00:00'")
	params.Set("charset", "utf8mb4")
	params.Set("collation", "utf8mb4_unicode_ci")
	for k, v := range d.Params {
		params.Set(k, v)
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?%s",
		d.User, d.Password, d.Host, d.Port, d.Name, params.Encode())
}

// Redacted returns the DSN with the password removed, for logs.
func (d Database) Redacted() string {
	return fmt.Sprintf("%s:***@tcp(%s:%d)/%s", d.User, d.Host, d.Port, d.Name)
}
