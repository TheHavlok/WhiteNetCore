package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"30s":   30 * time.Second,
		"5m":    5 * time.Minute,
		"1h30m": 90 * time.Minute,
		"7d":    7 * 24 * time.Hour,
		"0.5d":  12 * time.Hour,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseDuration(""); err == nil {
		t.Error("empty duration was accepted")
	}
	if _, err := ParseDuration("tomorrow"); err == nil {
		t.Error("nonsense duration was accepted")
	}
}

func TestLoadAppliesFileThenEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.toml")
	body := `
master_key = "` + validKey + `"

[database]
host = "db.internal"
name = "panel"
user = "panel"
password = "from-file"

[http]
listen = "0.0.0.0:9000"
panel_path = "/_p/abcd"

[node]
heartbeat_interval = "10s"
offline_after = "45s"

[retention]
raw_metrics = "12h"
hourly_metrics = "30d"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// The environment must win over the file, which is what lets Compose
	// supply the password without it being in the mounted config.
	t.Setenv("WN_DB_PASSWORD", "from-env")
	t.Setenv("WN_HTTP_LISTEN", "127.0.0.1:1234")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Host != "db.internal" {
		t.Errorf("database.host = %q", cfg.Database.Host)
	}
	if cfg.Database.Password != "from-env" {
		t.Errorf("database.password = %q, want the environment value", cfg.Database.Password)
	}
	if cfg.HTTP.Listen != "127.0.0.1:1234" {
		t.Errorf("http.listen = %q, want the environment value", cfg.HTTP.Listen)
	}
	if cfg.HTTP.PanelPath != "/_p/abcd" {
		t.Errorf("http.panel_path = %q", cfg.HTTP.PanelPath)
	}
	if cfg.Node.HeartbeatInterval.Duration() != 10*time.Second {
		t.Errorf("node.heartbeat_interval = %v", cfg.Node.HeartbeatInterval)
	}
	if cfg.Retention.RawMetrics.Duration() != 12*time.Hour {
		t.Errorf("retention.raw_metrics = %v", cfg.Retention.RawMetrics)
	}
	if cfg.Retention.HourlyMetrics.Duration() != 30*24*time.Hour {
		t.Errorf("retention.hourly_metrics = %v", cfg.Retention.HourlyMetrics)
	}
	// Values absent from the file keep their defaults.
	if cfg.GRPC.Listen != Default().GRPC.Listen {
		t.Errorf("grpc.listen = %q, want the default", cfg.GRPC.Listen)
	}
}

func TestValidate(t *testing.T) {
	base := func() Config {
		cfg := Default()
		cfg.MasterKey = validKey
		return cfg
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("the default configuration with a master key must validate: %v", err)
	}

	cases := map[string]func(*Config){
		"empty master key":    func(c *Config) { c.MasterKey = "" },
		"short master key":    func(c *Config) { c.MasterKey = "too-short" },
		"no database name":    func(c *Config) { c.Database.Name = "" },
		"no http listen":      func(c *Config) { c.HTTP.Listen = "" },
		"no grpc listen":      func(c *Config) { c.GRPC.Listen = "" },
		"relative panel path": func(c *Config) { c.HTTP.PanelPath = "admin" },
		"offline before beat": func(c *Config) { c.Node.OfflineAfter = c.Node.HeartbeatInterval },
	}
	for name, mutate := range cases {
		cfg := base()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestDSN(t *testing.T) {
	cfg := Default()
	cfg.Database.Password = "p@ss word"
	dsn := cfg.Database.DSN()

	// multiStatements is what lets a migration file hold more than one
	// statement, and parseTime is what makes DATETIME columns scan into
	// time.Time. Both are load-bearing, so assert on them.
	for _, want := range []string{"multiStatements=true", "parseTime=true", "loc=UTC", "charset=utf8mb4"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("DSN is missing %s: %s", want, dsn)
		}
	}
	if !strings.HasPrefix(dsn, "whitenet:p@ss word@tcp(127.0.0.1:3306)/whitenet?") {
		t.Errorf("unexpected DSN prefix: %s", dsn)
	}
	if strings.Contains(cfg.Database.Redacted(), "p@ss word") {
		t.Error("Redacted leaked the password")
	}
}

func TestLoadWithoutFileUsesDefaultsAndEnv(t *testing.T) {
	t.Setenv("WN_MASTER_KEY", validKey)
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MasterKey != validKey {
		t.Error("master key did not come from the environment")
	}
	if cfg.Database.Name != Default().Database.Name {
		t.Errorf("database.name = %q, want the default", cfg.Database.Name)
	}
}

func TestEnvTrustedProxiesOverride(t *testing.T) {
	// Compose supplies this, so both the list form and the deliberate
	// "trust nothing" form have to survive the round trip.
	t.Setenv("WN_TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12")
	cfg := Default()
	applyEnv(&cfg)
	if got := cfg.HTTP.TrustedProxies; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "172.16.0.0/12" {
		t.Fatalf("trusted proxies = %q", got)
	}

	t.Setenv("WN_TRUSTED_PROXIES", "")
	cfg = Default()
	cfg.HTTP.TrustedProxies = []string{"127.0.0.1/32"}
	applyEnv(&cfg)
	if len(cfg.HTTP.TrustedProxies) != 0 {
		t.Fatalf("an empty value should clear the list, got %q", cfg.HTTP.TrustedProxies)
	}
}
