// Package config loads the node agent's configuration.
//
// The agent's configuration is deliberately tiny. Everything about how a node
// serves traffic - inbounds, users, keys, which cores run - is desired state
// pushed by Main, so it has no business being in a file on the node. What is
// here is only what the agent needs in order to reach Main and find its own
// files.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// EnvPrefix prefixes every environment override, e.g. WN_AGENT_MAIN.
const EnvPrefix = "WN_AGENT_"

// DefaultPath is where the installer puts the configuration file.
const DefaultPath = "/etc/whitenet-agent/agent.toml"

type Config struct {
	// Main is the agent's gRPC endpoint on the panel, host:port.
	Main string `toml:"main"`

	// DataDir holds the agent's identity (key, certificate), the last state
	// it applied and its core configurations.
	DataDir string `toml:"data_dir"`
	// BinDir holds the supervised core binaries: xray, whitenet (the DNS
	// tunnel) and openflux.
	BinDir string `toml:"bin_dir"`

	// Token is the one-time enrolment token. The agent clears it from the
	// file as soon as enrolment succeeds, so a stale copy cannot be reused.
	Token string `toml:"token"`

	// CAFingerprint pins Main's CA at install time. Without it, the first
	// connection would have to trust whatever certificate it is offered.
	CAFingerprint string `toml:"ca_fingerprint"`

	Reconnect Reconnect `toml:"reconnect"`
	Cores     Cores     `toml:"cores"`
	Log       Log       `toml:"log"`
}

// Reconnect is the backoff for a lost Session stream. The agent keeps serving
// traffic from its last applied state throughout, so a long outage is not an
// outage for users.
type Reconnect struct {
	InitialDelay Duration `toml:"initial_delay"`
	MaxDelay     Duration `toml:"max_delay"`
	// Multiplier and Jitter spread reconnects so a fleet does not retry in
	// lockstep after Main restarts.
	Multiplier float64  `toml:"multiplier"`
	Jitter     float64  `toml:"jitter"`
	Timeout    Duration `toml:"timeout"`
}

// Cores locates the supervised processes and their control sockets.
type Cores struct {
	// XrayBinary, WNDNSBinary and OpenFluxBinary are resolved against BinDir
	// when they are not absolute.
	XrayBinary     string `toml:"xray_binary"`
	WNDNSBinary    string `toml:"wndns_binary"`
	OpenFluxBinary string `toml:"openflux_binary"`

	// XrayAPIAddress is the local address of Xray's gRPC API, used to add
	// and remove users without a restart and to read traffic counters. It
	// must stay on the loopback interface.
	XrayAPIAddress string `toml:"xray_api_address"`

	// RestartBackoff is the delay before restarting a core that died, and
	// RestartBackoffMax the ceiling for a core that keeps dying.
	RestartBackoff    Duration `toml:"restart_backoff"`
	RestartBackoffMax Duration `toml:"restart_backoff_max"`
	// StartTimeout is how long a core gets to come up before the attempt
	// counts as a failure.
	StartTimeout Duration `toml:"start_timeout"`
	// StopTimeout is how long a core gets to exit on SIGTERM before SIGKILL.
	StopTimeout Duration `toml:"stop_timeout"`
}

type Log struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Duration is a time.Duration that reads as a TOML string.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(strings.TrimSpace(string(text)))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func Default() Config {
	return Config{
		DataDir: "/var/lib/whitenet-agent",
		BinDir:  "/usr/local/lib/whitenet-agent/bin",
		Reconnect: Reconnect{
			InitialDelay: Duration(time.Second),
			MaxDelay:     Duration(5 * time.Minute),
			Multiplier:   2,
			Jitter:       0.2,
			Timeout:      Duration(20 * time.Second),
		},
		Cores: Cores{
			XrayBinary:        "xray",
			WNDNSBinary:       "whitenet",
			OpenFluxBinary:    "openflux",
			XrayAPIAddress:    "127.0.0.1:10085",
			RestartBackoff:    Duration(2 * time.Second),
			RestartBackoffMax: Duration(2 * time.Minute),
			StartTimeout:      Duration(15 * time.Second),
			StopTimeout:       Duration(10 * time.Second),
		},
		Log: Log{Level: "info", Format: "text"},
	}
}

// Load reads the file, applies environment overrides and validates.
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

func applyEnv(cfg *Config) {
	envString(&cfg.Main, "MAIN")
	envString(&cfg.Token, "TOKEN")
	envString(&cfg.CAFingerprint, "CA_FINGERPRINT")
	envString(&cfg.DataDir, "DATA_DIR")
	envString(&cfg.BinDir, "BIN_DIR")
	envString(&cfg.Log.Level, "LOG_LEVEL")
	envString(&cfg.Log.Format, "LOG_FORMAT")
}

func envString(target *string, key string) {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok {
		*target = v
	}
}

func (c Config) Validate() error {
	if c.Main == "" {
		return errors.New("config: main is required (host:port of the panel's agent endpoint)")
	}
	if c.DataDir == "" {
		return errors.New("config: data_dir is required")
	}
	if c.Reconnect.Multiplier < 1 {
		return fmt.Errorf("config: reconnect.multiplier must be at least 1, got %v", c.Reconnect.Multiplier)
	}
	if c.Reconnect.Jitter < 0 || c.Reconnect.Jitter > 1 {
		return fmt.Errorf("config: reconnect.jitter must be within [0,1], got %v", c.Reconnect.Jitter)
	}
	if c.Reconnect.MaxDelay.Duration() < c.Reconnect.InitialDelay.Duration() {
		return errors.New("config: reconnect.max_delay must be at least reconnect.initial_delay")
	}
	// Xray's API must not be reachable from outside the node: it can add
	// users and read every counter.
	if host, _, err := splitHostPort(c.Cores.XrayAPIAddress); err != nil {
		return fmt.Errorf("config: cores.xray_api_address: %w", err)
	} else if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("config: cores.xray_api_address must be on the loopback interface, got %q", host)
	}
	return nil
}

func splitHostPort(addr string) (host, port string, err error) {
	host, port, found := strings.Cut(addr, ":")
	if !found || host == "" || port == "" {
		return "", "", fmt.Errorf("expected host:port, got %q", addr)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", fmt.Errorf("bad port in %q", addr)
	}
	return host, port, nil
}

// Paths derived from DataDir. Collected here so the agent and the installer
// agree on them without repeating string literals.

// KeyPath is the agent's private key for mutual TLS.
func (c Config) KeyPath() string { return filepath.Join(c.DataDir, "agent.key") }

// CertPath is the client certificate Main issued at enrolment.
func (c Config) CertPath() string { return filepath.Join(c.DataDir, "agent.crt") }

// CAPath is Main's CA, pinned at enrolment.
func (c Config) CAPath() string { return filepath.Join(c.DataDir, "main-ca.crt") }

// StatePath is the last desired state the agent applied. Keeping it on disk
// is what lets a node come back up serving traffic while Main is unreachable.
func (c Config) StatePath() string { return filepath.Join(c.DataDir, "state.pb") }

// CoreConfigDir holds the generated configuration for each core.
func (c Config) CoreConfigDir() string { return filepath.Join(c.DataDir, "cores") }

// Binary resolves a core binary against BinDir.
func (c Config) Binary(name string) string {
	if name == "" {
		return ""
	}
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.BinDir, name)
}
