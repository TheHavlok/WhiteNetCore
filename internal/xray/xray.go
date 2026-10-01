// Package xray runs an embedded xray-core instance and turns share links
// (vless://, vmess://, trojan://, ss://) into an Xray configuration.
//
// It reuses the packet path that is already there rather than adding a second
// one. xray-core is started with a single local SOCKS5 inbound, and tun2socks
// dials that port instead of the WhiteNet client's. Nothing about TUN
// handling, DNS or the platform layers changes - only which process answers on
// the other end of the SOCKS port. The two cores are mutually exclusive: one
// profile is active at a time, so they never compete for memory, which matters
// inside an iOS packet tunnel extension.
package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/thehavlok/whitenet/internal/logger"
	"github.com/xtls/xray-core/core"

	// Registers every protocol, transport and codec xray-core ships with.
	// Without this blank import a configuration referencing vless or reality
	// fails to load at runtime with an unhelpful "unknown protocol".
	_ "github.com/xtls/xray-core/main/distro/all"
)

// ErrAlreadyRunning is returned when Start is called twice without a Stop.
var ErrAlreadyRunning = errors.New("xray: already running")

// ErrNoOutbounds is returned for a configuration that cannot proxy anything.
var ErrNoOutbounds = errors.New("xray: config has no outbounds")

var (
	mu       sync.Mutex     //nolint:gochecknoglobals // one instance per process by design
	instance *core.Instance //nolint:gochecknoglobals // one instance per process by design
)

// Start brings up xray-core with a local SOCKS5 inbound on socksPort.
//
// configJSON is a standard Xray configuration: either one produced by
// ParseShareLink or one the user pasted themselves.
func Start(configJSON string, socksPort int) error {
	mu.Lock()
	defer mu.Unlock()

	if instance != nil {
		return ErrAlreadyRunning
	}

	raw, err := prepareConfig(configJSON, socksPort)
	if err != nil {
		return err
	}

	installDialerController()

	started, err := core.StartInstance("json", raw)
	if err != nil {
		return fmt.Errorf("xray: start instance: %w", err)
	}

	instance = started
	logger.Infof("xray started, SOCKS5 on 127.0.0.1:%d", socksPort)

	return nil
}

// Stop shuts the instance down. Safe to call when nothing is running.
func Stop() {
	mu.Lock()
	running := instance
	instance = nil
	mu.Unlock()

	if running == nil {
		return
	}

	if err := running.Close(); err != nil {
		logger.Warnf("xray: close instance: %v", err)
	}

	logger.Infof("xray stopped")
}

// IsRunning reports whether an instance is up.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()

	return instance != nil
}

// prepareConfig normalises a configuration before it reaches xray-core.
//
// Whatever inbounds the config carried are replaced by ours. That is not a
// liberty: this app is a tunnel, not a proxy server, and tun2socks has to know
// exactly which port to dial. Everything else - outbounds, routing, dns - is
// passed through untouched, so a hand-written config keeps working.
func prepareConfig(configJSON string, socksPort int) ([]byte, error) {
	var config map[string]any
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("xray: config is not valid JSON: %w", err)
	}

	outbounds, ok := config["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return nil, ErrNoOutbounds
	}

	config["inbounds"] = []any{SocksInbound(socksPort)}

	raw, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("xray: encode config: %w", err)
	}

	return raw, nil
}
