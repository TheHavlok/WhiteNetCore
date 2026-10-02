package mobile

// The flux client in the mobile core.
//
// The exit side has run flux since the agent did, but the apps never could:
// StartVPN knew two profile shapes, an Xray configuration and a WhiteNet
// YAML, and a flux server is neither. A flux profile now travels in its own
// shape, and this file is the only place that starts one - which is what lets
// every carrier work at once rather than one at a time.
//
// One client at a time, like every other core here: a profile is active or it
// is not, so the local proxy port can be fixed and the packet stack always
// knows where to dial.

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"sync"

	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	"github.com/thehavlok/whitenet/internal/memprofile"
)

// fluxMarker is the key that tells a flux profile from an Xray one. Both are
// JSON, so the shape alone cannot decide.
const fluxMarker = "whitenet_flux"

// fluxSocksPort is where the flux client listens. The cores never run at the
// same time, so a fixed port is safe and keeps the packet path simple.
const fluxSocksPort = 10810

// FluxProfile is a flux server as the app stores it: the client's half of
// what the panel configures on a node - the same carriers, the same secret,
// the same exit mode.
type FluxProfile struct {
	// Version marks the shape, so an older app refuses a profile it does not
	// understand instead of half-reading it.
	Version int `json:"whitenet_flux"`
	// Mode is the exit backend the node runs: l3 or l4. The client does not
	// choose it, but the session negotiates against it.
	Mode string `json:"mode,omitempty"`
	// Secret is the channel's shared key, hex. Without it the channel is open
	// to whoever finds the document.
	Secret string `json:"secret"`
	// Context is the KDF context and must match the exit's exactly. Empty
	// falls back to the highest-priority carrier's URL, as the exit does.
	Context string `json:"context,omitempty"`
	// SocksPort overrides the local proxy port.
	SocksPort int `json:"socks_port,omitempty"`
	// Carriers are the ways into the channel.
	Carriers []FluxCarrier `json:"carriers"`
}

// FluxCarrier is one way into the channel.
type FluxCarrier struct {
	Type     string            `json:"type"`
	URL      string            `json:"url,omitempty"`
	Priority int               `json:"priority,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
}

// IsFluxConfig reports whether config is a flux profile. It has to be checked
// before IsXrayConfig, because a flux profile is JSON too and would otherwise
// be handed to the wrong core.
func IsFluxConfig(config string) bool {
	trimmed := strings.TrimSpace(config)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, fluxMarker) {
		return false
	}
	var profile FluxProfile
	if err := json.Unmarshal([]byte(trimmed), &profile); err != nil {
		return false
	}
	return profile.Version > 0
}

var (
	fluxMu       sync.Mutex
	fluxInstance *fluxnode.Instance
)

// startFluxClient brings up a flux profile and hands back the usual Client, so
// the platform layers cannot tell which core is running.
//
// initPacketStack brings up the platform's tun2socks stack (initTUN on iOS,
// initTUNAndroid on Android). It is not optional: without it the flux SOCKS
// listener is up and the session connects, but nothing reads the device's
// packets from the OS tunnel, so the session carries no traffic - connected
// but nothing loads. The Xray path has always called it; flux has to as well.
func startFluxClient(config string, initPacketStack func(), pointPacketStackAt func(int) *Client) (*Client, error) {
	var profile FluxProfile
	if err := json.Unmarshal([]byte(config), &profile); err != nil {
		return nil, fmt.Errorf("flux profile: %w", err)
	}
	if len(profile.Carriers) == 0 {
		return nil, fmt.Errorf("flux profile: no carrier to connect through")
	}

	// Whatever was running goes first: two cores would fight over the local
	// port, and on iOS over the memory budget.
	Stop()
	memprofile.SetMobile(true)

	port := profile.SocksPort
	if port <= 0 {
		port = fluxSocksPort
	}
	// The previous core may not have released the port yet; a readiness check
	// would otherwise find its dying listener and call the tunnel up.
	waitForPortFree(port, portFreeTimeout)

	cfg := fluxnode.DefaultConfig()
	cfg.Exit = false
	cfg.Mode = profile.Mode
	cfg.Secret = profile.Secret
	cfg.Context = profile.Context
	cfg.SocksAddr = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Inbound = "socks5"
	cfg.Log = slog.New(slog.NewTextHandler(log.Writer(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	for _, carrier := range profile.Carriers {
		cfg.Carriers = append(cfg.Carriers, fluxnode.Carrier{
			Type:     carrier.Type,
			URL:      carrier.URL,
			Priority: carrier.Priority,
			Params:   carrier.Params,
		})
	}

	// The packet stack comes up before the client, so the device's traffic
	// has somewhere to go the moment the session is ready. It is a sync.Once
	// inside, so a second profile does not rebuild it.
	if initPacketStack != nil {
		initPacketStack()
	}

	instance, err := fluxnode.Start(cfg)
	if err != nil {
		return nil, fmt.Errorf("flux: %w", err)
	}

	fluxMu.Lock()
	fluxInstance = instance
	fluxMu.Unlock()

	log.Printf("flux client running: %d carrier(s), SOCKS5 on 127.0.0.1:%d", len(cfg.Carriers), port)
	return pointPacketStackAt(port), nil
}

// stopFluxClient shuts the flux client down. Safe when none is running, which
// is what lets Stop() call it unconditionally.
func stopFluxClient() {
	fluxMu.Lock()
	instance := fluxInstance
	fluxInstance = nil
	fluxMu.Unlock()

	if instance == nil {
		return
	}
	if err := instance.Stop(); err != nil {
		log.Printf("flux client stop: %v", err)
	}
}

// FluxSessionActive reports whether the flux client has a live session with
// its exit. A carrier being attached to its document says nothing about the
// other side being there, so this is the honest thing for an app to show.
func FluxSessionActive() bool {
	fluxMu.Lock()
	instance := fluxInstance
	fluxMu.Unlock()
	return instance != nil && instance.SessionActive()
}
