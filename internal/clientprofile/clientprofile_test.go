package clientprofile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"

	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// buildable asserts that the core itself accepts the configuration. Parsing is
// not enough: a field the core does not know is silently ignored by JSON
// decoding, so only Build catches a setting that will never take effect.
func buildable(t *testing.T, configJSON string) {
	t.Helper()
	cfg, err := serial.DecodeJSONConfig(bytes.NewReader([]byte(configJSON)))
	if err != nil {
		t.Fatalf("the core could not parse the config: %v\n%s", err, configJSON)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("the core could not build the config: %v\n%s", err, configJSON)
	}
}

func TestEveryXrayProtocolBuilds(t *testing.T) {
	servers := []subscription.Server{
		{
			ID: "n:vless", Name: "VLESS reality", Protocol: "vless", Transport: "reality",
			Address: "198.51.100.10", Port: 443,
			Params: map[string]string{
				"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
				"flow": "xtls-rprx-vision", "sni": "www.microsoft.com",
				"pbk": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
				"sid": "6ba85179e30d4fc2", "fp": "chrome",
			},
		},
		{
			ID: "n:xhttp", Name: "VLESS xhttp", Protocol: "vless", Transport: "xhttp",
			Address: "cdn.example.com", Port: 443,
			Params: map[string]string{
				"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
				"path": "/wn", "host": "cdn.example.com", "mode": "auto",
				"security": "tls", "sni": "cdn.example.com",
			},
		},
		{
			ID: "n:vmess", Name: "VMess ws", Protocol: "vmess", Transport: "ws",
			Address: "198.51.100.11", Port: 8080,
			Params: map[string]string{
				"uuid":     "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
				"security": "auto", "path": "/v", "host": "example.com",
			},
		},
		{
			ID: "n:trojan", Name: "Trojan", Protocol: "trojan", Transport: "tls",
			Address: "198.51.100.12", Port: 443,
			Params: map[string]string{"password": "s3cr3t", "sni": "example.com"},
		},
		{
			ID: "n:ss", Name: "Shadowsocks", Protocol: "shadowsocks", Transport: "raw",
			Address: "198.51.100.13", Port: 8388,
			Params: map[string]string{"method": "aes-256-gcm", "password": "pw"},
		},
		{
			ID: "n:ss2022", Name: "Shadowsocks 2022", Protocol: "shadowsocks2022", Transport: "raw",
			Address: "198.51.100.14", Port: 8389,
			Params: map[string]string{
				"method":   "2022-blake3-aes-128-gcm",
				"password": "RkZGRkZGRkZGRkZGRkZGRg==",
			},
		},
		{
			ID: "n:hy2", Name: "Hysteria2", Protocol: "hysteria2", Transport: "hysteria",
			Address: "198.51.100.15", Port: 8443,
			Params: map[string]string{
				"auth": "Zm9vYmFyYmF6cXV1eA", "sni": "bing.com",
				"obfs": "salamander", "obfs_password": "mask",
				"up_mbps": "100", "down_mbps": "300",
			},
		},
		{
			ID: "n:grpc", Name: "VLESS grpc", Protocol: "vless", Transport: "grpc",
			Address: "198.51.100.16", Port: 443,
			Params: map[string]string{
				"uuid":         "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
				"service_name": "wn", "multi_mode": "true", "sni": "example.com",
			},
		},
		{
			ID: "n:kcp", Name: "VLESS kcp", Protocol: "vless", Transport: "kcp",
			Address: "198.51.100.17", Port: 2080,
			Params: map[string]string{
				"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
				"seed": "sEEd", "finalmask": "header-srtp",
			},
		},
	}

	for _, server := range servers {
		t.Run(server.Name, func(t *testing.T) {
			profile, err := FromServer(server, Options{})
			if err != nil {
				t.Fatalf("FromServer: %v", err)
			}
			if profile.Kind != KindXray {
				t.Fatalf("kind = %q, want xray", profile.Kind)
			}
			if profile.Chained() {
				t.Fatal("an ordinary server must not need two cores")
			}
			buildable(t, profile.Config)
		})
	}
}

func TestSocksPortIsTheOneAsked(t *testing.T) {
	server := subscription.Server{
		ID: "n:v", Name: "v", Protocol: "vless", Transport: "raw",
		Address: "198.51.100.1", Port: 443,
		Params: map[string]string{"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"},
	}
	profile, err := FromServer(server, Options{SocksPort: 12345})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile.Config, "12345") {
		t.Fatalf("the config does not listen where it was told:\n%s", profile.Config)
	}
}

func TestDNSTunnelChainsThroughItsOwnProxy(t *testing.T) {
	server := subscription.Server{
		ID: "n:wndns-53", Name: "node DNS", Protocol: "wndns", Transport: "dns",
		Address: "198.51.100.2", Port: 53,
		Params: map[string]string{
			"domains":           "t1.tun.example, t2.tun.example",
			"encryption_method": "2",
			"encryption_key":    "4f3c2b1a09876543210fedcba9876543",
		},
		Chain: &subscription.Chain{
			Protocol: "vless", Transport: "raw",
			Params: map[string]string{"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"},
		},
	}

	profile, err := FromServer(server, Options{SocksPort: 10808, ChainSocksPort: 10809})
	if err != nil {
		t.Fatalf("FromServer: %v", err)
	}
	if !profile.Chained() {
		t.Fatal("a DNS server needs both cores; the inner half is missing")
	}
	if profile.Kind != KindWhiteNet || profile.Inner.Kind != KindXray {
		t.Fatalf("kinds = %q/%q", profile.Kind, profile.Inner.Kind)
	}

	// The tunnel offers its proxy on the chain port, and the inner core must
	// dial out through exactly that - not over the network, which would skip
	// the tunnel and fail with no explanation.
	if !strings.Contains(profile.Config, "port: 10809") {
		t.Fatalf("the tunnel does not listen on the chain port:\n%s", profile.Config)
	}
	for _, want := range []string{"t1.tun.example", "t2.tun.example", "dialerProxy"} {
		if !strings.Contains(profile.Config+profile.Inner.Config, want) {
			t.Fatalf("missing %q", want)
		}
	}

	var inner map[string]any
	if err := json.Unmarshal([]byte(profile.Inner.Config), &inner); err != nil {
		t.Fatal(err)
	}
	outbounds, _ := inner["outbounds"].([]any)
	var dialer map[string]any
	for _, entry := range outbounds {
		out, _ := entry.(map[string]any)
		if out["tag"] == "dns-tunnel" {
			dialer = out
		}
	}
	if dialer == nil {
		t.Fatalf("no dialer outbound in:\n%s", profile.Inner.Config)
	}
	settings, _ := dialer["settings"].(map[string]any)
	servers, _ := settings["servers"].([]any)
	first, _ := servers[0].(map[string]any)
	if port, ok := first["port"].(float64); !ok || int(port) != 10809 {
		t.Fatalf("the dialer points at %v, not the tunnel's port", first["port"])
	}

	buildable(t, profile.Inner.Config)
}

func TestDNSTunnelWithoutAChainIsStandalone(t *testing.T) {
	// The classic DNS VPN: no inner hop, the shared key is the whole
	// authentication, and the device's traffic goes straight through the
	// tunnel. This is what worked before chaining existed, so it must keep
	// working - a node with no chain target still produces a usable profile.
	profile, err := FromServer(subscription.Server{
		ID: "n:dns", Name: "dns", Protocol: "wndns", Transport: "dns",
		Address: "198.51.100.2", Port: 53,
		Params: map[string]string{
			"domains": "t.example", "encryption_key": "4f3c2b1a09876543210fedcba9876543",
			"encryption_method": "2",
		},
	}, Options{SocksPort: 10808})
	if err != nil {
		t.Fatalf("a standalone DNS server must build: %v", err)
	}
	if profile.Chained() {
		t.Fatal("a DNS server with no chain must not need two cores")
	}
	if profile.Kind != KindWhiteNet {
		t.Fatalf("kind = %q", profile.Kind)
	}
	// Standalone, the tunnel serves the device directly on the main port.
	if !strings.Contains(profile.Config, "port: 10808") {
		t.Fatalf("the tunnel does not serve the device directly:\n%s", profile.Config)
	}
	for _, want := range []string{"provider: dns", "t.example", "method: 2"} {
		if !strings.Contains(profile.Config, want) {
			t.Fatalf("missing %q in:\n%s", want, profile.Config)
		}
	}
}

func TestFluxPrefersTheHighestPriorityCarrier(t *testing.T) {
	server := subscription.Server{
		ID: "n:flux", Name: "node flux", Protocol: "flux", Transport: "cupsonline",
		Flux: &subscription.Flux{
			Mode: "l4",
			Channels: []subscription.Channel{{
				ID:      "ch-7",
				Secret:  "7b1f0c9d2e3a4b5c6d7e8f90a1b2c3d47b1f0c9d2e3a4b5c6d7e8f90a1b2c3d4",
				Context: "https://cups.online/room/ab12cd",
				Carriers: []subscription.Carrier{
					{Type: "cupsonline", URL: "https://cups.online/room/ab12cd", Priority: 50},
					{Type: "direct", Priority: 100, Params: map[string]string{"dial": "198.51.100.3:8444"}},
				},
			}},
		},
	}

	profile, err := FromServer(server, Options{SocksPort: 8808})
	if err != nil {
		t.Fatalf("FromServer: %v", err)
	}
	if profile.Kind != KindFlux {
		t.Fatalf("kind = %q, want flux", profile.Kind)
	}

	// The flux client takes JSON carrying every carrier, so it can fail over
	// without the app reconnecting; it is the client that picks by priority.
	var doc struct {
		Version   int    `json:"whitenet_flux"`
		Mode      string `json:"mode"`
		Secret    string `json:"secret"`
		SocksPort int    `json:"socks_port"`
		Carriers  []struct {
			Type     string            `json:"type"`
			Priority int               `json:"priority"`
			Params   map[string]string `json:"params"`
		} `json:"carriers"`
	}
	if err := json.Unmarshal([]byte(profile.Config), &doc); err != nil {
		t.Fatalf("flux profile is not valid JSON: %v\n%s", err, profile.Config)
	}
	if doc.Version == 0 {
		t.Fatalf("the flux marker is missing, so the client would not recognise it:\n%s", profile.Config)
	}
	if doc.SocksPort != 8808 {
		t.Fatalf("socks port = %d, want 8808", doc.SocksPort)
	}
	if doc.Secret == "" {
		t.Fatal("the channel secret did not travel; the session cannot authenticate")
	}
	if len(doc.Carriers) != 2 {
		t.Fatalf("both carriers must travel for failover, got %d", len(doc.Carriers))
	}
	var direct struct {
		Priority int
		Dial     string
	}
	for _, c := range doc.Carriers {
		if c.Type == "direct" {
			direct.Priority = c.Priority
			direct.Dial = c.Params["dial"]
		}
	}
	if direct.Priority != 100 {
		t.Fatalf("the direct carrier's priority was lost: %d", direct.Priority)
	}
	if direct.Dial != "198.51.100.3:8444" {
		t.Fatalf("the carrier's dial address is missing: %q", direct.Dial)
	}
}

func TestFluxWithOnlyALeaseIsRefused(t *testing.T) {
	// A lease endpoint is not a channel: the app has to take one first, and
	// saying so beats producing a profile with no credentials in it.
	_, err := FromServer(subscription.Server{
		ID: "n:flux", Name: "flux", Protocol: "flux",
		Flux: &subscription.Flux{Mode: "l4", Lease: "https://sub.example/lease/t"},
	}, Options{})
	if err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("error = %v; want one that points at the lease", err)
	}
}

func TestMissingCredentialsAreNamed(t *testing.T) {
	// The app shows this to a user, so it has to say which field is missing
	// rather than failing as a connection error later.
	_, err := FromServer(subscription.Server{
		ID: "n:v", Name: "broken", Protocol: "vless", Transport: "raw",
		Address: "198.51.100.1", Port: 443,
	}, Options{})
	if err == nil || !strings.Contains(err.Error(), "uuid") {
		t.Fatalf("error = %v; want one naming uuid", err)
	}
}

func TestUnknownProtocolIsRefusedNotGuessed(t *testing.T) {
	_, err := FromServer(subscription.Server{
		ID: "n:x", Name: "future", Protocol: "something-new",
		Address: "198.51.100.1", Port: 443,
	}, Options{})
	if err == nil {
		t.Fatal("an unknown protocol must be refused so the app can skip it")
	}
}
