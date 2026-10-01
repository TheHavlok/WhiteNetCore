package xraycfg

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	// The loader and every protocol and transport it may reference. Loading
	// a generated configuration with xray-core's own loader is the only check
	// that actually proves the field names are right.
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

const (
	testRealityKey = "8Ht6ptKRTCXbDGEurgCVoOTUQSXCDKDTiGhA-dSWMms"
	testUUID       = "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"
)

func testUsers() []*nodepb.User {
	return []*nodepb.User{
		{
			Id:         1,
			Uuid:       testUUID,
			Email:      UserEmail(1, testUUID),
			VlessUuid:  testUUID,
			Password:   "trojan-and-hysteria-password",
			SsPassword: "c2hhZG93c29ja3NVc2VyS2V5MTIzNA==",
		},
		{
			Id:         2,
			Uuid:       "11111111-2222-3333-4444-555555555555",
			Email:      UserEmail(2, "11111111-2222-3333-4444-555555555555"),
			VlessUuid:  "11111111-2222-3333-4444-555555555555",
			Password:   "second-user-password",
			SsPassword: "c2Vjb25kVXNlcktleTEyMzQ1Njc4OTA=",
		},
	}
}

func opts() Options {
	return Options{APIAddress: "127.0.0.1:10085", LogLevel: "warning"}
}

// loadsInXray renders the state and hands it to xray-core's own JSON loader.
// A field name this package gets wrong fails here, which is the point.
func loadsInXray(t *testing.T, state *nodepb.NodeState) {
	t.Helper()
	raw, err := Generate(state, opts())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := serial.DecodeJSONConfig(bytes.NewReader(raw)); err != nil {
		t.Fatalf("xray-core rejected the configuration: %v\n%s", err, raw)
	}
	// DecodeJSONConfig only parses; Build turns it into the real protobuf
	// configuration and is where a wrong value (rather than a wrong name)
	// shows up.
	cfg, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray-core could not build the configuration: %v\n%s", err, raw)
	}
}

func TestVLESSRealityLoadsInXray(t *testing.T) {
	state := &nodepb.NodeState{
		Version:  7,
		NodeUuid: "4f1c9e0a-7b2d-4e8a-9c31-5a6b7c8d9e0f",
		Users:    testUsers(),
		Inbounds: []*nodepb.Inbound{{
			Tag:        "vless-reality-443",
			Core:       nodepb.Core_CORE_XRAY,
			Protocol:   nodepb.Protocol_PROTOCOL_VLESS,
			Enabled:    true,
			ListenPort: 443,
			Params: map[string]string{
				"network":      "raw",
				"security":     "reality",
				"target":       "www.microsoft.com:443",
				"server_names": "www.microsoft.com,microsoft.com",
				"short_ids":    "6ba85179e30d4fc2,aa",
				"flow":         "xtls-rprx-vision",
				"fp":           "chrome",
			},
			Secrets: map[string]string{"private_key": testRealityKey},
		}},
	}
	loadsInXray(t, state)

	cfg, err := Build(state, opts())
	if err != nil {
		t.Fatal(err)
	}
	// The API inbound comes first and is on loopback; the panel's inbound
	// follows.
	if len(cfg.Inbounds) != 2 {
		t.Fatalf("got %d inbounds, want 2 (api + vless)", len(cfg.Inbounds))
	}
	api := cfg.Inbounds[0]
	if api.Tag != APITag || api.Listen != "127.0.0.1" || api.Port != 10085 {
		t.Errorf("api inbound = %+v", api)
	}
	in := cfg.Inbounds[1]
	settings, ok := in.Settings.(vlessSettings)
	if !ok {
		t.Fatalf("settings type = %T", in.Settings)
	}
	if len(settings.Clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(settings.Clients))
	}
	if settings.Decryption != "none" {
		t.Errorf("decryption = %q, want none", settings.Decryption)
	}
	if settings.Clients[0].Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q, want the inbound's flow", settings.Clients[0].Flow)
	}
	if settings.Clients[0].Email != UserEmail(1, testUUID) {
		t.Errorf("email = %q", settings.Clients[0].Email)
	}
	reality := in.StreamSettings.RealitySettings
	if reality == nil {
		t.Fatal("no realitySettings")
	}
	// target, not dest: the name changed and the old one is only an alias.
	if reality.Target != "www.microsoft.com:443" {
		t.Errorf("target = %q", reality.Target)
	}
	if len(reality.ServerNames) != 2 || len(reality.ShortIds) != 2 {
		t.Errorf("serverNames = %v, shortIds = %v", reality.ServerNames, reality.ShortIds)
	}
	if reality.PrivateKey != testRealityKey {
		t.Error("private key did not reach realitySettings")
	}
}

func TestEveryProtocolLoadsInXray(t *testing.T) {
	// One TLS certificate, self-signed, for the protocols that need one.
	cert, key := testCertificate(t)

	cases := map[string]*nodepb.Inbound{
		"vless-xhttp": {
			Tag: "vless-xhttp", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_VLESS, Enabled: true, ListenPort: 8443,
			Params: map[string]string{
				"network": "xhttp", "security": "tls", "path": "/wn",
				"host": "cdn.example.com", "mode": "auto", "sni": "cdn.example.com",
			},
			Secrets: map[string]string{"certificate": cert, "key": key},
		},
		"vless-ws": {
			Tag: "vless-ws", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_VLESS, Enabled: true, ListenPort: 8444,
			Params:  map[string]string{"network": "ws", "security": "tls", "path": "/ws"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		},
		"vless-grpc": {
			Tag: "vless-grpc", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_VLESS, Enabled: true, ListenPort: 8445,
			Params:  map[string]string{"network": "grpc", "security": "tls", "service_name": "wn"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		},
		"vless-httpupgrade": {
			Tag: "vless-hu", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_VLESS, Enabled: true, ListenPort: 8446,
			Params:  map[string]string{"network": "httpupgrade", "security": "tls", "path": "/hu"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		},
		"vmess-kcp": {
			Tag: "vmess-kcp", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_VMESS, Enabled: true, ListenPort: 8447,
			Params: map[string]string{"network": "mkcp", "congestion": "true",
				"finalmask_udp": "header-srtp,mkcp-aes128gcm"},
			Secrets: map[string]string{"mkcp-aes128gcm_password": "kcp-seed"},
		},
		"trojan-tls": {
			Tag: "trojan", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_TROJAN, Enabled: true, ListenPort: 8448,
			Params:  map[string]string{"network": "raw", "security": "tls", "sni": "trojan.example"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		},
		"shadowsocks-legacy": {
			Tag: "ss", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS, Enabled: true, ListenPort: 8449,
			Params: map[string]string{"method": "aes-256-gcm"},
		},
		"shadowsocks-2022": {
			Tag: "ss2022", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022, Enabled: true, ListenPort: 8450,
			Params:  map[string]string{"method": "2022-blake3-aes-128-gcm"},
			Secrets: map[string]string{"password": "qxGZVPkTfTCCRWg6cNFVMg=="},
		},
		"hysteria2-salamander": {
			Tag: "hy2-obfs", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_HYSTERIA2, Enabled: true, ListenPort: 8452,
			Params: map[string]string{
				"security": "tls", "sni": "hy2.example", "finalmask_udp": "salamander",
			},
			Secrets: map[string]string{"certificate": cert, "key": key, "obfs_password": "s3cr3t"},
		},
		"hysteria2": {
			Tag: "hy2", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_HYSTERIA2, Enabled: true, ListenPort: 8451,
			Params: map[string]string{
				"security": "tls", "sni": "hy2.example",
				"up_mbps": "100", "down_mbps": "300", "congestion": "bbr",
			},
			Secrets: map[string]string{"certificate": cert, "key": key},
		},
	}

	for name, inbound := range cases {
		t.Run(name, func(t *testing.T) {
			loadsInXray(t, &nodepb.NodeState{
				Users:    testUsers(),
				Inbounds: []*nodepb.Inbound{inbound},
			})
		})
	}
}

// Hysteria2 is where the panel is most likely to be wrong, because Xray's
// shape differs from the standalone implementation: the users live in the
// proxy settings and the transport carries the bandwidth hints.
func TestHysteria2Shape(t *testing.T) {
	cert, key := testCertificate(t)
	state := &nodepb.NodeState{
		Users: testUsers(),
		Inbounds: []*nodepb.Inbound{{
			Tag: "hy2", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_HYSTERIA2, Enabled: true, ListenPort: 8443,
			Params:  map[string]string{"security": "tls", "up_mbps": "100", "down_mbps": "300"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		}},
	}
	cfg, err := Build(state, opts())
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Inbounds[1]
	if in.Protocol != "hysteria" {
		t.Errorf("protocol = %q, want hysteria (the Xray name for Hysteria2)", in.Protocol)
	}
	settings, ok := in.Settings.(hysteriaProxySettings)
	if !ok {
		t.Fatalf("settings type = %T", in.Settings)
	}
	if settings.Version != 2 {
		t.Errorf("version = %d, want 2", settings.Version)
	}
	if len(settings.Clients) != 2 || settings.Clients[0].Auth != "trojan-and-hysteria-password" {
		t.Errorf("clients = %+v", settings.Clients)
	}
	if in.StreamSettings.Network != "hysteria" {
		t.Errorf("network = %q, want hysteria", in.StreamSettings.Network)
	}
	if in.StreamSettings.HysteriaSettings == nil || in.StreamSettings.HysteriaSettings.Up != "100 mbps" {
		t.Errorf("hysteriaSettings = %+v", in.StreamSettings.HysteriaSettings)
	}
	// Without TLS there is no QUIC to run it over.
	state.Inbounds[0].Params["security"] = "none"
	if _, err := Build(state, opts()); err == nil {
		t.Error("hysteria2 without tls was accepted")
	}
}

// The API inbound and the routing rule for it are what let the agent add
// users without a restart and read counters. Losing either breaks the panel
// quietly, so assert on them.
func TestAPIAndStatsAlwaysPresent(t *testing.T) {
	cfg, err := Build(&nodepb.NodeState{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API == nil || cfg.API.Tag != APITag {
		t.Fatalf("api = %+v", cfg.API)
	}
	wantServices := map[string]bool{"HandlerService": false, "StatsService": false}
	for _, s := range cfg.API.Services {
		wantServices[s] = true
	}
	for name, present := range wantServices {
		if !present {
			t.Errorf("api services is missing %s", name)
		}
	}
	if cfg.Stats == nil {
		t.Error("stats object is missing, so there are no counters to read")
	}
	level0, ok := cfg.Policy.Levels["0"]
	if !ok || !level0.StatsUserUplink || !level0.StatsUserDownlink {
		t.Errorf("policy level 0 = %+v, want per-user counters enabled", level0)
	}
	var routed bool
	for _, rule := range cfg.Routing.Rules {
		// Both tags must be APITag: the api object registers its outbound
		// handler under its own tag.
		if rule.OutboundTag == APITag && len(rule.InboundTag) == 1 && rule.InboundTag[0] == APITag {
			routed = true
		}
	}
	if !routed {
		t.Error("no routing rule sends api traffic to the api outbound")
	}
}

func TestAPIAddressMustBeLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:10085", "185.68.184.144:10085", "", "127.0.0.1", "127.0.0.1:0"} {
		o := opts()
		o.APIAddress = addr
		if _, err := Build(&nodepb.NodeState{}, o); err == nil {
			t.Errorf("api address %q was accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:10085", "localhost:10085", "[::1]:10085"} {
		o := opts()
		o.APIAddress = addr
		if _, err := Build(&nodepb.NodeState{}, o); err != nil {
			t.Errorf("api address %q was rejected: %v", addr, err)
		}
	}
}

func TestNonXrayInboundsAreSkipped(t *testing.T) {
	cfg, err := Build(&nodepb.NodeState{
		Inbounds: []*nodepb.Inbound{
			{Tag: "dns-tunnel", Core: nodepb.Core_CORE_WNDNS, Protocol: nodepb.Protocol_PROTOCOL_WNDNS,
				Enabled: true, ListenPort: 53, ForwardToTag: "vless-local"},
			{Tag: "disabled", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
				Enabled: false, ListenPort: 1234},
		},
	}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("got %d inbounds, want only the api one: %+v", len(cfg.Inbounds), cfg.Inbounds)
	}
}

// An unchanged state must render byte-identical output, or the agent cannot
// tell a real change from map iteration order and restarts Xray for nothing.
func TestOutputIsDeterministic(t *testing.T) {
	state := &nodepb.NodeState{
		Users: testUsers(),
		Inbounds: []*nodepb.Inbound{
			{Tag: "b-inbound", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_TROJAN,
				Enabled: true, ListenPort: 8002, Params: map[string]string{"network": "raw"}},
			{Tag: "a-inbound", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
				Enabled: true, ListenPort: 8001, Params: map[string]string{"network": "raw"}},
		},
	}
	first, err := Generate(state, opts())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Generate(state, opts())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("two renders of the same state differ")
		}
	}
	// Sorted by tag, so a-inbound precedes b-inbound regardless of input
	// order.
	var parsed struct {
		Inbounds []struct{ Tag string } `json:"inbounds"`
	}
	if err := json.Unmarshal(first, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Inbounds[1].Tag != "a-inbound" || parsed.Inbounds[2].Tag != "b-inbound" {
		t.Errorf("inbounds are not sorted by tag: %+v", parsed.Inbounds)
	}
}

func TestBuildRejections(t *testing.T) {
	cases := map[string]*nodepb.Inbound{
		"reality without a private key": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 443,
			Params: map[string]string{"security": "reality", "target": "a:443",
				"server_names": "a", "short_ids": "aa"},
		},
		"reality without a target": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 443,
			Params:  map[string]string{"security": "reality", "server_names": "a", "short_ids": "aa"},
			Secrets: map[string]string{"private_key": testRealityKey},
		},
		"reality without short ids": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 443,
			Params:  map[string]string{"security": "reality", "target": "a:443", "server_names": "a"},
			Secrets: map[string]string{"private_key": testRealityKey},
		},
		"tls without a certificate": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 443,
			Params: map[string]string{"security": "tls"},
		},
		"unknown network": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 443,
			Params: map[string]string{"network": "carrier-pigeon"},
		},
		"unknown security": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 443,
			Params: map[string]string{"security": "wishful-thinking"},
		},
		"port out of range": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenPort: 70000,
		},
		"shadowsocks without a method": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
			Enabled: true, ListenPort: 443,
		},
		"2022 method on the legacy protocol": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
			Enabled: true, ListenPort: 443,
			Params: map[string]string{"method": "2022-blake3-aes-128-gcm"},
		},
		"2022 protocol with a legacy method": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022,
			Enabled: true, ListenPort: 443,
			Params:  map[string]string{"method": "aes-256-gcm"},
			Secrets: map[string]string{"password": "k"},
		},
		"2022 chacha with several users": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022,
			Enabled: true, ListenPort: 443,
			Params:  map[string]string{"method": "2022-blake3-chacha20-poly1305"},
			Secrets: map[string]string{"password": "k"},
		},
		"2022 without a server key": {
			Tag: "a", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022,
			Enabled: true, ListenPort: 443,
			Params: map[string]string{"method": "2022-blake3-aes-128-gcm"},
		},
	}
	for name, inbound := range cases {
		if _, err := Build(&nodepb.NodeState{Users: testUsers(), Inbounds: []*nodepb.Inbound{inbound}}, opts()); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A node with no users yet must still produce a configuration Xray accepts,
// or a freshly added node never comes up.
func TestNoUsersStillLoads(t *testing.T) {
	loadsInXray(t, &nodepb.NodeState{
		Inbounds: []*nodepb.Inbound{
			{Tag: "vless", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
				Enabled: true, ListenPort: 443, Params: map[string]string{"network": "raw"}},
			{Tag: "ss", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
				Enabled: true, ListenPort: 444, Params: map[string]string{"method": "aes-256-gcm"},
				Secrets: map[string]string{"password": "fallback-key-nobody-has"}},
		},
	})
}

func TestUserEmailRoundTrip(t *testing.T) {
	email := UserEmail(4242, testUUID)
	if !strings.HasPrefix(email, "4242.") || !strings.HasSuffix(email, "@whitenet") {
		t.Fatalf("email = %q", email)
	}
	id, ok := UserIDFromEmail(email)
	if !ok || id != 4242 {
		t.Fatalf("UserIDFromEmail(%q) = %d, %v", email, id, ok)
	}
	// Xray also reports counters for things that are not our users; those
	// must be ignored rather than mapped to user 0.
	for _, other := range []string{"", "someone@example.com", "api", "notanumber.abc@whitenet"} {
		if _, ok := UserIDFromEmail(other); ok {
			t.Errorf("UserIDFromEmail(%q) claimed to be one of ours", other)
		}
	}
}
