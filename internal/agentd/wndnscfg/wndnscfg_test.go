package wndnscfg

import (
	"encoding/json"
	"strings"
	"testing"

	// The tunnel's own loader. Feeding it the generated configuration is the
	// only check that proves the key names are right.
	dnsconfig "github.com/thehavlok/whitenet/masterdnsvpn/config"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

const testKey = "4f3c2b1a09876543210fedcba9876543" // 32 hex characters

func tunnelState() *nodepb.NodeState {
	return &nodepb.NodeState{
		Version: 3,
		Inbounds: []*nodepb.Inbound{
			{
				Tag:        "wndns-53",
				Core:       nodepb.Core_CORE_WNDNS,
				Protocol:   nodepb.Protocol_PROTOCOL_WNDNS,
				Enabled:    true,
				ListenPort: 53,
				Params: map[string]string{
					"domains":           "t1.wn-dns.example,t2.wn-dns.example",
					"encryption_method": "2",
				},
				Secrets:      map[string]string{"encryption_key": testKey},
				ForwardToTag: "vless-local",
			},
			{
				Tag:           "vless-local",
				Core:          nodepb.Core_CORE_XRAY,
				Protocol:      nodepb.Protocol_PROTOCOL_VLESS,
				Enabled:       true,
				ListenAddress: "127.0.0.1",
				ListenPort:    21080,
			},
		},
	}
}

func testOpts() Options {
	return Options{KeyFile: "/var/lib/whitenet-agent/cores/wndns.key", LogLevel: "info"}
}

func TestBuildLoadsInTunnel(t *testing.T) {
	cfg, err := Build(tunnelState(), testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("no configuration produced for a node with a tunnel")
	}

	// The tunnel's own loader has the final say on every key name.
	loaded, err := dnsconfig.LoadServerConfigFromJSONBase64WithOverrides(
		cfg.Base64JSON(), dnsconfig.ServerConfigOverrides{})
	if err != nil {
		t.Fatalf("the tunnel rejected the configuration: %v\n%s", err, cfg.JSON)
	}

	if loaded.ProtocolType != "TCP" {
		t.Errorf("protocol type = %q, want TCP (SOCKS5 mode would make the node an open proxy)", loaded.ProtocolType)
	}
	if loaded.UDPPort != 53 {
		t.Errorf("udp port = %d", loaded.UDPPort)
	}
	if loaded.ForwardPort != 21080 {
		t.Errorf("forward port = %d, want the chained inbound's port", loaded.ForwardPort)
	}
	if loaded.ForwardIP != "127.0.0.1" {
		t.Errorf("forward ip = %q", loaded.ForwardIP)
	}
	if len(loaded.Domain) != 2 || loaded.Domain[0] != "t1.wn-dns.example" {
		t.Errorf("domains = %v", loaded.Domain)
	}
	if loaded.DataEncryptionMethod != EncryptionChaCha20 {
		t.Errorf("encryption method = %d", loaded.DataEncryptionMethod)
	}
	if loaded.EncryptionKeyFile != testOpts().KeyFile {
		t.Errorf("key file = %q", loaded.EncryptionKeyFile)
	}
	if cfg.Key != testKey {
		t.Error("the key did not come through for the agent to write")
	}
}

// A node without a tunnel must produce nothing and no error: that is the
// normal case, and the agent keeps the core stopped.
func TestBuildReturnsNilWithoutATunnel(t *testing.T) {
	cfg, err := Build(&nodepb.NodeState{
		Inbounds: []*nodepb.Inbound{{
			Tag: "vless", Core: nodepb.Core_CORE_XRAY,
			Protocol: nodepb.Protocol_PROTOCOL_VLESS, Enabled: true, ListenPort: 443,
		}},
	}, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Errorf("got a configuration for a node with no tunnel: %+v", cfg)
	}
}

func TestBuildIgnoresDisabledTunnel(t *testing.T) {
	state := tunnelState()
	state.Inbounds[0].Enabled = false
	cfg, err := Build(state, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Error("a disabled tunnel produced a configuration")
	}
}

func TestBuildRejections(t *testing.T) {
	cases := map[string]func(*nodepb.NodeState){
		"no forward target": func(s *nodepb.NodeState) {
			s.Inbounds[0].ForwardToTag = ""
		},
		"forward target missing": func(s *nodepb.NodeState) {
			s.Inbounds[0].ForwardToTag = "nothing-here"
		},
		"forward target disabled": func(s *nodepb.NodeState) {
			s.Inbounds[1].Enabled = false
		},
		"forward target is public": func(s *nodepb.NodeState) {
			s.Inbounds[1].ListenAddress = "0.0.0.0"
		},
		"forward target is not xray": func(s *nodepb.NodeState) {
			s.Inbounds[1].Core = nodepb.Core_CORE_OPENFLUX
		},
		"no domains": func(s *nodepb.NodeState) {
			delete(s.Inbounds[0].Params, "domains")
		},
		"domain is a url": func(s *nodepb.NodeState) {
			s.Inbounds[0].Params["domains"] = "https://t1.example/"
		},
		"key of the wrong length": func(s *nodepb.NodeState) {
			s.Inbounds[0].Secrets["encryption_key"] = "too-short"
		},
		"unknown encryption method": func(s *nodepb.NodeState) {
			s.Inbounds[0].Params["encryption_method"] = "42"
		},
		"port out of range": func(s *nodepb.NodeState) {
			s.Inbounds[0].ListenPort = 70000
		},
		"two tunnels": func(s *nodepb.NodeState) {
			second := &nodepb.Inbound{
				Tag: "wndns-5353", Core: nodepb.Core_CORE_WNDNS,
				Protocol: nodepb.Protocol_PROTOCOL_WNDNS, Enabled: true, ListenPort: 5353,
				Params:       map[string]string{"domains": "t3.example"},
				Secrets:      map[string]string{"encryption_key": testKey},
				ForwardToTag: "vless-local",
			}
			s.Inbounds = append(s.Inbounds, second)
		},
		"tuning value is not a number": func(s *nodepb.NodeState) {
			s.Inbounds[0].Params["udp_readers"] = "lots"
		},
	}
	for name, mutate := range cases {
		state := tunnelState()
		mutate(state)
		if _, err := Build(state, testOpts()); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	// A missing key file path is an agent mistake, not a state one.
	if _, err := Build(tunnelState(), Options{}); err == nil {
		t.Error("no key file path: expected an error")
	}
	// Forwarding off the node would turn it into an open relay.
	if _, err := Build(tunnelState(), Options{KeyFile: "/k", ForwardHost: "10.0.0.5"}); err == nil {
		t.Error("non-loopback forward host: expected an error")
	}
}

// The AES methods need shorter keys; getting this wrong means the tunnel
// refuses its own key file at startup.
func TestKeyLengthPerMethod(t *testing.T) {
	cases := map[int]int{
		EncryptionNone:      32,
		EncryptionXOR:       32,
		EncryptionChaCha20:  32,
		EncryptionAES128GCM: 16,
		EncryptionAES192GCM: 24,
		EncryptionAES256GCM: 32,
	}
	for method, want := range cases {
		if got := KeyLength(method); got != want {
			t.Errorf("KeyLength(%d) = %d, want %d", method, got, want)
		}
	}

	state := tunnelState()
	state.Inbounds[0].Params["encryption_method"] = "3"
	state.Inbounds[0].Secrets["encryption_key"] = strings.Repeat("a", 16)
	if _, err := Build(state, testOpts()); err != nil {
		t.Errorf("a 16-character key for AES-128 was rejected: %v", err)
	}
}

// Method 0 means no encryption, so no key is needed and a missing one must not
// stop the tunnel.
func TestNoEncryptionNeedsNoKey(t *testing.T) {
	state := tunnelState()
	state.Inbounds[0].Params["encryption_method"] = "0"
	delete(state.Inbounds[0].Secrets, "encryption_key")
	if _, err := Build(state, testOpts()); err != nil {
		t.Fatal(err)
	}
}

func TestOptionalTuningPassesThrough(t *testing.T) {
	state := tunnelState()
	state.Inbounds[0].Params["udp_readers"] = "4"
	state.Inbounds[0].Params["max_packet_size"] = "1200"
	state.Inbounds[0].Params["upload_compression"] = "0,1,2"
	state.Inbounds[0].Params["dns_upstream_servers"] = "1.1.1.1:53,8.8.8.8:53"

	cfg, err := Build(state, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(cfg.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["UDP_READERS"] != float64(4) {
		t.Errorf("UDP_READERS = %v", doc["UDP_READERS"])
	}
	if doc["MAX_PACKET_SIZE"] != float64(1200) {
		t.Errorf("MAX_PACKET_SIZE = %v", doc["MAX_PACKET_SIZE"])
	}
	if list, ok := doc["SUPPORTED_UPLOAD_COMPRESSION_TYPES"].([]any); !ok || len(list) != 3 {
		t.Errorf("upload compression = %v", doc["SUPPORTED_UPLOAD_COMPRESSION_TYPES"])
	}
	if list, ok := doc["DNS_UPSTREAM_SERVERS"].([]any); !ok || len(list) != 2 {
		t.Errorf("dns upstream = %v", doc["DNS_UPSTREAM_SERVERS"])
	}

	// Anything the panel did not set must stay absent, so the tunnel's own
	// defaults remain in charge.
	if _, present := doc["DNS_REQUEST_WORKERS"]; present {
		t.Error("an unset tuning value was written anyway")
	}

	// And the loader still accepts it.
	if _, err := dnsconfig.LoadServerConfigFromJSONBase64WithOverrides(
		cfg.Base64JSON(), dnsconfig.ServerConfigOverrides{}); err != nil {
		t.Fatalf("the tunnel rejected the tuned configuration: %v", err)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	state := tunnelState()
	first, err := Build(state, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Build(state, testOpts())
		if err != nil {
			t.Fatal(err)
		}
		if string(again.JSON) != string(first.JSON) {
			t.Fatal("two renders of the same state differ")
		}
	}
}
