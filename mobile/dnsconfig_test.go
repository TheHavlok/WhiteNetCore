package mobile

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// dnsConfigJSON is what StartVPN hands the tunnel for a profile, parsed so
// the shape can be checked without starting anything.
//
// This exists because of a regression: the method was written unconditionally
// with a default of its own, which silently changed it under every profile
// that predates the field. The two ends have to agree on the method, so such
// a profile stops working with no visible cause.
func dnsConfigJSON(t *testing.T, profile string) map[string]any {
	t.Helper()
	var cfg yamlConfig
	if err := yaml.Unmarshal([]byte(profile), &cfg); err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	raw, err := dnsClientJSON(cfg, 10808)
	if err != nil {
		t.Fatalf("build the tunnel config: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("the built config is not valid JSON: %v\n%s", err, raw)
	}
	return out
}

func TestLegacyDNSProfileKeepsTheLibraryDefaultMethod(t *testing.T) {
	// A profile from before the field existed. Sending any method here would
	// change what it has always used.
	profile := `
mode: cnc
auth:
  provider: dns
crypto:
  key: "4f3c2b1a09876543210fedcba9876543"
masterdns:
  domains: ["t1.tun.example"]
net:
  transport: dns
socks:
  host: "127.0.0.1"
  port: 10808
`
	config := dnsConfigJSON(t, profile)
	if _, present := config["DATA_ENCRYPTION_METHOD"]; present {
		t.Fatalf("a profile that names no method must not get one: %v", config)
	}
	domains, _ := config["DOMAINS"].([]any)
	if len(domains) != 1 || domains[0] != "t1.tun.example" {
		t.Fatalf("domains = %v", config["DOMAINS"])
	}
}

func TestDNSProfileWithAMethodSendsIt(t *testing.T) {
	profile := `
auth:
  provider: dns
crypto:
  key: "4f3c2b1a09876543210fedcba9876543"
masterdns:
  domains: ["t1.tun.example", "t2.tun.example"]
  method: 2
`
	config := dnsConfigJSON(t, profile)
	if config["DATA_ENCRYPTION_METHOD"] != float64(2) {
		t.Fatalf("method = %v, want 2", config["DATA_ENCRYPTION_METHOD"])
	}
	// Several domains travel, because a resolver that rate-limits one still
	// leaves the others.
	if domains, _ := config["DOMAINS"].([]any); len(domains) != 2 {
		t.Fatalf("domains = %v", config["DOMAINS"])
	}
}

func TestDNSProfileCanAskForNoEncryption(t *testing.T) {
	// Method 0 is a real choice, and has to be distinguishable from "unset".
	profile := `
auth:
  provider: dns
crypto:
  key: "k"
masterdns:
  domains: ["t.example"]
  method: 0
`
	config := dnsConfigJSON(t, profile)
	if config["DATA_ENCRYPTION_METHOD"] != float64(0) {
		t.Fatalf("method = %v, want 0", config["DATA_ENCRYPTION_METHOD"])
	}
}

// The tunnel polls for downstream data; without it, download speed is
// whatever the start of a transfer happens to leave in flight.
func TestDNSProfilePollsForDownloads(t *testing.T) {
	config := dnsConfigJSON(t, `
masterdns:
  domains: ["t.example"]
crypto:
  key: "k"
`)
	if config["DOWNLOAD_POLL_WINDOW"] != float64(dnsDownloadPollWindow) {
		t.Fatalf("poll window = %v, want %d", config["DOWNLOAD_POLL_WINDOW"], dnsDownloadPollWindow)
	}
}

// A profile's own resolvers replace the built-in list; one that names none,
// or none that parse, gets the built-in list.
func TestDNSResolversFromProfile(t *testing.T) {
	var cfg yamlConfig
	if err := yaml.Unmarshal([]byte(`
masterdns:
  domains: ["t.example"]
  resolvers: ["10.0.0.53", "10.0.0.54:5353", "garbage"]
`), &cfg); err != nil {
		t.Fatal(err)
	}
	resolvers, ports := dnsResolvers(cfg)
	if len(resolvers) != 2 || resolvers[0].IP != "10.0.0.53" || resolvers[1].Port != 5353 {
		t.Fatalf("resolvers = %v", resolvers)
	}
	if ports["10.0.0.53"] != 53 {
		t.Fatalf("the resolver map holds ports, got %v", ports)
	}

	for _, profile := range []string{
		"masterdns:\n  domains: [\"t.example\"]\n",
		"masterdns:\n  domains: [\"t.example\"]\n  resolvers: [\"nope\"]\n",
	} {
		var plain yamlConfig
		if err := yaml.Unmarshal([]byte(profile), &plain); err != nil {
			t.Fatal(err)
		}
		got, _ := dnsResolvers(plain)
		if len(got) != len(defaultDNSResolvers) {
			t.Fatalf("%q: %d resolvers, want the %d built in", profile, len(got), len(defaultDNSResolvers))
		}
	}
}
