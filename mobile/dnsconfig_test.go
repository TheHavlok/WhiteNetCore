package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// dnsConfigJSON reproduces what StartVPN builds for the tunnel, so the shape
// can be checked without starting anything.
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

	domains := make([]string, 0, len(cfg.MasterDns.Domains))
	for _, domain := range cfg.MasterDns.Domains {
		if domain = strings.TrimSpace(domain); domain != "" {
			domains = append(domains, `"`+domain+`"`)
		}
	}
	method := ""
	if cfg.MasterDns.Method != nil {
		method = jsonMethodLine(*cfg.MasterDns.Method)
	}

	raw := `{"PROTOCOL_TYPE":"SOCKS5","DOMAINS":[` + strings.Join(domains, ",") + `]` + method +
		`,"ENCRYPTION_KEY":"` + cfg.Crypto.Key + `"}`
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("the built config is not valid JSON: %v\n%s", err, raw)
	}
	return out
}

func jsonMethodLine(method int) string {
	return `,"DATA_ENCRYPTION_METHOD":` + itoa(method)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
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
