package api

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	"github.com/thehavlok/whitenet/internal/panel/keygen"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/store"
	mdnsconfig "github.com/thehavlok/whitenet/masterdnsvpn/config"
)

// secretBox is an alias so the helpers read as being about secrets rather
// than about a particular package path.
type secretBox = secret.Box

func sortStrings(values []string) { sort.Strings(values) }

func validProtocol(protocol string) bool {
	switch protocol {
	case store.ProtoVLESS, store.ProtoVMess, store.ProtoTrojan,
		store.ProtoShadowsocks, store.ProtoShadowsocks2022,
		store.ProtoHysteria2, store.ProtoWNDNS:
		return true
	default:
		return false
	}
}

func validSecurity(security string) bool {
	switch security {
	case "none", "tls", "reality":
		return true
	default:
		return false
	}
}

// validateTag checks an Xray tag. It is the key traffic counters are stored
// under and it has to survive being put in a JSON configuration, so the
// character set is deliberately narrow.
func validateTag(tag string) error {
	if len(tag) < 2 || len(tag) > 64 {
		return errors.New("a tag is 2 to 64 characters")
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("a tag cannot contain %q", string(r))
		}
	}
	return nil
}

// validateInbound checks that a protocol has what it needs before the panel
// stores it.
//
// The agent and xray-core would both reject a bad inbound, but by then the
// state has been pushed and a node is failing to apply it. Catching it here
// means the admin sees the problem in the form they are filling in.
func validateInbound(protocol, network, security string, params store.JSONMap, secrets map[string]string) error {
	switch protocol {
	case store.ProtoShadowsocks:
		method := params["method"]
		if method == "" {
			return errors.New("Shadowsocks needs a method")
		}
		if strings.HasPrefix(method, "2022-") {
			return errors.New("that is a 2022 method; choose the Shadowsocks 2022 protocol instead")
		}
		if !contains(keygen.LegacyShadowsocksMethods(), method) {
			return fmt.Errorf("unsupported Shadowsocks method %q", method)
		}

	case store.ProtoShadowsocks2022:
		method := params["method"]
		if !strings.HasPrefix(method, "2022-") {
			return errors.New("Shadowsocks 2022 needs a 2022-blake3-* method")
		}
		if _, err := keygen.Shadowsocks2022KeySize(method); err != nil {
			return fmt.Errorf("unsupported method %q", method)
		}
		if secrets["password"] == "" {
			return errors.New("Shadowsocks 2022 needs a server key; use the generate button")
		}
		if !keygen.SupportsMultipleUsers(method) {
			return fmt.Errorf("%s cannot serve more than one user; choose an aes method", method)
		}

	case store.ProtoHysteria2:
		if security != "tls" {
			return errors.New("Hysteria2 runs over QUIC and needs TLS")
		}

	case store.ProtoWNDNS:
		domains := splitCSV(params["domains"])
		if len(domains) == 0 {
			return errors.New("the DNS tunnel needs at least one domain")
		}
		for _, domain := range domains {
			if err := validateDomain(domain); err != nil {
				return err
			}
		}
		for _, resolver := range splitCSV(params["resolvers"]) {
			if parsed, _ := mdnsconfig.ParseResolverList([]string{resolver}); len(parsed) == 0 {
				return fmt.Errorf("%q is not a resolver: use an address, address:port or [v6]:port", resolver)
			}
		}
		method, err := strconv.Atoi(orDefault(params["encryption_method"], "2"))
		if err != nil || method < 0 || method > 5 {
			return errors.New("the encryption method must be 0 to 5")
		}
		if method != 0 {
			key := secrets["encryption_key"]
			want := wndnsKeyLength(method)
			if len(key) != want {
				return fmt.Errorf("the encryption key must be %d hex characters for method %d; use the generate button", want, method)
			}
		}
	}

	switch security {
	case "reality":
		if params["target"] == "" && params["dest"] == "" {
			return errors.New("REALITY needs a target, such as www.microsoft.com:443")
		}
		if params["server_names"] == "" && params["sni"] == "" {
			return errors.New("REALITY needs at least one server name")
		}
		if params["short_ids"] == "" {
			return errors.New("REALITY needs at least one short id; use the generate button")
		}
		if secrets["private_key"] == "" {
			return errors.New("REALITY needs a private key; use the generate button")
		}
		if _, err := keygen.RealityPublicKey(secrets["private_key"]); err != nil {
			return errors.New("that REALITY private key is not a valid x25519 key")
		}

	case "tls":
		if params["cert_file"] == "" && secrets["certificate"] == "" {
			return errors.New("TLS needs either a certificate file path or a certificate")
		}
		if secrets["certificate"] != "" && secrets["key"] == "" {
			return errors.New("a TLS certificate needs its private key")
		}
	}

	// A finalmask that takes a password must have one, or the node refuses
	// the inbound at startup.
	for _, mask := range append(splitCSV(params["finalmask_udp"]), splitCSV(params["finalmask_tcp"])...) {
		switch mask {
		case "mkcp-aes128gcm":
			if secrets["mkcp-aes128gcm_password"] == "" {
				return errors.New("the mkcp-aes128gcm mask needs a password")
			}
		case "salamander":
			if secrets["salamander_password"] == "" && secrets["obfs_password"] == "" {
				return errors.New("the salamander mask needs an obfuscation password")
			}
		}
	}

	_ = network
	return nil
}

// wndnsKeyLength is how many hex characters the tunnel's key file needs for a
// method. It mirrors the tunnel's own table, which reads the file as text and
// insists on the exact length.
func wndnsKeyLength(method int) int {
	switch method {
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}

func validateDomain(domain string) error {
	if domain == "" {
		return errors.New("a domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("the domain %q is too long", domain)
	}
	if strings.ContainsAny(domain, " /:@?#") {
		return fmt.Errorf("%q is not a domain", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return fmt.Errorf("%q has an empty label", domain)
		}
		if len(label) > 63 {
			return fmt.Errorf("%q has a label longer than 63 characters", domain)
		}
	}
	return nil
}

// validateChannel checks a flux channel before the panel stores it.
func validateChannel(transport, url string, params map[string]string, secret string) error {
	if !fluxnode.ValidCarrier(transport) {
		return fmt.Errorf("unknown carrier %q", transport)
	}
	switch transport {
	case fluxnode.CarrierDirect:
		listen := params["listen"]
		if listen == "" {
			return errors.New("the direct carrier needs a listen address, such as 0.0.0.0:8444")
		}
		if _, _, err := net.SplitHostPort(listen); err != nil {
			return errors.New("the listen address must be host:port")
		}
	case fluxnode.CarrierOneMe:
		if params["token"] == "" || params["uid"] == "" {
			return errors.New("the MAX carrier needs a token and a user id")
		}
		if _, err := strconv.ParseInt(params["uid"], 10, 64); err != nil {
			return errors.New("the MAX user id must be a number")
		}
	default:
		if url == "" {
			return fmt.Errorf("the %s carrier needs a document URL", transport)
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return errors.New("the document URL must start with http:// or https://")
		}
	}

	// A channel without a secret runs unauthenticated, which would let anyone
	// who finds the document use the exit.
	if len(secret) != 64 {
		return errors.New("a channel needs a 64-character hex secret; use the generate button")
	}
	for _, r := range secret {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return errors.New("the channel secret must be hex")
		}
	}

	// Extra carriers in one channel: "type:url@priority", comma separated.
	for _, spec := range splitCSV(params["carriers"]) {
		carrierType, _, _ := strings.Cut(spec, ":")
		if !fluxnode.ValidCarrier(strings.TrimSpace(carrierType)) {
			return fmt.Errorf("unknown carrier %q in the extra carrier list", carrierType)
		}
	}
	return nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
