// Package wndnscfg renders the WhiteNet DNS tunnel's configuration from a
// node's desired state.
//
// The tunnel is masterdnsvpn, which has no accounts: it authenticates with one
// shared encryption key per server. The panel therefore runs it in TCP-forward
// mode, pointing every tunnelled stream at a local Xray inbound on the
// loopback interface. That inbound is what authenticates the user, counts
// their traffic and can revoke them - all things the DNS protocol cannot do.
//
// The configuration is handed to the tunnel as base64 JSON on the command
// line, using the loader masterdnsvpn already has, so nothing has to be
// written to a file that could drift from the state.
package wndnscfg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

// Encryption methods, as masterdnsvpn numbers them.
const (
	EncryptionNone      = 0
	EncryptionXOR       = 1
	EncryptionChaCha20  = 2
	EncryptionAES128GCM = 3
	EncryptionAES192GCM = 4
	EncryptionAES256GCM = 5
)

// KeyLength is how many hex characters a key must have for each method. The
// tunnel reads the key file as text and insists on the exact length, so the
// agent has to get this right before the process starts rather than after it
// fails.
func KeyLength(method int) int {
	switch method {
	case EncryptionAES128GCM:
		return 16
	case EncryptionAES192GCM:
		return 24
	default:
		return 32
	}
}

// Options are what the agent knows and the state does not.
type Options struct {
	// KeyFile is where the agent wrote the encryption key.
	KeyFile string
	// LogLevel is the tunnel's own level: debug, info, warn, error.
	LogLevel string
	// ForwardHost is the loopback address the tunnel forwards to. Empty means
	// 127.0.0.1.
	ForwardHost string
}

// Config is one tunnel instance's configuration.
type Config struct {
	// Inbound is the wndns inbound this configuration came from, for logs.
	InboundTag string
	// Key is the encryption key, which the agent must write to Options.KeyFile
	// before starting the process.
	Key string
	// KeyMethod is the method the key belongs to.
	KeyMethod int
	// JSON is the configuration itself.
	JSON []byte
}

// Base64JSON is what the tunnel's --config-json flag takes.
func (c Config) Base64JSON() string {
	return base64.StdEncoding.EncodeToString(c.JSON)
}

// Build renders the configuration for the wndns inbound in state.
//
// It returns nil without an error when the node has no DNS tunnel, which is
// the normal case: the agent then keeps that core stopped.
func Build(state *nodepb.NodeState, opts Options) (*Config, error) {
	if state == nil {
		return nil, fmt.Errorf("wndnscfg: nil state")
	}

	var inbound *nodepb.Inbound
	for _, in := range state.GetInbounds() {
		if in.GetProtocol() != nodepb.Protocol_PROTOCOL_WNDNS || !in.GetEnabled() {
			continue
		}
		if inbound != nil {
			// The tunnel binds one UDP port and has one key; two of them on
			// one node would need two processes, which the panel does not
			// model. Refuse clearly rather than silently serving one.
			return nil, fmt.Errorf("wndnscfg: node has more than one enabled wndns inbound (%s and %s)",
				inbound.GetTag(), in.GetTag())
		}
		inbound = in
	}
	if inbound == nil {
		return nil, nil
	}

	params := inbound.GetParams()
	if params == nil {
		params = map[string]string{}
	}
	secrets := inbound.GetSecrets()
	if secrets == nil {
		secrets = map[string]string{}
	}

	// The forward target is another inbound on this node, named by tag. This
	// is the chain that gives the tunnel a user model.
	target, err := findForwardTarget(state, inbound)
	if err != nil {
		return nil, err
	}

	domains := splitList(params["domains"])
	if len(domains) == 0 {
		return nil, fmt.Errorf("wndnscfg: inbound %s has no params.domains", inbound.GetTag())
	}
	for _, domain := range domains {
		if strings.ContainsAny(domain, " /:") {
			return nil, fmt.Errorf("wndnscfg: %q is not a domain", domain)
		}
	}

	method := atoiOr(params["encryption_method"], EncryptionChaCha20)
	if method < EncryptionNone || method > EncryptionAES256GCM {
		return nil, fmt.Errorf("wndnscfg: unknown encryption method %d", method)
	}
	key := secrets["encryption_key"]
	if method != EncryptionNone {
		if want := KeyLength(method); len(key) != want {
			return nil, fmt.Errorf("wndnscfg: encryption key is %d characters, method %d needs %d",
				len(key), method, want)
		}
	}
	if opts.KeyFile == "" {
		return nil, fmt.Errorf("wndnscfg: no key file path given")
	}

	port := int(inbound.GetListenPort())
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("wndnscfg: port %d is out of range", port)
	}
	host := inbound.GetListenAddress()
	if host == "" {
		host = "0.0.0.0"
	}
	forwardHost := opts.ForwardHost
	if forwardHost == "" {
		forwardHost = "127.0.0.1"
	}
	// The tunnel's upstream must stay on the node: forwarding somewhere else
	// would turn it into an open relay.
	if ip := net.ParseIP(forwardHost); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("wndnscfg: forward host %q must be on the loopback interface", forwardHost)
	}

	// Keys are masterdnsvpn's own TOML tags; its JSON loader matches on them.
	doc := map[string]any{
		// TCP mode forwards every tunnelled stream to one address, which is
		// exactly the chain the panel wants. SOCKS5 mode would make the node
		// an open proxy for anyone holding the shared key.
		"PROTOCOL_TYPE":          "TCP",
		"UDP_HOST":               host,
		"UDP_PORT":               port,
		"DOMAIN":                 domains,
		"FORWARD_IP":             forwardHost,
		"FORWARD_PORT":           int(target.GetListenPort()),
		"DATA_ENCRYPTION_METHOD": method,
		"ENCRYPTION_KEY_FILE":    opts.KeyFile,
		"LOG_LEVEL":              defaultString(opts.LogLevel, "info"),
	}

	// Optional tuning, passed through only when the panel set it, so the
	// tunnel's own defaults stay in charge otherwise.
	for key, param := range map[string]string{
		"UDP_READERS":             "udp_readers",
		"MAX_PACKET_SIZE":         "max_packet_size",
		"MAX_CONCURRENT_REQUESTS": "max_concurrent_requests",
		"DNS_REQUEST_WORKERS":     "dns_request_workers",
		"SESSION_TIMEOUT_SECONDS": "session_timeout_seconds",
	} {
		if v := params[param]; v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("wndnscfg: params.%s = %q is not a number", param, v)
			}
			doc[key] = n
		}
	}
	if v := splitIntList(params["upload_compression"]); len(v) > 0 {
		doc["SUPPORTED_UPLOAD_COMPRESSION_TYPES"] = v
	}
	if v := splitIntList(params["download_compression"]); len(v) > 0 {
		doc["SUPPORTED_DOWNLOAD_COMPRESSION_TYPES"] = v
	}
	if v := splitList(params["dns_upstream_servers"]); len(v) > 0 {
		doc["DNS_UPSTREAM_SERVERS"] = v
	}

	raw, err := marshalStable(doc)
	if err != nil {
		return nil, err
	}
	return &Config{
		InboundTag: inbound.GetTag(),
		Key:        key,
		KeyMethod:  method,
		JSON:       raw,
	}, nil
}

// findForwardTarget resolves the inbound the tunnel forwards into and checks
// that it can actually serve the traffic.
func findForwardTarget(state *nodepb.NodeState, tunnel *nodepb.Inbound) (*nodepb.Inbound, error) {
	tag := tunnel.GetForwardToTag()
	if tag == "" {
		return nil, fmt.Errorf("wndnscfg: inbound %s has no forward_to_tag; without it the tunnel would carry traffic nothing authenticates",
			tunnel.GetTag())
	}
	for _, in := range state.GetInbounds() {
		if in.GetTag() != tag {
			continue
		}
		if !in.GetEnabled() {
			return nil, fmt.Errorf("wndnscfg: inbound %s forwards to %s, which is disabled", tunnel.GetTag(), tag)
		}
		if in.GetCore() != nodepb.Core_CORE_XRAY {
			return nil, fmt.Errorf("wndnscfg: inbound %s forwards to %s, which is not served by xray-core", tunnel.GetTag(), tag)
		}
		// The target has to listen on the loopback interface. If it were
		// public, the tunnel's chain would be bypassable and the port would
		// be an unannounced second way in.
		if addr := in.GetListenAddress(); addr != "" {
			if ip := net.ParseIP(addr); ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("wndnscfg: forward target %s listens on %s; it must be on the loopback interface", tag, addr)
			}
		}
		return in, nil
	}
	return nil, fmt.Errorf("wndnscfg: inbound %s forwards to %s, which does not exist on this node", tunnel.GetTag(), tag)
}

// marshalStable serialises the document. encoding/json sorts map keys, so an
// unchanged state renders byte-identical output and the agent can tell a real
// change from a map iteration.
func marshalStable(doc map[string]any) ([]byte, error) {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("wndnscfg: marshal: %w", err)
	}
	return raw, nil
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitIntList(v string) []int {
	parts := splitList(v)
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func atoiOr(v string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return n
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
