// Package clientprofile turns a server from a WhiteNet subscription into the
// configuration an app can actually start.
//
// The apps hold one opaque configuration string per profile and hand it to the
// core, which tells the two formats apart by shape: Xray's is JSON, WhiteNet's
// is YAML. This package is the only place that knows how a subscription's
// protocol and params become one of those, so iOS and Android cannot disagree
// about what a server means - and neither has to re-implement it in Swift or
// Kotlin.
//
// The mapping is the inverse of what the panel generates for a node, and the
// parameter names are the ones LINKS.md tabulates.
package clientprofile

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/thehavlok/whitenet/internal/panel/subscription"
	"github.com/thehavlok/whitenet/internal/xray"
)

// Kind says which core runs a profile.
type Kind string

const (
	// KindXray is an Xray JSON configuration.
	KindXray Kind = "xray"
	// KindWhiteNet is a WhiteNet YAML profile: the DNS tunnel, or flux.
	KindWhiteNet Kind = "whitenet"
)

// Default local ports.
//
// Two of them, because a chained profile runs both cores at once: the DNS
// tunnel offers its SOCKS proxy on ChainSocksPort and Xray dials out through
// it while serving the device on SocksPort. A single port would have the two
// cores fighting over one listener.
const (
	DefaultSocksPort      = 10808
	DefaultChainSocksPort = 10809
)

// Options are the local details a subscription does not carry.
type Options struct {
	// SocksPort is where the core listens for the device's traffic.
	SocksPort int
	// ChainSocksPort is the inner tunnel's own proxy, used by a chained
	// profile.
	ChainSocksPort int
}

func (o Options) withDefaults() Options {
	if o.SocksPort == 0 {
		o.SocksPort = DefaultSocksPort
	}
	if o.ChainSocksPort == 0 {
		o.ChainSocksPort = DefaultChainSocksPort
	}
	if o.ChainSocksPort == o.SocksPort {
		o.ChainSocksPort = o.SocksPort + 1
	}
	return o
}

// Profile is a connectable server as the app stores it.
type Profile struct {
	// ID is the subscription's server id, so the app can match a profile to
	// the server it came from across refreshes.
	ID string
	// Name is what the user sees.
	Name string
	// Kind says which core Config belongs to.
	Kind Kind
	// Config is the configuration string, JSON or YAML.
	Config string
	// Inner is the second half of a chained profile. When it is set, the app
	// starts Config first, waits for it, and then starts Inner, which dials
	// out through it. Only the DNS tunnel uses this: it has no accounts of
	// its own, so the inner protocol is what authenticates the user.
	Inner *Profile
}

// Chained reports whether this profile needs two cores.
func (p *Profile) Chained() bool { return p != nil && p.Inner != nil }

// FromServer builds the profile for one subscription server.
func FromServer(server subscription.Server, opt Options) (*Profile, error) {
	opt = opt.withDefaults()

	switch server.Protocol {
	case subscription.ProtocolWNDNS:
		return dnsProfile(server, opt)
	case subscription.ProtocolFlux:
		return fluxProfile(server, opt)
	default:
		config, err := xrayConfig(server, opt.SocksPort, "")
		if err != nil {
			return nil, err
		}
		return &Profile{ID: server.ID, Name: server.Name, Kind: KindXray, Config: config}, nil
	}
}

// xrayConfig renders an Xray client configuration for one server.
//
// dialerTag, when set, makes the outbound dial through another outbound with
// that tag - which is how a chained profile reaches the server through a
// tunnel instead of over the network.
func xrayConfig(server subscription.Server, socksPort int, dialerTag string) (string, error) {
	outbound, err := outboundFor(server)
	if err != nil {
		return "", err
	}
	if dialerTag != "" {
		stream, _ := outbound["streamSettings"].(map[string]any)
		if stream == nil {
			stream = map[string]any{"network": "tcp", "security": "none"}
			outbound["streamSettings"] = stream
		}
		// sockopt.dialerProxy rather than the older proxySettings.tag: the
		// two are mutually exclusive and the core rejects a config that sets
		// both, so there is exactly one right choice here.
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt == nil {
			sockopt = map[string]any{}
			stream["sockopt"] = sockopt
		}
		sockopt["dialerProxy"] = dialerTag
	}

	config := xray.BuildConfig(outbound, socksPort)
	if dialerTag != "" {
		outbounds, _ := config["outbounds"].([]any)
		config["outbounds"] = append(outbounds, map[string]any{
			"tag":      dialerTag,
			"protocol": "socks",
			"settings": map[string]any{
				"servers": []any{map[string]any{
					"address": "127.0.0.1",
					"port":    dialerPort(server),
				}},
			},
		})
	}

	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("clientprofile: marshal: %w", err)
	}
	return string(raw), nil
}

// dialerPort is stashed on the server by dnsProfile, which is the only caller
// that chains. Keeping it out of the subscription format means a client-side
// detail does not become part of the wire contract.
func dialerPort(server subscription.Server) int {
	if server.Params == nil {
		return DefaultChainSocksPort
	}
	if port, err := strconv.Atoi(server.Params[paramChainPort]); err == nil && port > 0 {
		return port
	}
	return DefaultChainSocksPort
}

// paramChainPort is internal to this package; it never appears in a
// subscription.
const paramChainPort = "__chain_socks_port"

// outboundFor builds the proxy outbound for a server.
func outboundFor(server subscription.Server) (map[string]any, error) {
	p := server.Params
	if p == nil {
		p = map[string]string{}
	}
	if server.Address == "" {
		return nil, fmt.Errorf("clientprofile: %s server %q has no address", server.Protocol, server.Name)
	}
	if server.Port <= 0 || server.Port > 65535 {
		return nil, fmt.Errorf("clientprofile: %s server %q has port %d", server.Protocol, server.Name, server.Port)
	}

	var settings map[string]any
	switch server.Protocol {
	case subscription.ProtocolVLESS:
		if p["uuid"] == "" {
			return nil, missing(server, "uuid")
		}
		user := map[string]any{"id": p["uuid"], "encryption": "none"}
		if flow := p["flow"]; flow != "" {
			user["flow"] = flow
		}
		settings = vnextSettings(server, user)

	case subscription.ProtocolVMess:
		if p["uuid"] == "" {
			return nil, missing(server, "uuid")
		}
		user := map[string]any{"id": p["uuid"], "security": orDefault(p["security"], "auto")}
		if alterID, err := strconv.Atoi(p["alter_id"]); err == nil && alterID > 0 {
			user["alterId"] = alterID
		}
		settings = vnextSettings(server, user)

	case subscription.ProtocolTrojan:
		if p["password"] == "" {
			return nil, missing(server, "password")
		}
		settings = map[string]any{"servers": []any{map[string]any{
			"address":  server.Address,
			"port":     server.Port,
			"password": p["password"],
		}}}

	case subscription.ProtocolShadowsocks, subscription.ProtocolShadowsocks2022:
		if p["method"] == "" {
			return nil, missing(server, "method")
		}
		if p["password"] == "" {
			return nil, missing(server, "password")
		}
		settings = map[string]any{"servers": []any{map[string]any{
			"address":  server.Address,
			"port":     server.Port,
			"method":   p["method"],
			"password": p["password"],
		}}}

	case subscription.ProtocolHysteria2:
		if p["auth"] == "" {
			return nil, missing(server, "auth")
		}
		// Hysteria's outbound carries only where to connect; the credential
		// is a transport setting, because in this core Hysteria *is* the
		// transport. Putting it in the outbound builds fine and then fails
		// to authenticate, which is the worst of both.
		settings = map[string]any{
			"version": 2,
			"address": server.Address,
			"port":    server.Port,
		}

	default:
		return nil, fmt.Errorf("clientprofile: unsupported protocol %q", server.Protocol)
	}

	outbound := map[string]any{
		"tag":      "proxy",
		"protocol": outboundProtocol(server.Protocol),
		"settings": settings,
	}
	if stream := streamFor(server); stream != nil {
		outbound["streamSettings"] = stream
	}
	return outbound, nil
}

// outboundProtocol maps our protocol names onto the core's.
func outboundProtocol(protocol string) string {
	switch protocol {
	case subscription.ProtocolShadowsocks2022:
		// One Shadowsocks outbound serves both: the method decides which
		// cipher family it is, and the core reads it from there.
		return "shadowsocks"
	case subscription.ProtocolHysteria2:
		// Hysteria2 is native here, under the name the core uses.
		return "hysteria"
	default:
		return protocol
	}
}

func vnextSettings(server subscription.Server, user map[string]any) map[string]any {
	return map[string]any{"vnext": []any{map[string]any{
		"address": server.Address,
		"port":    server.Port,
		"users":   []any{user},
	}}}
}

func missing(server subscription.Server, field string) error {
	return fmt.Errorf("clientprofile: %s server %q is missing params.%s",
		server.Protocol, server.Name, field)
}

// streamFor builds streamSettings from the transport and its params.
func streamFor(server subscription.Server) map[string]any {
	p := server.Params
	if p == nil {
		p = map[string]string{}
	}

	network, security := networkAndSecurity(server)
	stream := map[string]any{"network": network, "security": security}

	switch security {
	case "reality":
		// The public key goes in under both names: the field was publicKey
		// before Xray 25.x and is password now. Unknown keys are ignored by
		// the config parser, so writing both costs nothing and avoids a
		// failure that looks like a working tunnel carrying no traffic.
		stream["realitySettings"] = compact(map[string]any{
			"serverName":  p["sni"],
			"fingerprint": orDefault(p["fp"], "chrome"),
			"publicKey":   p["pbk"],
			"password":    p["pbk"],
			"shortId":     p["sid"],
			"spiderX":     p["spx"],
		})
	case "tls":
		tls := compact(map[string]any{
			"serverName":  firstNonEmpty(p["sni"], p["host"], server.Address),
			"fingerprint": orDefault(p["fp"], "chrome"),
		})
		if alpn := p["alpn"]; alpn != "" {
			tls["alpn"] = splitList(alpn)
		}
		if isTrue(p["allow_insecure"]) {
			tls["allowInsecure"] = true
		}
		stream["tlsSettings"] = tls
	}

	switch network {
	case "xhttp":
		stream["xhttpSettings"] = compact(map[string]any{
			"path": orDefault(p["path"], "/"),
			"host": p["host"],
			"mode": orDefault(p["mode"], "auto"),
		})
	case "ws":
		ws := map[string]any{"path": orDefault(p["path"], "/")}
		if host := p["host"]; host != "" {
			ws["host"] = host
		}
		stream["wsSettings"] = ws
	case "httpupgrade":
		stream["httpupgradeSettings"] = compact(map[string]any{
			"path": orDefault(p["path"], "/"),
			"host": p["host"],
		})
	case "grpc":
		grpc := map[string]any{"serviceName": p["service_name"]}
		if isTrue(p["multi_mode"]) {
			grpc["multiMode"] = true
		}
		stream["grpcSettings"] = grpc
	case "kcp":
		stream["kcpSettings"] = map[string]any{}
		// mKCP's own header and seed were removed from kcpSettings in this
		// core and became finalmask masks - a config that still carries them
		// is refused outright. A seed maps to the keyed mask, since that is
		// what a seed did.
		switch {
		case firstNonEmpty(p["finalmask"], p["header"]) != "":
			stream["finalmask"] = finalMask(
				firstNonEmpty(p["finalmask"], p["header"]),
				firstNonEmpty(p["finalmask_password"], p["seed"]))
		case p["seed"] != "":
			stream["finalmask"] = finalMask("mkcp-aes128gcm", p["seed"])
		}
	case "hysteria":
		hysteria := compact(map[string]any{
			"version": 2,
			"auth":    p["auth"],
			"up":      bandwidth(p["up_mbps"]),
			"down":    bandwidth(p["down_mbps"]),
		})
		stream["hysteriaSettings"] = hysteria
		// Hysteria2's salamander obfuscation is a finalmask mask here too,
		// which is why the subscription's obfs/obfs_password are described as
		// the client's view of the same thing.
		if obfs := p["obfs"]; obfs != "" {
			stream["finalmask"] = finalMask(obfs, p["obfs_password"])
		}
	}

	return stream
}

// networkAndSecurity resolves the transport name a subscription uses into the
// core's network plus security pair. The subscription says "reality", which is
// a security over a plain network, not a network of its own.
func networkAndSecurity(server subscription.Server) (string, string) {
	switch server.Transport {
	case "", "raw", "tcp":
		return "tcp", "none"
	case "reality":
		return "tcp", "reality"
	case "tls":
		return "tcp", "tls"
	case "xhttp", "ws", "httpupgrade", "grpc", "kcp":
		security := "none"
		if server.Params != nil {
			if server.Params["sni"] != "" || server.Params["security"] == "tls" {
				security = "tls"
			}
			if server.Params["security"] == "reality" || server.Params["pbk"] != "" {
				security = "reality"
			}
		}
		return server.Transport, security
	case "hysteria":
		return "hysteria", "tls"
	default:
		return server.Transport, "none"
	}
}

// tcpMasks are the masks that apply to a stream transport; everything else
// this core registers is a UDP mask. The side matters: finalmask has one list
// per side and a mask put in the wrong one is accepted by the JSON decoder and
// then never applied.
var tcpMasks = map[string]bool{"header-custom": true, "fragment": true, "sudoku": true}

func finalMask(kind, password string) map[string]any {
	mask := map[string]any{"type": kind}
	if password != "" {
		mask["settings"] = map[string]any{"password": password}
	}
	side := "udp"
	if tcpMasks[kind] {
		side = "tcp"
	}
	return map[string]any{side: []any{mask}}
}

// bandwidth renders a Hysteria rate. The core takes a string such as
// "100 mbps", not a number, so a bare figure from the subscription is given
// its unit here.
func bandwidth(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, err := strconv.Atoi(value); err == nil {
		return value + " mbps"
	}
	return value
}

// --- the DNS tunnel ---------------------------------------------------------

// dnsProfile builds the pair a DNS-tunnelled server needs.
//
// The tunnel authenticates nobody: one shared key per server lets in anyone
// who has it. So the panel chains it into a local inbound on the node, and the
// client has to do the matching thing - bring the tunnel up, then speak the
// chained protocol through it. The chained hop reaches the node's loopback
// inbound, so the server dials nothing of the client's choosing: in forward
// mode the tunnel ignores the requested destination entirely.
func dnsProfile(server subscription.Server, opt Options) (*Profile, error) {
	p := server.Params
	if p == nil {
		return nil, missing(server, "domains")
	}
	if p["domains"] == "" {
		return nil, missing(server, "domains")
	}
	if p["encryption_key"] == "" {
		return nil, missing(server, "encryption_key")
	}
	if server.Chain == nil {
		return nil, fmt.Errorf("clientprofile: DNS server %q has no chain: "+
			"the tunnel has no accounts of its own, so without an inner protocol there is nothing to authenticate with",
			server.Name)
	}

	domains := splitList(p["domains"])
	quoted := make([]string, 0, len(domains))
	for _, domain := range domains {
		quoted = append(quoted, strconv.Quote(fmt.Sprint(domain)))
	}

	outer := fmt.Sprintf(`mode: cnc
auth:
  provider: dns
crypto:
  key: %s
masterdns:
  domains: [%s]
net:
  transport: dns
socks:
  host: "127.0.0.1"
  port: %d
`,
		strconv.Quote(p["encryption_key"]),
		strings.Join(quoted, ", "),
		opt.ChainSocksPort,
	)
	if method := p["encryption_method"]; method != "" {
		outer += fmt.Sprintf("  method: %s\n", method)
	}

	// The inner hop has no address of its own: it is reached through the
	// tunnel, which forwards to whatever the node chained it to. Loopback is
	// the honest placeholder - nothing on the client dials it directly.
	inner := subscription.Server{
		ID:        server.ID + ":chain",
		Name:      server.Name + " (inner)",
		Protocol:  server.Chain.Protocol,
		Transport: server.Chain.Transport,
		Address:   "127.0.0.1",
		Port:      1,
		Params:    map[string]string{},
	}
	for k, v := range server.Chain.Params {
		inner.Params[k] = v
	}
	inner.Params[paramChainPort] = strconv.Itoa(opt.ChainSocksPort)

	innerConfig, err := xrayConfig(inner, opt.SocksPort, "dns-tunnel")
	if err != nil {
		return nil, err
	}

	return &Profile{
		ID:     server.ID,
		Name:   server.Name,
		Kind:   KindWhiteNet,
		Config: outer,
		Inner: &Profile{
			ID:     inner.ID,
			Name:   inner.Name,
			Kind:   KindXray,
			Config: innerConfig,
		},
	}, nil
}

// --- flux -------------------------------------------------------------------

// fluxProfile builds the YAML for a flux server.
//
// A channel carries one client at a time, so a subscription normally gives the
// app a lease endpoint instead of a channel. Leasing is the app's job - it has
// to renew while it runs - so this takes the channel the app ended up with.
func fluxProfile(server subscription.Server, opt Options) (*Profile, error) {
	if server.Flux == nil || len(server.Flux.Channels) == 0 {
		return nil, fmt.Errorf("clientprofile: flux server %q carries no channel: "+
			"take a lease from flux.lease first and build the profile from what it returns",
			server.Name)
	}
	channel := server.Flux.Channels[0]
	if len(channel.Carriers) == 0 {
		return nil, fmt.Errorf("clientprofile: flux channel %q has no carrier", channel.ID)
	}
	if channel.Secret == "" {
		return nil, fmt.Errorf("clientprofile: flux channel %q has no secret", channel.ID)
	}

	// The carriers are tried in priority order, highest first, which is what
	// makes two carriers in one channel a failover pair.
	carrier := channel.Carriers[0]
	for _, candidate := range channel.Carriers[1:] {
		if candidate.Priority > carrier.Priority {
			carrier = candidate
		}
	}

	room := firstNonEmpty(carrier.URL, channel.Context, channel.ID)
	config := fmt.Sprintf(`mode: cnc
auth:
  provider: %s
room:
  id: %s
crypto:
  key: %s
net:
  transport: %s
socks:
  host: "127.0.0.1"
  port: %d
`,
		carrier.Type,
		strconv.Quote(room),
		strconv.Quote(channel.Secret),
		orDefault(carrier.Params["transport"], "data"),
		opt.SocksPort,
	)
	if dial := carrier.Params["dial"]; dial != "" {
		config += fmt.Sprintf("  dial: %s\n", strconv.Quote(dial))
	}

	return &Profile{
		ID:     server.ID,
		Name:   server.Name,
		Kind:   KindWhiteNet,
		Config: config,
	}, nil
}

// --- helpers ----------------------------------------------------------------

func compact(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if v == nil {
			continue
		}
		out[k] = v
	}
	return out
}

func splitList(raw string) []any {
	var out []any
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
