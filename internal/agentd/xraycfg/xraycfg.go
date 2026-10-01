// Package xraycfg renders an Xray configuration from a node's desired state.
//
// Every field name here was taken from xray-core's own JSON loader
// (infra/conf) in the pinned version, not from memory or a blog post: the
// names have changed more than once (tcp became raw, splithttp became xhttp,
// dest became target in REALITY) and a wrong one is a node that silently
// refuses to start.
//
// The generated configuration always contains the API inbound, the stats
// object and a policy that counts per-user traffic. Those are not optional
// extras - they are how the agent adds users without a restart and how the
// panel learns what anyone used.
package xraycfg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

// APITag is the tag shared by the api object, the inbound that carries API
// traffic and the routing rule for it. All three must use the same string:
// the api object registers an outbound handler under its own tag, so a
// routing rule pointing anywhere else sends the agent's gRPC calls into the
// tunnel, where they are answered by a connection reset.
const APITag = "wn-api"

// Options are the knobs that come from the agent rather than from the state.
type Options struct {
	// APIAddress is where Xray's gRPC API listens, host:port. It must stay
	// on the loopback interface: it can add users and read every counter.
	APIAddress string
	// LogLevel is debug, info, warning, error or none.
	LogLevel string
	// AccessLog and ErrorLog are file paths; empty means stdout/stderr,
	// which is what systemd wants.
	AccessLog string
	ErrorLog  string
	// DNSServers overrides Xray's outbound resolver. Empty uses the host's.
	DNSServers []string
}

// Generate renders the configuration for one node.
func Generate(state *nodepb.NodeState, opts Options) ([]byte, error) {
	cfg, err := Build(state, opts)
	if err != nil {
		return nil, err
	}
	// Indented, because this file is the first thing anyone looks at when a
	// node misbehaves.
	return json.MarshalIndent(cfg, "", "  ")
}

// Config is the top level of an Xray configuration.
type Config struct {
	Log       *logConfig     `json:"log,omitempty"`
	API       *apiConfig     `json:"api,omitempty"`
	Stats     *struct{}      `json:"stats,omitempty"`
	Policy    *policyConfig  `json:"policy,omitempty"`
	DNS       *dnsConfig     `json:"dns,omitempty"`
	Inbounds  []Inbound      `json:"inbounds"`
	Outbounds []Outbound     `json:"outbounds"`
	Routing   *routingConfig `json:"routing,omitempty"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
}

type apiConfig struct {
	Tag string `json:"tag"`
	// Services is what the agent needs: HandlerService to add and remove
	// users, StatsService to read counters.
	Services []string `json:"services"`
	Listen   string   `json:"listen,omitempty"`
}

type policyConfig struct {
	Levels map[string]policyLevel `json:"levels,omitempty"`
	System *policySystem          `json:"system,omitempty"`
}

type policyLevel struct {
	// These two are what make per-user counters exist at all. Without them
	// StatsService has nothing to report and every limit silently never
	// triggers.
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
	HandshakeTimeout  int  `json:"handshake,omitempty"`
	ConnIdleTimeout   int  `json:"connIdle,omitempty"`
}

type policySystem struct {
	StatsInboundUplink    bool `json:"statsInboundUplink"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
}

type dnsConfig struct {
	Servers []string `json:"servers,omitempty"`
}

// Inbound is one listening endpoint.
type Inbound struct {
	Tag            string          `json:"tag"`
	Listen         string          `json:"listen,omitempty"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings,omitempty"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
	Sniffing       *sniffing       `json:"sniffing,omitempty"`
}

type sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride,omitempty"`
	RouteOnly    bool     `json:"routeOnly,omitempty"`
}

// Outbound is where traffic leaves.
type Outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings any    `json:"settings,omitempty"`
}

type routingConfig struct {
	DomainStrategy string        `json:"domainStrategy,omitempty"`
	Rules          []routingRule `json:"rules"`
}

type routingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type streamSettings struct {
	Network  string `json:"network,omitempty"`
	Security string `json:"security,omitempty"`

	// FinalMask is where obfuscation lives in this version of Xray. The mKCP
	// header and seed, and Hysteria2's Salamander, all moved here from their
	// old homes, so the panel configures them through one mechanism.
	FinalMask *finalMask `json:"finalmask,omitempty"`

	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`

	RawSettings         *rawSettings         `json:"rawSettings,omitempty"`
	XHTTPSettings       *xhttpSettings       `json:"xhttpSettings,omitempty"`
	WSSettings          *wsSettings          `json:"wsSettings,omitempty"`
	GRPCSettings        *grpcSettings        `json:"grpcSettings,omitempty"`
	HTTPUpgradeSettings *httpUpgradeSettings `json:"httpupgradeSettings,omitempty"`
	KCPSettings         *kcpSettings         `json:"kcpSettings,omitempty"`
	HysteriaSettings    *hysteriaSettings    `json:"hysteriaSettings,omitempty"`
}

// finalMask holds the TCP and UDP mask chains. The order matters: masks are
// applied outward, so the last entry is what is on the wire.
type finalMask struct {
	TCP []mask `json:"tcp,omitempty"`
	UDP []mask `json:"udp,omitempty"`
}

type mask struct {
	Type     string `json:"type"`
	Settings any    `json:"settings,omitempty"`
}

// maskPassword is the settings shape of every mask that takes one
// (mkcp-aes128gcm, salamander).
type maskPassword struct {
	Password string `json:"password"`
}

type tlsSettings struct {
	ServerName    string        `json:"serverName,omitempty"`
	ALPN          []string      `json:"alpn,omitempty"`
	Certificates  []certificate `json:"certificates,omitempty"`
	MinVersion    string        `json:"minVersion,omitempty"`
	RejectUnknown bool          `json:"rejectUnknownSni,omitempty"`
	Fingerprint   string        `json:"fingerprint,omitempty"`
}

type certificate struct {
	// CertificateFile and KeyFile point at files on the node; Certificate
	// and Key carry the PEM inline. The agent writes inline material to
	// files, so only the file form reaches Xray in practice.
	CertificateFile string   `json:"certificateFile,omitempty"`
	KeyFile         string   `json:"keyFile,omitempty"`
	Certificate     []string `json:"certificate,omitempty"`
	Key             []string `json:"key,omitempty"`
	OCSPStapling    int      `json:"ocspStapling,omitempty"`
}

type realitySettings struct {
	Show bool `json:"show,omitempty"`
	// Target is what unmatched traffic is handed to. It used to be called
	// dest; both still load, and this is the current name.
	Target      string   `json:"target"`
	Xver        int      `json:"xver,omitempty"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
	MaxTimeDiff int      `json:"maxTimeDiff,omitempty"`
	// Mldsa65Seed is REALITY's post-quantum seed; set only when the panel
	// generated one.
	Mldsa65Seed string `json:"mldsa65Seed,omitempty"`
}

type rawSettings struct {
	// AcceptProxyProtocol matters when something terminates in front.
	AcceptProxyProtocol bool          `json:"acceptProxyProtocol,omitempty"`
	Header              *headerObject `json:"header,omitempty"`
}

type headerObject struct {
	Type string `json:"type"`
}

type xhttpSettings struct {
	Host    string            `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Mode    string            `json:"mode,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type wsSettings struct {
	Path                string            `json:"path,omitempty"`
	Host                string            `json:"host,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

type httpUpgradeSettings struct {
	Path                string            `json:"path,omitempty"`
	Host                string            `json:"host,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol,omitempty"`
}

type kcpSettings struct {
	MTU              int  `json:"mtu,omitempty"`
	TTI              int  `json:"tti,omitempty"`
	UplinkCapacity   int  `json:"uplinkCapacity,omitempty"`
	DownlinkCapacity int  `json:"downlinkCapacity,omitempty"`
	Congestion       bool `json:"congestion,omitempty"`
	ReadBufferSize   int  `json:"readBufferSize,omitempty"`
	WriteBufferSize  int  `json:"writeBufferSize,omitempty"`
}

type hysteriaSettings struct {
	Version int    `json:"version"`
	Auth    string `json:"auth,omitempty"`
	// Congestion, Up and Down are optional. Up and Down are Xray's Bandwidth
	// type, which is a string with a unit suffix ("100 mbps"), not a number
	// and not an object.
	Congestion     string `json:"congestion,omitempty"`
	Up             string `json:"up,omitempty"`
	Down           string `json:"down,omitempty"`
	UDPIdleTimeout int    `json:"udpIdleTimeout,omitempty"`
}

// Protocol-specific settings objects.

type vlessSettings struct {
	Clients    []vlessClient `json:"clients"`
	Decryption string        `json:"decryption"`
	Flow       string        `json:"flow,omitempty"`
}

type vlessClient struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Level int    `json:"level,omitempty"`
	Flow  string `json:"flow,omitempty"`
}

type vmessSettings struct {
	Clients []vmessClient `json:"clients"`
}

type vmessClient struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Level    int    `json:"level,omitempty"`
	Security string `json:"security,omitempty"`
}

type trojanSettings struct {
	Clients []trojanClient `json:"clients"`
}

type trojanClient struct {
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
	Level    int    `json:"level,omitempty"`
}

type shadowsocksSettings struct {
	// Method and Password at this level are the server key for a 2022
	// method; for a legacy method they are the single-user fallback.
	Method   string              `json:"method,omitempty"`
	Password string              `json:"password,omitempty"`
	Clients  []shadowsocksClient `json:"clients,omitempty"`
	Network  string              `json:"network,omitempty"`
}

type shadowsocksClient struct {
	Password string `json:"password"`
	Method   string `json:"method,omitempty"`
	Email    string `json:"email,omitempty"`
	Level    int    `json:"level,omitempty"`
}

type hysteriaProxySettings struct {
	Version int              `json:"version"`
	Clients []hysteriaClient `json:"clients"`
}

type hysteriaClient struct {
	Auth  string `json:"auth"`
	Email string `json:"email,omitempty"`
	Level int    `json:"level,omitempty"`
}

type dokodemoSettings struct {
	Address string   `json:"address"`
	Port    int      `json:"port,omitempty"`
	Network string   `json:"network,omitempty"`
	Follow  []string `json:"followRedirect,omitempty"`
}

type freedomSettings struct {
	DomainStrategy string `json:"domainStrategy,omitempty"`
}

// Build assembles the configuration without serialising it, so tests can
// inspect the structure instead of grepping JSON.
func Build(state *nodepb.NodeState, opts Options) (*Config, error) {
	if state == nil {
		return nil, fmt.Errorf("xraycfg: nil state")
	}
	apiHost, apiPort, err := splitAPIAddress(opts.APIAddress)
	if err != nil {
		return nil, err
	}

	logLevel := opts.LogLevel
	if logLevel == "" {
		logLevel = "warning"
	}

	cfg := &Config{
		Log: &logConfig{LogLevel: logLevel, Access: opts.AccessLog, Error: opts.ErrorLog},
		API: &apiConfig{
			Tag:      APITag,
			Services: []string{"HandlerService", "StatsService"},
		},
		Stats: &struct{}{},
		Policy: &policyConfig{
			// Level 0 is what every user gets. Counting uplink and downlink
			// there is what makes traffic accounting work at all.
			Levels: map[string]policyLevel{
				"0": {StatsUserUplink: true, StatsUserDownlink: true},
			},
			System: &policySystem{
				StatsInboundUplink:   true,
				StatsInboundDownlink: true,
			},
		},
		Outbounds: []Outbound{
			{Tag: "direct", Protocol: "freedom", Settings: freedomSettings{DomainStrategy: "UseIP"}},
			{Tag: "blocked", Protocol: "blackhole"},
		},
		Routing: &routingConfig{
			DomainStrategy: "AsIs",
			Rules: []routingRule{
				// API traffic must be answered by the api handler, not
				// proxied. Both tags are APITag on purpose.
				{Type: "field", InboundTag: []string{APITag}, OutboundTag: APITag},
			},
		},
	}
	if len(opts.DNSServers) > 0 {
		cfg.DNS = &dnsConfig{Servers: opts.DNSServers}
	}

	// The API inbound is a dokodemo-door on the loopback interface. Xray
	// answers gRPC on it because routing sends the tag to the api outbound.
	cfg.Inbounds = append(cfg.Inbounds, Inbound{
		Tag:      APITag,
		Listen:   apiHost,
		Port:     apiPort,
		Protocol: "dokodemo-door",
		Settings: dokodemoSettings{Address: apiHost},
	})

	// Stable order, so an unchanged state renders byte-identical output and
	// the agent can tell a real change from a map iteration.
	inbounds := append([]*nodepb.Inbound(nil), state.GetInbounds()...)
	sort.SliceStable(inbounds, func(i, j int) bool { return inbounds[i].GetTag() < inbounds[j].GetTag() })

	users := append([]*nodepb.User(nil), state.GetUsers()...)
	sort.SliceStable(users, func(i, j int) bool { return users[i].GetId() < users[j].GetId() })

	for _, inbound := range inbounds {
		if !inbound.GetEnabled() {
			continue
		}
		// Only Xray's own inbounds belong in this file. The DNS tunnel and
		// flux are different processes with their own configuration.
		if inbound.GetCore() != nodepb.Core_CORE_XRAY {
			continue
		}
		built, err := buildInbound(inbound, users)
		if err != nil {
			return nil, fmt.Errorf("xraycfg: inbound %s: %w", inbound.GetTag(), err)
		}
		cfg.Inbounds = append(cfg.Inbounds, built)
	}
	return cfg, nil
}

func splitAPIAddress(addr string) (host string, port int, err error) {
	if addr == "" {
		return "", 0, fmt.Errorf("xraycfg: api address is empty")
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return "", 0, fmt.Errorf("xraycfg: api address %q: %w", addr, splitErr)
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("xraycfg: api address %q has a bad port", addr)
	}
	// The API can add users and read every counter; exposing it is a full
	// compromise of the node, so refuse rather than warn.
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", 0, fmt.Errorf("xraycfg: api address %q must be on the loopback interface", addr)
	}
	return host, port, nil
}

func buildInbound(in *nodepb.Inbound, users []*nodepb.User) (Inbound, error) {
	params := in.GetParams()
	if params == nil {
		params = map[string]string{}
	}
	secrets := in.GetSecrets()
	if secrets == nil {
		secrets = map[string]string{}
	}

	out := Inbound{
		Tag:      in.GetTag(),
		Listen:   in.GetListenAddress(),
		Port:     int(in.GetListenPort()),
		Sniffing: buildSniffing(params),
	}
	if out.Port <= 0 || out.Port > 65535 {
		return out, fmt.Errorf("port %d is out of range", out.Port)
	}

	switch in.GetProtocol() {
	case nodepb.Protocol_PROTOCOL_VLESS:
		out.Protocol = "vless"
		clients := make([]vlessClient, 0, len(users))
		for _, u := range users {
			if u.GetVlessUuid() == "" {
				continue
			}
			flow := u.GetFlow()
			if flow == "" {
				flow = params["flow"]
			}
			clients = append(clients, vlessClient{ID: u.GetVlessUuid(), Email: u.GetEmail(), Flow: flow})
		}
		out.Settings = vlessSettings{
			Clients: clients,
			// Required by the loader. The panel does not use VLESS
			// Encryption yet; "none" is the plain path.
			Decryption: defaultString(params["decryption"], "none"),
			Flow:       params["flow"],
		}

	case nodepb.Protocol_PROTOCOL_VMESS:
		out.Protocol = "vmess"
		clients := make([]vmessClient, 0, len(users))
		for _, u := range users {
			if u.GetVlessUuid() == "" {
				continue
			}
			// VMess reuses the user's single UUID; one identity per user
			// across every protocol is what keeps a subscription stable.
			clients = append(clients, vmessClient{
				ID:       u.GetVlessUuid(),
				Email:    u.GetEmail(),
				Security: defaultString(params["security"], "auto"),
			})
		}
		out.Settings = vmessSettings{Clients: clients}

	case nodepb.Protocol_PROTOCOL_TROJAN:
		out.Protocol = "trojan"
		clients := make([]trojanClient, 0, len(users))
		for _, u := range users {
			if u.GetPassword() == "" {
				continue
			}
			clients = append(clients, trojanClient{Password: u.GetPassword(), Email: u.GetEmail()})
		}
		out.Settings = trojanSettings{Clients: clients}

	case nodepb.Protocol_PROTOCOL_SHADOWSOCKS:
		out.Protocol = "shadowsocks"
		method := params["method"]
		if method == "" {
			return out, fmt.Errorf("shadowsocks needs params.method")
		}
		if strings.HasPrefix(method, "2022-") {
			return out, fmt.Errorf("method %q is a 2022 method; use the shadowsocks2022 protocol", method)
		}
		clients := make([]shadowsocksClient, 0, len(users))
		for _, u := range users {
			if u.GetSsPassword() == "" {
				continue
			}
			clients = append(clients, shadowsocksClient{
				Password: u.GetSsPassword(),
				Method:   method,
				Email:    u.GetEmail(),
			})
		}
		if len(clients) == 0 {
			// An inbound built without a clients list is a single-user
			// server, and a single-user server is not a UserManager, so the
			// agent could never add the first user without a restart. A
			// placeholder client keeps it multi-user from the start; its
			// password is derived from the inbound's own secret and is never
			// handed to anyone.
			fallback := secrets["password"]
			if fallback == "" {
				return out, fmt.Errorf("shadowsocks has no users and no secrets.password to derive a placeholder from")
			}
			clients = append(clients, shadowsocksClient{
				Password: fallback,
				Method:   method,
				Email:    PlaceholderEmail,
			})
		}
		out.Settings = shadowsocksSettings{
			Clients: clients,
			Network: defaultString(params["network"], "tcp,udp"),
		}

	case nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022:
		out.Protocol = "shadowsocks"
		method := params["method"]
		if !strings.HasPrefix(method, "2022-") {
			return out, fmt.Errorf("shadowsocks2022 needs a 2022-* params.method, got %q", method)
		}
		// Multi-user 2022 only works with the blake3-aes methods; the
		// chacha one has no per-user key derivation.
		if len(users) > 0 && !strings.Contains(method, "aes") {
			return out, fmt.Errorf("method %q cannot serve several users; use a 2022-blake3-aes-*-gcm method", method)
		}
		serverKey := secrets["password"]
		if serverKey == "" {
			return out, fmt.Errorf("shadowsocks2022 needs secrets.password (the server key)")
		}
		settings := shadowsocksSettings{
			Method:   method,
			Password: serverKey,
			Network:  defaultString(params["network"], "tcp,udp"),
		}
		for _, u := range users {
			if u.GetSsPassword() == "" {
				continue
			}
			settings.Clients = append(settings.Clients, shadowsocksClient{
				Password: u.GetSsPassword(),
				Email:    u.GetEmail(),
			})
		}
		if len(settings.Clients) == 0 {
			// Same reason as the legacy case: without a clients list the
			// inbound is a single-user server and no user can be added at
			// runtime. The placeholder key is derived from the server key, so
			// it is deterministic and nobody has been given it.
			settings.Clients = append(settings.Clients, shadowsocksClient{
				Password: PlaceholderKey(serverKey, method),
				Email:    PlaceholderEmail,
			})
		}
		out.Settings = settings

	case nodepb.Protocol_PROTOCOL_HYSTERIA2:
		out.Protocol = "hysteria"
		clients := make([]hysteriaClient, 0, len(users))
		for _, u := range users {
			if u.GetPassword() == "" {
				continue
			}
			// Hysteria2 reuses the user's password, like Trojan.
			clients = append(clients, hysteriaClient{Auth: u.GetPassword(), Email: u.GetEmail()})
		}
		out.Settings = hysteriaProxySettings{Version: 2, Clients: clients}

	default:
		return out, fmt.Errorf("protocol %s is not served by xray-core", in.GetProtocol())
	}

	stream, err := buildStream(in, params, secrets)
	if err != nil {
		return out, err
	}
	out.StreamSettings = stream
	return out, nil
}

func buildSniffing(params map[string]string) *sniffing {
	if params["sniffing"] == "false" {
		return nil
	}
	// Sniffing on, route-only: the panel does not route by domain yet, but
	// having the destination in the access log is what makes an abuse report
	// answerable.
	return &sniffing{
		Enabled:      true,
		DestOverride: []string{"http", "tls", "quic"},
		RouteOnly:    true,
	}
}

func buildStream(in *nodepb.Inbound, params, secrets map[string]string) (*streamSettings, error) {
	network, err := normalizeNetwork(params["network"], in.GetProtocol())
	if err != nil {
		return nil, err
	}
	security := defaultString(params["security"], "none")

	stream := &streamSettings{Network: network, Security: security}

	switch network {
	case "raw":
		stream.RawSettings = &rawSettings{
			AcceptProxyProtocol: params["accept_proxy_protocol"] == "true",
		}
		if h := params["header"]; h != "" && h != "none" {
			stream.RawSettings.Header = &headerObject{Type: h}
		}
	case "xhttp":
		stream.XHTTPSettings = &xhttpSettings{
			Host: params["host"],
			Path: defaultString(params["path"], "/"),
			Mode: defaultString(params["mode"], "auto"),
		}
	case "websocket":
		stream.WSSettings = &wsSettings{
			Path:                defaultString(params["path"], "/"),
			Host:                params["host"],
			AcceptProxyProtocol: params["accept_proxy_protocol"] == "true",
		}
	case "httpupgrade":
		stream.HTTPUpgradeSettings = &httpUpgradeSettings{
			Path:                defaultString(params["path"], "/"),
			Host:                params["host"],
			AcceptProxyProtocol: params["accept_proxy_protocol"] == "true",
		}
	case "grpc":
		stream.GRPCSettings = &grpcSettings{
			ServiceName: params["service_name"],
			MultiMode:   params["multi_mode"] == "true",
		}
	case "mkcp":
		// header and seed used to live here; they are finalmask masks now,
		// which the panel sets through params.finalmask_udp.
		stream.KCPSettings = &kcpSettings{
			MTU:              atoiOr(params["mtu"], 1350),
			TTI:              atoiOr(params["tti"], 50),
			UplinkCapacity:   atoiOr(params["uplink_capacity"], 50),
			DownlinkCapacity: atoiOr(params["downlink_capacity"], 100),
			Congestion:       params["congestion"] == "true",
		}
	case "hysteria":
		hy := &hysteriaSettings{
			Version:        2,
			Auth:           secrets["auth"],
			Congestion:     params["congestion"],
			UDPIdleTimeout: atoiOr(params["udp_idle_timeout"], 0),
		}
		// Either the explicit Bandwidth string ("100 mbps", "2 gbps") or the
		// convenience form the panel's form uses.
		hy.Up = bandwidthValue(params["up"], params["up_mbps"])
		hy.Down = bandwidthValue(params["down"], params["down_mbps"])
		stream.HysteriaSettings = hy
	}

	switch security {
	case "none":
		// Hysteria2 is QUIC; without TLS there is nothing to run it over.
		if in.GetProtocol() == nodepb.Protocol_PROTOCOL_HYSTERIA2 {
			return nil, fmt.Errorf("hysteria2 requires tls")
		}
	case "tls":
		tls := &tlsSettings{
			ServerName:    params["sni"],
			MinVersion:    params["min_version"],
			RejectUnknown: params["reject_unknown_sni"] == "true",
		}
		if alpn := params["alpn"]; alpn != "" {
			tls.ALPN = splitList(alpn)
		}
		switch {
		case params["cert_file"] != "":
			tls.Certificates = []certificate{{
				CertificateFile: params["cert_file"],
				KeyFile:         params["key_file"],
				OCSPStapling:    atoiOr(params["ocsp_stapling"], 3600),
			}}
		case secrets["certificate"] != "":
			tls.Certificates = []certificate{{
				Certificate: strings.Split(strings.TrimRight(secrets["certificate"], "\n"), "\n"),
				Key:         strings.Split(strings.TrimRight(secrets["key"], "\n"), "\n"),
			}}
		default:
			return nil, fmt.Errorf("tls needs either params.cert_file or secrets.certificate")
		}
		stream.TLSSettings = tls

	case "reality":
		target := params["target"]
		if target == "" {
			target = params["dest"] // the old name, still accepted by the panel
		}
		if target == "" {
			return nil, fmt.Errorf("reality needs params.target")
		}
		serverNames := splitList(params["server_names"])
		if len(serverNames) == 0 {
			if sni := params["sni"]; sni != "" {
				serverNames = []string{sni}
			}
		}
		if len(serverNames) == 0 {
			return nil, fmt.Errorf("reality needs params.server_names")
		}
		shortIDs := splitList(params["short_ids"])
		if len(shortIDs) == 0 {
			// An empty short id is valid and means "any", but relying on it
			// by accident makes every client indistinguishable; be explicit.
			return nil, fmt.Errorf("reality needs params.short_ids")
		}
		if secrets["private_key"] == "" {
			return nil, fmt.Errorf("reality needs secrets.private_key")
		}
		stream.RealitySettings = &realitySettings{
			Show:        params["show"] == "true",
			Target:      target,
			Xver:        atoiOr(params["xver"], 0),
			ServerNames: serverNames,
			PrivateKey:  secrets["private_key"],
			ShortIds:    shortIDs,
			MaxTimeDiff: atoiOr(params["max_time_diff"], 0),
			Mldsa65Seed: secrets["mldsa65_seed"],
		}

	default:
		return nil, fmt.Errorf("unknown security %q (want none, tls or reality)", security)
	}

	fm, err := buildFinalMask(params, secrets)
	if err != nil {
		return nil, err
	}
	stream.FinalMask = fm

	return stream, nil
}

// maskNeedsPassword lists the masks whose settings carry a secret. Everything
// else takes no settings at all, and sending an empty object for them is
// accepted but pointless.
var maskNeedsPassword = map[string]bool{
	"mkcp-aes128gcm": true,
	"salamander":     true,
}

// knownUDPMasks and knownTCPMasks are what this version of xray-core
// registers. Validating here turns a typo in the panel into a clear error
// instead of an inbound that fails to build on the node.
var (
	knownUDPMasks = map[string]bool{
		"header-custom": true, "header-dns": true, "header-dtls": true,
		"header-srtp": true, "header-utp": true, "header-wechat": true,
		"header-wireguard": true, "mkcp-original": true, "mkcp-aes128gcm": true,
		"noise": true, "salamander": true,
	}
	knownTCPMasks = map[string]bool{
		"header-custom": true, "fragment": true, "sudoku": true,
	}
)

// buildFinalMask reads params.finalmask_tcp and params.finalmask_udp, each a
// comma-separated list of mask types. A mask that needs a password takes it
// from secrets under "<type>_password", or from secrets.obfs_password for
// salamander, which is what the panel's Hysteria2 form calls it.
func buildFinalMask(params, secrets map[string]string) (*finalMask, error) {
	tcp, err := buildMasks(splitList(params["finalmask_tcp"]), knownTCPMasks, "tcp", secrets)
	if err != nil {
		return nil, err
	}
	udp, err := buildMasks(splitList(params["finalmask_udp"]), knownUDPMasks, "udp", secrets)
	if err != nil {
		return nil, err
	}
	if len(tcp) == 0 && len(udp) == 0 {
		return nil, nil
	}
	return &finalMask{TCP: tcp, UDP: udp}, nil
}

func buildMasks(types []string, known map[string]bool, side string, secrets map[string]string) ([]mask, error) {
	if len(types) == 0 {
		return nil, nil
	}
	out := make([]mask, 0, len(types))
	for _, maskType := range types {
		if !known[maskType] {
			return nil, fmt.Errorf("unknown %s finalmask %q", side, maskType)
		}
		m := mask{Type: maskType}
		if maskNeedsPassword[maskType] {
			password := secrets[maskType+"_password"]
			if password == "" && maskType == "salamander" {
				password = secrets["obfs_password"]
			}
			if password == "" {
				return nil, fmt.Errorf("finalmask %s needs secrets.%s_password", maskType, maskType)
			}
			m.Settings = maskPassword{Password: password}
		}
		out = append(out, m)
	}
	return out, nil
}

// normalizeNetwork maps the panel's spelling to what xray-core's loader
// expects. The panel stores the friendly names; the loader wants raw, xhttp,
// websocket, httpupgrade, grpc, mkcp or hysteria.
func normalizeNetwork(network string, protocol nodepb.Protocol) (string, error) {
	if network == "" {
		if protocol == nodepb.Protocol_PROTOCOL_HYSTERIA2 {
			return "hysteria", nil
		}
		return "raw", nil
	}
	switch network {
	case "raw", "tcp":
		return "raw", nil
	case "xhttp", "splithttp":
		return "xhttp", nil
	case "ws", "websocket":
		return "websocket", nil
	case "httpupgrade":
		return "httpupgrade", nil
	case "grpc":
		return "grpc", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "hysteria":
		return "hysteria", nil
	default:
		return "", fmt.Errorf("unknown network %q", network)
	}
}

// PlaceholderEmail is the email of the reserved client that keeps a
// Shadowsocks inbound in multi-user mode when the node has no users yet. The
// agent ignores counters for it, and the panel never shows it.
const PlaceholderEmail = "reserved.placeholder@whitenet"

// PlaceholderKey derives the reserved client's key from the inbound's server
// key. Deterministic, so re-rendering an unchanged state does not produce a
// different configuration, and distinct from the server key, so holding the
// server key alone is not enough to connect as the placeholder.
func PlaceholderKey(serverKey, method string) string {
	sum := sha256.Sum256([]byte("whitenet-placeholder\x00" + method + "\x00" + serverKey))
	size := 32
	if strings.Contains(method, "128") {
		size = 16
	}
	return base64.StdEncoding.EncodeToString(sum[:size])
}

// UserEmail is the key Xray reports traffic under. It has to be unique per
// user and stable for the user's lifetime, because the counters are keyed by
// it and renaming one loses that user's history.
func UserEmail(userID uint64, uuid string) string {
	prefix := uuid
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return fmt.Sprintf("%d.%s@whitenet", userID, prefix)
}

// UserIDFromEmail recovers the user id from an email produced by UserEmail.
// The agent uses it to turn Xray's counters back into user ids.
func UserIDFromEmail(email string) (uint64, bool) {
	idPart, _, found := strings.Cut(email, ".")
	if !found {
		return 0, false
	}
	id, err := strconv.ParseUint(idPart, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// bandwidthValue prefers an explicit Bandwidth string and otherwise turns a
// plain megabit number into one.
func bandwidthValue(explicit, mbps string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if n := atoiOr(mbps, 0); n > 0 {
		return strconv.Itoa(n) + " mbps"
	}
	return ""
}

func atoiOr(v string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return n
}

// splitList parses a comma-separated parameter, which is how a list travels
// through the flat string map.
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
