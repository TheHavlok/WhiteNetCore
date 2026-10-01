package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ShareLink is one parsed subscription link plus the Xray configuration built
// from it. The apps show Name/Protocol/Address in the profile list and store
// ConfigJSON exactly where they used to store the WhiteNet YAML.
type ShareLink struct {
	Name       string
	Protocol   string
	Address    string
	Security   string
	Transport  string
	ConfigJSON string
}

var (
	// ErrUnsupportedLink is returned for a scheme this package cannot parse.
	ErrUnsupportedLink = errors.New("xray: unsupported share link")
	// ErrMalformedLink is returned when the scheme is known but the body is not usable.
	ErrMalformedLink = errors.New("xray: malformed share link")
)

// DefaultSocksPort is the port written into a freshly parsed configuration.
// Start overrides it, so it only matters when a user reads the config.
const DefaultSocksPort = 10808

const (
	proxyTag        = "proxy"
	socksInboundTag = "socks-in"
)

var supportedSchemes = []string{"vless://", "vmess://", "trojan://", "ss://"}

// IsShareLink reports whether raw looks like something ParseShareLink handles.
func IsShareLink(raw string) bool {
	raw = strings.TrimSpace(raw)
	for _, scheme := range supportedSchemes {
		if strings.HasPrefix(raw, scheme) {
			return true
		}
	}

	return false
}

// ParseShareLink converts one share link into a complete Xray configuration.
func ParseShareLink(raw string) (*ShareLink, error) {
	raw = strings.TrimSpace(raw)

	var (
		link     *ShareLink
		outbound map[string]any
		err      error
	)

	switch {
	case strings.HasPrefix(raw, "vless://"):
		link, outbound, err = parseVLESS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		link, outbound, err = parseVMess(raw)
	case strings.HasPrefix(raw, "trojan://"):
		link, outbound, err = parseTrojan(raw)
	case strings.HasPrefix(raw, "ss://"):
		link, outbound, err = parseShadowsocks(raw)
	default:
		return nil, ErrUnsupportedLink
	}

	if err != nil {
		return nil, err
	}

	outbound["tag"] = proxyTag

	encoded, err := json.MarshalIndent(BuildConfig(outbound, DefaultSocksPort), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("xray: encode config: %w", err)
	}

	link.ConfigJSON = string(encoded)

	return link, nil
}

// BuildConfig wraps one outbound into a full client configuration.
//
// The inbound is always ours: the app is a tunnel, not a proxy server, and
// tun2socks has to know exactly which port to dial. Sniffing is on so Xray can
// recover the real hostname from the TLS ClientHello - by the time traffic
// reaches here the destination is already an IP, and Reality needs the name.
func BuildConfig(outbound map[string]any, socksPort int) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			SocksInbound(socksPort),
		},
		"outbounds": []any{
			outbound,
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
	}
}

// SocksInbound is the single local inbound every configuration gets.
func SocksInbound(port int) map[string]any {
	return map[string]any{
		"tag":      socksInboundTag,
		"protocol": "socks",
		"listen":   "127.0.0.1",
		"port":     port,
		"settings": map[string]any{
			"auth": "noauth",
			"udp":  true,
			"ip":   "127.0.0.1",
		},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []any{"http", "tls", "quic"},
		},
	}
}

// --- Per-protocol parsing ---------------------------------------------------

func parseVLESS(raw string) (*ShareLink, map[string]any, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformedLink, err)
	}

	host, port, err := hostPort(parsed, 443)
	if err != nil {
		return nil, nil, err
	}

	uuid := ""
	if parsed.User != nil {
		uuid = parsed.User.Username()
	}
	if uuid == "" {
		return nil, nil, fmt.Errorf("%w: vless link has no id", ErrMalformedLink)
	}

	q := paramsOf(parsed)

	user := map[string]any{
		"id":         uuid,
		"encryption": q.get("encryption", "none"),
	}
	if flow := q.get("flow", ""); flow != "" {
		user["flow"] = flow
	}

	network := q.get("type", "tcp")
	security := q.get("security", "none")

	outbound := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": host,
					"port":    port,
					"users":   []any{user},
				},
			},
		},
		"streamSettings": streamSettings(q, network, security),
	}

	return &ShareLink{
		Name:      displayName(parsed.Fragment, host, port),
		Protocol:  "vless",
		Address:   net.JoinHostPort(host, strconv.Itoa(port)),
		Security:  security,
		Transport: network,
	}, outbound, nil
}

func parseVMess(raw string) (*ShareLink, map[string]any, error) {
	decoded, err := decodeBase64(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: vmess body is not base64: %w", ErrMalformedLink, err)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(decoded), &body); err != nil {
		return nil, nil, fmt.Errorf("%w: vmess body is not JSON: %w", ErrMalformedLink, err)
	}

	host := asString(body["add"])
	port := asInt(body["port"], 443)
	if host == "" {
		return nil, nil, fmt.Errorf("%w: vmess link has no address", ErrMalformedLink)
	}

	network := valueOr(asString(body["net"]), "tcp")

	security := "none"
	if tls := asString(body["tls"]); tls == "tls" || tls == "reality" {
		security = tls
	}

	// vmess:// packs stream options into flat JSON keys; map them onto the
	// same names the URL-based links use so streamSettings stays single-source.
	q := params{
		"sni":         asString(body["sni"]),
		"host":        asString(body["host"]),
		"path":        valueOr(asString(body["path"]), "/"),
		"fp":          asString(body["fp"]),
		"alpn":        asString(body["alpn"]),
		"headerType":  asString(body["type"]),
		"serviceName": asString(body["path"]),
	}

	user := map[string]any{
		"id":       asString(body["id"]),
		"alterId":  asInt(body["aid"], 0),
		"security": valueOr(asString(body["scy"]), "auto"),
	}

	outbound := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": host,
					"port":    port,
					"users":   []any{user},
				},
			},
		},
		"streamSettings": streamSettings(q, network, security),
	}

	return &ShareLink{
		Name:      displayName(asString(body["ps"]), host, port),
		Protocol:  "vmess",
		Address:   net.JoinHostPort(host, strconv.Itoa(port)),
		Security:  security,
		Transport: network,
	}, outbound, nil
}

func parseTrojan(raw string) (*ShareLink, map[string]any, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformedLink, err)
	}

	host, port, err := hostPort(parsed, 443)
	if err != nil {
		return nil, nil, err
	}

	password := ""
	if parsed.User != nil {
		password = parsed.User.Username()
	}
	if password == "" {
		return nil, nil, fmt.Errorf("%w: trojan link has no password", ErrMalformedLink)
	}

	q := paramsOf(parsed)
	network := q.get("type", "tcp")
	security := q.get("security", "tls")

	outbound := map[string]any{
		"protocol": "trojan",
		"settings": map[string]any{
			"servers": []any{
				map[string]any{
					"address":  host,
					"port":     port,
					"password": password,
				},
			},
		},
		"streamSettings": streamSettings(q, network, security),
	}

	return &ShareLink{
		Name:      displayName(parsed.Fragment, host, port),
		Protocol:  "trojan",
		Address:   net.JoinHostPort(host, strconv.Itoa(port)),
		Security:  security,
		Transport: network,
	}, outbound, nil
}

// parseShadowsocks handles both the legacy fully-base64 form and SIP002.
func parseShadowsocks(raw string) (*ShareLink, map[string]any, error) {
	body := strings.TrimPrefix(raw, "ss://")

	fragment := ""
	if idx := strings.Index(body, "#"); idx >= 0 {
		fragment = body[idx+1:]
		body = body[:idx]
	}
	if unescaped, err := url.QueryUnescape(fragment); err == nil {
		fragment = unescaped
	}

	var userInfo, hostPart string

	if idx := strings.LastIndex(body, "@"); idx >= 0 {
		// SIP002: ss://base64(method:password)@host:port
		userInfo, hostPart = body[:idx], body[idx+1:]
		if !strings.Contains(userInfo, ":") {
			decoded, err := decodeBase64(userInfo)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: ss userinfo is not base64: %w", ErrMalformedLink, err)
			}
			userInfo = decoded
		}
	} else {
		// Legacy: ss://base64(method:password@host:port)
		decoded, err := decodeBase64(stripQuery(body))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: ss body is not base64: %w", ErrMalformedLink, err)
		}
		idx := strings.LastIndex(decoded, "@")
		if idx < 0 {
			return nil, nil, fmt.Errorf("%w: ss body has no host", ErrMalformedLink)
		}
		userInfo, hostPart = decoded[:idx], decoded[idx+1:]
	}

	hostPart = stripQuery(hostPart)

	method, password, found := strings.Cut(userInfo, ":")
	if !found {
		return nil, nil, fmt.Errorf("%w: ss userinfo has no password", ErrMalformedLink)
	}

	host, portText, err := net.SplitHostPort(hostPart)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ss address %q: %w", ErrMalformedLink, hostPart, err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ss port %q", ErrMalformedLink, portText)
	}

	outbound := map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []any{
				map[string]any{
					"address":  host,
					"port":     port,
					"method":   method,
					"password": password,
				},
			},
		},
	}

	return &ShareLink{
		Name:      displayName(fragment, host, port),
		Protocol:  "shadowsocks",
		Address:   net.JoinHostPort(host, strconv.Itoa(port)),
		Security:  "none",
		Transport: "tcp",
	}, outbound, nil
}
