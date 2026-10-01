package xray

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// params is the flattened query of a share link: every key keeps only its
// first value, which is what these links use in practice.
type params map[string]string

func paramsOf(u *url.URL) params {
	out := make(params)
	for key, values := range u.Query() {
		if len(values) > 0 {
			out[key] = values[0]
		}
	}

	return out
}

func (p params) get(key, fallback string) string {
	if value, ok := p[key]; ok && value != "" {
		return value
	}

	return fallback
}

// streamSettings renders the transport and TLS half of an outbound.
//
// Every protocol funnels through here so Reality, WebSocket, gRPC and the
// rest behave identically no matter which link syntax they arrived in.
func streamSettings(q params, network, security string) map[string]any {
	if network == "" {
		network = "tcp"
	}
	if security == "" {
		security = "none"
	}

	settings := map[string]any{
		"network":  network,
		"security": security,
	}

	switch security {
	case "reality":
		// Публичный ключ сервера пишем сразу под двумя именами.
		//
		// В Xray до 25.x клиентское поле называлось publicKey, в свежих
		// версиях — password. Конфиг разбирается обычным encoding/json,
		// незнакомые ключи молча игнорируются, поэтому указать оба безопасно
		// и избавляет от привязки к версии ядра. Ошибка здесь не заметна на
		// глаз: туннель поднимается и молча не работает.
		publicKey := q.get("pbk", q.get("password", q.get("pwd", "")))

		settings["realitySettings"] = compact(map[string]any{
			"serverName":  q.get("sni", ""),
			"fingerprint": q.get("fp", "chrome"),
			"publicKey":   publicKey,
			"password":    publicKey,
			"shortId":     q.get("sid", ""),
			"spiderX":     q.get("spx", ""),
		})
	case "tls":
		tls := compact(map[string]any{
			"serverName":  q.get("sni", q.get("host", "")),
			"fingerprint": q.get("fp", "chrome"),
		})
		if alpn := q.get("alpn", ""); alpn != "" {
			tls["alpn"] = splitList(alpn)
		}
		if insecure := q.get("allowInsecure", ""); insecure == "1" || insecure == "true" {
			tls["allowInsecure"] = true
		}
		settings["tlsSettings"] = tls
	}

	switch network {
	case "ws":
		ws := map[string]any{"path": q.get("path", "/")}
		if host := q.get("host", ""); host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		settings["wsSettings"] = ws

	case "grpc":
		settings["grpcSettings"] = map[string]any{
			"serviceName": q.get("serviceName", q.get("path", "")),
		}

	case "httpupgrade":
		upgrade := map[string]any{"path": q.get("path", "/")}
		if host := q.get("host", ""); host != "" {
			upgrade["host"] = host
		}
		settings["httpupgradeSettings"] = upgrade

	case "http", "h2":
		settings["network"] = "http"
		httpSettings := map[string]any{"path": q.get("path", "/")}
		if host := q.get("host", ""); host != "" {
			httpSettings["host"] = splitList(host)
		}
		settings["httpSettings"] = httpSettings

	case "tcp":
		// Plain TCP carries no settings unless the link asks for the HTTP
		// camouflage header.
		if q.get("headerType", "") != "http" {
			break
		}
		request := map[string]any{"path": []any{q.get("path", "/")}}
		if host := q.get("host", ""); host != "" {
			request["headers"] = map[string]any{"Host": splitList(host)}
		}
		settings["tcpSettings"] = map[string]any{
			"header": map[string]any{
				"type":    "http",
				"request": request,
			},
		}
	}

	return settings
}

// --- small helpers ----------------------------------------------------------

// hostPort pulls the address out of a URL, defaulting the port.
func hostPort(u *url.URL, defaultPort int) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("%w: link has no host", ErrMalformedLink)
	}

	port := defaultPort
	if text := u.Port(); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return "", 0, fmt.Errorf("%w: port %q", ErrMalformedLink, text)
		}
		port = parsed
	}

	return host, port, nil
}

// displayName falls back to the address when the link carries no label.
func displayName(fragment, host string, port int) string {
	name := strings.TrimSpace(fragment)
	if name != "" {
		return name
	}

	return fmt.Sprintf("%s:%d", host, port)
}

// decodeBase64 accepts both the standard and URL alphabets, padded or not,
// because share links in the wild use all four combinations.
func decodeBase64(raw string) (string, error) {
	text := strings.TrimSpace(raw)
	text = strings.ReplaceAll(text, "-", "+")
	text = strings.ReplaceAll(text, "_", "/")

	if pad := len(text) % 4; pad != 0 {
		text += strings.Repeat("=", 4-pad)
	}

	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func stripQuery(raw string) string {
	if idx := strings.Index(raw, "?"); idx >= 0 {
		return raw[:idx]
	}

	return raw
}

func splitList(raw string) []any {
	parts := strings.Split(raw, ",")
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

// compact drops empty values so the generated config stays readable.
func compact(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		if text, ok := value.(string); ok && text == "" {
			continue
		}
		out[key] = value
	}

	return out
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

// asString coerces a vmess JSON field that may be a string or a number.
func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

// asInt does the same for ports and alterId, which arrive as either form.
func asInt(value any, fallback int) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			return parsed
		}
	}

	return fallback
}
