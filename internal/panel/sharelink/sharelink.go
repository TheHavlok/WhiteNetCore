// Package sharelink encodes and decodes whitenet:// links: one or more
// servers, packed into something a person can paste into a chat or scan off
// another phone's screen.
//
// Two link shapes exist, and they are for different jobs:
//
//	whitenet://v1/<payload>            a server bundle, self-contained
//	whitenetvpn://import?url=<sub>     a subscription, fetched and refreshed
//
// Prefer the subscription link for a real user: it updates on its own, it
// enforces limits, and it can be revoked by reissuing the token. A share link
// is a snapshot - handy for a test server, a one-off, or handing one node to
// someone - and whoever holds it has the credentials in it until they change.
//
// The encoding follows OpenFlux's: DEFLATE the JSON, then base64url without
// padding. It is compact enough for a QR code, and decoding is deliberately
// forgiving about what copying through a terminal or a chat app does to a
// link.
package sharelink

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// Prefix starts every server-bundle link. The path segment is the payload
// version, so a future format can be told apart instead of guessed at.
const Prefix = "whitenet://v1/"

// ImportScheme is the deep link the app registers for subscriptions.
const ImportScheme = "whitenetvpn"

// maxPayload bounds the decompressed JSON so a crafted link cannot make the
// decoder allocate without limit.
const maxPayload = 256 << 10

// Error codes. They are the contract with the app: the app words each one for
// its user, this package only decides which it is.
const (
	CodeNotLink            = "not_link"
	CodeUnsupportedVersion = "unsupported_version"
	CodeCaseChanged        = "case_changed"
	CodeDamaged            = "damaged"
	CodeTooLarge           = "too_large"
	CodeBadPayload         = "bad_payload"
	CodeNoServers          = "no_servers"
	CodeBadServer          = "bad_server"
	CodeNoURL              = "no_url"
	CodeNotHTTPS           = "not_https"
)

// Error is a link that cannot be used.
type Error struct {
	Code  string
	Param string
	text  string
	cause error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return e.text + ": " + e.cause.Error()
	}
	return e.text
}

func (e *Error) Unwrap() error { return e.cause }

func linkError(code, param, text string, cause error) error {
	return &Error{Code: code, Param: param, text: text, cause: cause}
}

// Bundle is what a whitenet:// link carries.
type Bundle struct {
	// Name is a suggested profile name in the app.
	Name string `json:"name,omitempty"`
	// Servers is the point of the link.
	Servers []subscription.Server `json:"servers"`
	// Sub is an optional subscription URL. When present the app should
	// import the servers to connect right away and then switch to the
	// subscription, which is how a link can be both instant and
	// self-updating.
	Sub string `json:"sub,omitempty"`
	// Branding travels with the link so a shared server still looks right.
	Branding *subscription.Branding `json:"branding,omitempty"`
}

// Validate reports whether b describes something the app can connect with.
func (b Bundle) Validate() error {
	if len(b.Servers) == 0 {
		return linkError(CodeNoServers, "", "sharelink: no servers in the link", nil)
	}
	seen := map[string]bool{}
	for i, server := range b.Servers {
		if err := server.Validate(); err != nil {
			return linkError(CodeBadServer, server.ID,
				fmt.Sprintf("sharelink: server %d (%s)", i, server.Name), err)
		}
		if seen[server.ID] {
			return linkError(CodeBadServer, server.ID, "sharelink: duplicate server id "+server.ID, nil)
		}
		seen[server.ID] = true
	}
	if b.Sub != "" {
		if err := checkSubURL(b.Sub); err != nil {
			return err
		}
	}
	return nil
}

// Encode validates b and returns its whitenet:// link.
func Encode(b Bundle) (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("sharelink: marshal: %w", err)
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("sharelink: deflate: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return "", fmt.Errorf("sharelink: deflate: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("sharelink: deflate: %w", err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// EncodeServer is Encode for the common case of sharing one server.
func EncodeServer(name string, server subscription.Server) (string, error) {
	return Encode(Bundle{Name: name, Servers: []subscription.Server{server}})
}

// Decode parses and validates a whitenet:// link.
//
// It is forgiving in the ways a link actually gets damaged in transit:
// surrounding and embedded whitespace (a link wraps when copied out of a
// terminal or a chat), base64 padding that some encoders add, and the standard
// base64 alphabet where this one uses the URL alphabet. A link Encode wrote
// has none of those.
func Decode(link string) (Bundle, error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, Prefix) {
		lower := strings.ToLower(link)
		switch {
		case strings.HasPrefix(lower, "whitenet://") && !strings.HasPrefix(link, "whitenet://"):
			// Some chat clients and mail readers lowercase or capitalise a
			// URL. The payload is case-sensitive base64url, so it is gone.
			return Bundle{}, linkError(CodeCaseChanged, "",
				"sharelink: the link's letters changed case on the way (whitenet:// links are case-sensitive); copy it again", nil)
		case strings.HasPrefix(link, "whitenet://"):
			return Bundle{}, linkError(CodeUnsupportedVersion, "",
				"sharelink: unsupported link version; update the app", nil)
		}
		return Bundle{}, linkError(CodeNotLink, "", "sharelink: not a whitenet:// link", nil)
	}

	body := normalizeBody(strings.TrimPrefix(link, Prefix))
	packed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Bundle{}, linkError(CodeDamaged, "",
			fmt.Sprintf("sharelink: bad link encoding (%d characters after the prefix; truncated or mangled?)", len(body)), err)
	}
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(packed)), maxPayload+1))
	if err != nil {
		return Bundle{}, linkError(CodeDamaged, "",
			"sharelink: bad link payload (not raw DEFLATE; truncated?)", err)
	}
	if len(raw) > maxPayload {
		return Bundle{}, linkError(CodeTooLarge, "", "sharelink: link payload too large", nil)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, linkError(CodeBadPayload, "", "sharelink: bad link payload", err)
	}
	if err := b.Validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// normalizeBody undoes what copying and other encoders do to a base64url
// payload.
func normalizeBody(b string) string {
	b = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', ' ', '​':
			return -1
		case '+':
			return '-'
		case '/':
			return '_'
		}
		return r
	}, b)
	return strings.TrimRight(b, "=")
}

// ImportLink builds the deep link that hands a subscription URL to the app:
//
//	whitenetvpn://import?url=https%3A%2F%2Fsub.example%2Fsub%2FTOKEN
//
// The subscription URL is percent-encoded in a query parameter, so a token
// containing characters that mean something in a URL cannot break the link.
func ImportLink(subURL string) (string, error) {
	if err := checkSubURL(subURL); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("url", subURL)
	return ImportScheme + "://import?" + q.Encode(), nil
}

// ParseImportLink extracts the subscription URL from an import deep link.
func ParseImportLink(link string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", linkError(CodeNotLink, "", "sharelink: not a link", err)
	}
	if !strings.EqualFold(parsed.Scheme, ImportScheme) {
		return "", linkError(CodeNotLink, parsed.Scheme,
			"sharelink: not a "+ImportScheme+":// link", nil)
	}
	// The host is "import" for whitenetvpn://import?... and empty for
	// whitenetvpn:///import?...; accept both rather than making the app's
	// URL building exact.
	action := parsed.Host
	if action == "" {
		action = strings.TrimPrefix(parsed.Path, "/")
	}
	if !strings.EqualFold(action, "import") {
		return "", linkError(CodeNotLink, action, "sharelink: unknown action "+action, nil)
	}
	subURL := parsed.Query().Get("url")
	if subURL == "" {
		return "", linkError(CodeNoURL, "", "sharelink: import link has no url parameter", nil)
	}
	if err := checkSubURL(subURL); err != nil {
		return "", err
	}
	return subURL, nil
}

// checkSubURL insists on https. A subscription carries every credential the
// user has; over http it is readable by anyone on the path, and the app has no
// way to warn about it after the fact.
func checkSubURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return linkError(CodeNoURL, raw, "sharelink: bad subscription url", err)
	}
	if parsed.Host == "" {
		return linkError(CodeNoURL, raw, "sharelink: subscription url has no host", nil)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return linkError(CodeNotHTTPS, parsed.Scheme,
			"sharelink: a subscription url must be https (it carries every credential the user has)", nil)
	}
	return nil
}

// ErrorCode returns the code of a sharelink error, or "" for anything else.
// The HTTP layer uses it to answer with a machine-readable reason.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// QR rendering. A link is meant to be scanned off a screen, so the panel, the
// subscription page and the CLI all need the same code with the same error
// correction level.

// qr builds the code at medium correction: it survives a slightly glared
// phone screen while staying small enough to scan off another phone.
func qr(link string) (*qrcode.QRCode, error) {
	code, err := qrcode.New(link, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("sharelink: qr: %w", err)
	}
	return code, nil
}

// PNG renders link as a size x size PNG.
func PNG(link string, size int) ([]byte, error) {
	code, err := qr(link)
	if err != nil {
		return nil, err
	}
	return code.PNG(size)
}

// Bitmap returns the code as rows of dark (true) modules, including the quiet
// zone, for a caller that renders it itself.
func Bitmap(link string) ([][]bool, error) {
	code, err := qr(link)
	if err != nil {
		return nil, err
	}
	return code.Bitmap(), nil
}

// Terminal renders the code with half-block characters, for a terminal or a
// service log.
func Terminal(link string) (string, error) {
	code, err := qr(link)
	if err != nil {
		return "", err
	}
	bitmap := code.Bitmap()
	var b strings.Builder
	// Two rows per character cell, so the code comes out roughly square in a
	// terminal where cells are about twice as tall as they are wide.
	for y := 0; y < len(bitmap); y += 2 {
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x]
			}
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
