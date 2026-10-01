package subhttp

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

//go:embed page.html
var pageFS embed.FS

// pageTemplate is parsed once: the page is served on every link anyone opens,
// and re-parsing it per request would be work for nothing.
var pageTemplate = template.Must(template.New("page.html").Funcs(template.FuncMap{
	"bytes":    humanBytes,
	"percent":  percent,
	"safeHTML": func(s string) template.HTML { return template.HTML(s) }, //nolint:gosec // only an admin sets this
}).ParseFS(pageFS, "page.html"))

// pageData is what the template renders.
type pageData struct {
	AppName      string
	LogoURL      string
	AccentColor  string
	Message      string
	SupportURL   string
	Instructions template.HTML

	UserName string
	Status   string
	// StatusLabel is the English phrase shown to the user, and StatusKind is
	// what the stylesheet colours by.
	StatusLabel string
	StatusKind  string

	HasExpiry     bool
	ExpiresAt     string
	DaysRemaining int

	HasTrafficLimit bool
	TrafficUsed     uint64
	TrafficLimit    uint64
	TrafficPercent  int

	DevicesUsed  int
	DevicesLimit int

	ServerCount int

	SubURL   string
	DeepLink string
	QRURL    string

	Downloads []download
}

type download struct {
	Label string
	URL   string
}

// handlePage serves the branded page a browser gets.
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !s.limiter.allow("page:"+s.clientIP(r), 60) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	user, err := s.store.UserBySubToken(r.Context(), token)
	if err != nil {
		// A plain 404, with no hint about whether the token ever existed.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(notFoundPage))
		return
	}

	branding, err := s.store.Branding(r.Context())
	if err != nil {
		s.log.Error("could not read the branding", "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	devices, err := s.store.UserDevices(r.Context(), user.ID)
	if err != nil {
		s.log.Error("could not read the devices", "user", user.ID, "error", err)
		devices = nil
	}
	nodes, err := s.store.NodesForUser(r.Context(), user.ID, true)
	if err != nil {
		s.log.Error("could not read the user's nodes", "user", user.ID, "error", err)
		nodes = nil
	}

	subURL, err := s.subscriptionURL(r, token)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	data := pageData{
		AppName:      orDefault(branding.AppName, "WhiteNetVPN"),
		LogoURL:      branding.LogoURL,
		AccentColor:  orDefault(branding.AccentColor, "#3b82f6"),
		Message:      branding.Message,
		SupportURL:   branding.SupportURL,
		Instructions: template.HTML(branding.InstructionsHTML), //nolint:gosec // only an admin sets this
		UserName:     user.Name,
		Status:       user.Status,
		DevicesUsed:  len(devices),
		DevicesLimit: int(user.DevicesLimit),
		ServerCount:  len(nodes),
		SubURL:       subURL,
		QRURL:        subURL + "/qr.png",
	}
	data.StatusLabel, data.StatusKind = statusWords(user)

	if user.ExpiresAt.Valid {
		data.HasExpiry = true
		data.ExpiresAt = user.ExpiresAt.Time.UTC().Format("2 January 2006")
		days := int(time.Until(user.ExpiresAt.Time).Hours() / 24)
		if days < 0 {
			days = 0
		}
		data.DaysRemaining = days
	}
	if user.TrafficLimit > 0 {
		data.HasTrafficLimit = true
		data.TrafficLimit = user.TrafficLimit
		data.TrafficPercent = percent(user.TrafficUsed, user.TrafficLimit)
	}
	data.TrafficUsed = user.TrafficUsed

	// The deep link needs https; without it the button is left out rather
	// than offering something that will not open.
	if deepLink, err := sharelink.ImportLink(subURL); err == nil {
		data.DeepLink = deepLink
	}

	for _, entry := range []download{
		{Label: "Android", URL: branding.AndroidURL},
		{Label: "iOS", URL: branding.IOSURL},
		{Label: "Windows", URL: branding.WindowsURL},
		{Label: "macOS", URL: branding.MacOSURL},
		{Label: "Linux", URL: branding.LinuxURL},
	} {
		if entry.URL != "" {
			data.Downloads = append(data.Downloads, entry)
		}
	}

	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		s.log.Error("could not render the subscription page", "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page shows the user's own data, so nothing in between may keep it.
	w.Header().Set("Cache-Control", "private, no-store")
	// The page loads no scripts and no third-party resources beyond the
	// configured logo, so the policy can be strict.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; img-src 'self' data: https:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// statusWords turns a status into something a user can act on.
func statusWords(user *store.User) (label, kind string) {
	switch user.Status {
	case store.UserActive:
		return "Active", "ok"
	case store.UserDisabled:
		return "Switched off — contact support", "bad"
	case store.UserExpired:
		return "Expired — renew to continue", "bad"
	case store.UserLimited:
		return "Data allowance used up", "warn"
	default:
		return strings.ToUpper(user.Status[:1]) + user.Status[1:], "warn"
	}
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KB", "MB", "GB", "TB", "PB"} {
		value /= unit
		if value < unit {
			if value < 10 {
				return fmt.Sprintf("%.2f %s", value, suffix)
			}
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f EB", value)
}

func percent(used, limit uint64) int {
	if limit == 0 {
		return 0
	}
	p := int(float64(used) / float64(limit) * 100)
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// notFoundPage is deliberately plain: it says nothing about whether the token
// ever existed.
const notFoundPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;
       font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:#0b0f14;color:#e6edf3}
  .box{text-align:center;padding:2rem}
  h1{font-size:1.25rem;margin:0 0 .5rem}
  p{margin:0;color:#8b949e}
</style></head>
<body><div class="box">
  <h1>This link is not valid</h1>
  <p>It may have been replaced. Ask for a new one.</p>
</div></body></html>`
