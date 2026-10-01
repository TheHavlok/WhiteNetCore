// Package subhttp serves subscriptions.
//
// One URL does two jobs. A browser gets the branded page - days left, traffic,
// a QR code, an "Open in WhiteNetVPN" button. The app gets JSON in WhiteNet's
// own format. Which one is decided by the request, not by a different path, so
// a user can paste the same link anywhere.
//
// The endpoint is unauthenticated apart from the token in the URL, which makes
// three things load-bearing: the token is long and random, the response is
// rate limited per address so the space cannot be walked, and the rendered
// document is cached briefly so a fleet of phones refreshing does not become a
// query storm.
package subhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/config"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/store"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// Headers the app sends. The device id is what the device limit counts, and
// the model is only for the admin's device list.
const (
	HeaderHWID       = "X-HWID"
	HeaderModel      = "X-Device-Model"
	HeaderPlatform   = "X-Platform"
	HeaderAppVersion = "X-App-Version"
)

// Server serves the subscription endpoints.
type Server struct {
	store *store.Store
	box   *secret.Box
	cfg   config.Config
	log   *slog.Logger

	limiter *limiter
	cache   *cache
}

// New returns a server.
func New(st *store.Store, box *secret.Box, cfg config.Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		store:   st,
		box:     box,
		cfg:     cfg,
		log:     log,
		limiter: newLimiter(),
		cache:   newCache(),
	}
}

// Routes returns the handler. It is mounted at the root of the subscription
// host, so the paths are the ones users see.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sub/{token}", s.handleSubscription)
	mux.HandleFunc("GET /sub/{token}/json", s.handleSubscriptionJSON)
	mux.HandleFunc("GET /sub/{token}/qr.png", s.handleQR)

	// Flux leases. A channel carries one client at a time, so the app asks
	// for one when it connects and renews while it uses it.
	mux.HandleFunc("POST /lease/{token}", s.handleAcquireLease)
	mux.HandleFunc("POST /lease/{token}/{leaseID}/renew", s.handleRenewLease)
	mux.HandleFunc("POST /lease/{token}/{leaseID}/release", s.handleReleaseLease)
	return mux
}

// handleSubscription answers a browser with the page and the app with JSON.
func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	if s.wantsJSON(r) {
		s.handleSubscriptionJSON(w, r)
		return
	}
	s.handlePage(w, r)
}

// wantsJSON decides whether the caller is the app.
//
// Three signals, in order of how much they prove: the device header the app
// always sends, an explicit Accept, and the user agent. A browser sends none
// of the first two and its user agent does not mention the app, so it gets the
// page.
func (s *Server) wantsJSON(r *http.Request) bool {
	if r.Header.Get(HeaderHWID) != "" {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return true
	}
	agent := strings.ToLower(r.UserAgent())
	for _, marker := range []string{"whitenet", "okhttp", "cfnetwork", "dart", "go-http-client"} {
		if strings.Contains(agent, marker) {
			return true
		}
	}
	return false
}

// handleSubscriptionJSON serves the document the app consumes.
func (s *Server) handleSubscriptionJSON(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	ip := s.clientIP(r)

	settings, err := s.store.SubscriptionSettings(r.Context())
	if err != nil {
		s.log.Error("could not read the subscription settings", "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.limiter.allow(ip, settings.RateLimitPerMinute) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	user, err := s.store.UserBySubToken(r.Context(), token)
	if err != nil {
		// The same answer whether the token never existed or was reissued, so
		// the endpoint does not confirm guesses.
		s.log.Warn("unknown subscription token", "ip", ip)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// The device ledger is checked before anything is rendered: a device past
	// the limit gets a clear refusal rather than a configuration it is not
	// entitled to.
	var deviceID *uint64
	if hwid := r.Header.Get(HeaderHWID); hwid != "" {
		device, err := s.store.SeenDevice(r.Context(), user.ID, hwid,
			r.Header.Get(HeaderModel), r.Header.Get(HeaderPlatform), r.Header.Get(HeaderAppVersion), ip)
		switch {
		case errors.Is(err, store.ErrDeviceLimit):
			s.writeJSON(w, http.StatusForbidden, map[string]any{
				"error": map[string]any{
					"code":    "device_limit",
					"message": fmt.Sprintf("this account allows %d devices", user.DevicesLimit),
				},
			})
			return
		case err != nil:
			s.log.Error("could not record a device", "user", user.ID, "error", err)
		default:
			deviceID = &device.ID
		}
	}

	// A cached document is reused briefly: every device refreshes on its own
	// schedule and the answer is the same for all of them.
	cacheKey := token
	if cached, ok := s.cache.get(cacheKey); ok {
		s.writeCached(w, cached)
		s.markFetched(r.Context(), user.ID)
		return
	}

	doc, err := s.render(r, user, deviceID)
	if err != nil {
		s.log.Error("could not render a subscription", "user", user.ID, "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		s.log.Error("could not serialise a subscription", "user", user.ID, "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if settings.CacheSeconds > 0 {
		s.cache.put(cacheKey, raw, time.Duration(settings.CacheSeconds)*time.Second)
	}

	s.writeCached(w, raw)
	s.markFetched(r.Context(), user.ID)
}

func (s *Server) writeCached(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The document carries the user's credentials, so no shared cache may
	// keep it.
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// markFetched records that the app collected a subscription, so the panel can
// show which users are actually using theirs. Best effort: it must not fail
// the request.
func (s *Server) markFetched(ctx context.Context, userID uint64) {
	if err := s.store.MarkSubFetched(ctx, userID); err != nil {
		s.log.Debug("could not record a subscription fetch", "user", userID, "error", err)
	}
}

// handleQR renders the import deep link as a PNG, for the page and for anyone
// who wants to put it on a screen.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !s.limiter.allow(s.clientIP(r), 60) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if _, err := s.store.UserBySubToken(r.Context(), token); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	subURL, err := s.subscriptionURL(r, token)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	link, err := sharelink.ImportLink(subURL)
	if err != nil {
		// Without https there is no deep link to encode; the plain URL still
		// scans and imports, so it is used instead.
		link = subURL
	}
	size := 320
	if v := r.URL.Query().Get("size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 120 && n <= 1024 {
			size = n
		}
	}
	png, err := sharelink.PNG(link, size)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=60")
	_, _ = w.Write(png)
}

// subscriptionURL rebuilds the user's own link, for the page and the QR code.
func (s *Server) subscriptionURL(r *http.Request, token string) (string, error) {
	domains, err := s.store.Domains(r.Context())
	if err != nil {
		return "", err
	}
	base := domains.SubBaseURL
	if base == "" {
		base = domains.PanelURL
	}
	if base == "" {
		base = requestBaseURL(r)
	}
	return strings.TrimRight(base, "/") + "/sub/" + token, nil
}

// ---------------------------------------------------------------------------
// Client address
// ---------------------------------------------------------------------------

func (s *Server) clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !s.trustedProxy(host) {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	first, _, _ := strings.Cut(forwarded, ",")
	first = strings.TrimSpace(first)
	if net.ParseIP(first) == nil {
		return host
	}
	return first
}

func (s *Server) trustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range s.cfg.HTTP.TrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Host
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = forwarded
	}
	return scheme + "://" + host
}

// ---------------------------------------------------------------------------
// Rate limiting and caching
// ---------------------------------------------------------------------------

// limiter is a per-address fixed-window counter. The token space is large, but
// without this an attacker could still try addresses in bulk, and a cheap
// counter makes that pointless.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*windowBucket
	swept   time.Time
}

type windowBucket struct {
	count int
	start time.Time
}

func newLimiter() *limiter {
	return &limiter{buckets: map[string]*windowBucket{}, swept: time.Now()}
}

func (l *limiter) allow(key string, perMinute int) bool {
	if perMinute <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.swept) > 10*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.start) > time.Minute {
				delete(l.buckets, k)
			}
		}
		l.swept = now
	}

	b, ok := l.buckets[key]
	if !ok || now.Sub(b.start) > time.Minute {
		l.buckets[key] = &windowBucket{count: 1, start: now}
		return true
	}
	if b.count >= perMinute {
		return false
	}
	b.count++
	return true
}

// cache holds rendered documents for a few seconds.
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	raw     []byte
	expires time.Time
}

func newCache() *cache { return &cache{entries: map[string]cacheEntry{}} }

func (c *cache) get(key string) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.raw, true
}

func (c *cache) put(key string, raw []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Drop whatever has expired while here, so the map does not grow with
	// every user who ever fetched.
	now := time.Now()
	for k, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = cacheEntry{raw: raw, expires: now.Add(ttl)}
}

// Invalidate drops a user's cached document, so a change in the panel shows up
// on the next fetch rather than after the cache lapses.
func (s *Server) Invalidate(token string) {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	delete(s.cache.entries, token)
}

// InvalidateAll drops every cached document, for a change that affects
// everyone - a node going offline, a template changing.
func (s *Server) InvalidateAll() {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	s.cache.entries = map[string]cacheEntry{}
}

// ensure the subscription package is referenced even if the render file moves.
var _ = subscription.Version
