// Package api is the panel's REST interface: everything the admin UI does
// goes through it, and it is the only way into the panel apart from the
// subscription endpoint and the agent's gRPC port.
//
// Responses are JSON. Errors are a single shape, {"error": {...}}, with a
// machine-readable code, because the UI has to show something sensible for
// each one and parsing prose is not a plan.
package api

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

	"github.com/thehavlok/whitenet/internal/panel/auth"
	"github.com/thehavlok/whitenet/internal/panel/config"
	"github.com/thehavlok/whitenet/internal/panel/noderpc"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/staterender"
	"github.com/thehavlok/whitenet/internal/panel/store"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// SessionCookie is the name of the admin session cookie.
const SessionCookie = "wn_session"

// SessionTTL is how long an admin session lasts.
const SessionTTL = 7 * 24 * time.Hour

// Login protection. The lock is on the account rather than the address,
// because an attacker has many addresses and one username to guess at.
const (
	loginFailureThreshold = 8
	loginLockDuration     = 15 * time.Minute
)

// SubscriptionRenderer renders what a user would be served. The admin API
// needs it to show the same servers the app will see - and a share link for
// each - without duplicating the rendering rules, which is where the panel and
// the app would otherwise drift apart. It is an interface so the API package
// does not depend on the subscription server, and so tests can leave it out.
type SubscriptionRenderer interface {
	Render(r *http.Request, user *store.User) (*subscription.Response, error)
}

// Server holds everything the handlers need.
type Server struct {
	store    *store.Store
	box      *secret.Box
	rpc      *noderpc.Server
	renderer *staterender.Renderer
	sub      SubscriptionRenderer
	cfg      config.Config
	log      *slog.Logger

	// loginLimiter bounds login attempts per client address, on top of the
	// per-account lock, so a password-spraying run over many usernames is
	// also slowed.
	loginLimiter *rateLimiter
}

// New returns a server.
func New(st *store.Store, box *secret.Box, rpc *noderpc.Server, renderer *staterender.Renderer, cfg config.Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		store:        st,
		box:          box,
		rpc:          rpc,
		renderer:     renderer,
		cfg:          cfg,
		log:          log,
		loginLimiter: newRateLimiter(20, time.Minute),
	}
}

// SetSubscriptionRenderer wires in the renderer after construction, because
// the subscription server and the API server are built from the same store and
// neither can be the other's constructor argument without an ordering rule
// that is easy to get wrong.
func (s *Server) SetSubscriptionRenderer(renderer SubscriptionRenderer) {
	s.sub = renderer
}

// Routes returns the API handler, to be mounted under /api.
//
// Patterns use Go's method-aware mux, so a wrong method answers 405 rather
// than falling through to a handler that then has to check.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: the login flow and the health check.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/setup", s.handleSetupNeeded)
	mux.HandleFunc("POST /auth/setup", s.handleSetup)

	// Everything else needs a session.
	authed := http.NewServeMux()

	authed.HandleFunc("GET /auth/me", s.handleMe)
	authed.HandleFunc("POST /auth/password", s.handleChangePassword)
	authed.HandleFunc("POST /auth/totp/start", s.handleTOTPStart)
	authed.HandleFunc("POST /auth/totp/confirm", s.handleTOTPConfirm)
	authed.HandleFunc("POST /auth/totp/disable", s.handleTOTPDisable)
	authed.HandleFunc("GET /auth/sessions", s.handleListSessions)

	authed.HandleFunc("GET /dashboard", s.handleDashboard)

	authed.HandleFunc("GET /nodes", s.handleListNodes)
	authed.HandleFunc("POST /nodes", s.handleCreateNode)
	authed.HandleFunc("GET /nodes/{id}", s.handleGetNode)
	authed.HandleFunc("PATCH /nodes/{id}", s.handleUpdateNode)
	authed.HandleFunc("DELETE /nodes/{id}", s.handleDeleteNode)
	authed.HandleFunc("POST /nodes/{id}/install-command", s.handleInstallCommand)
	authed.HandleFunc("POST /nodes/{id}/restart", s.handleRestartCore)
	authed.HandleFunc("POST /nodes/{id}/resync", s.handleResyncNode)
	authed.HandleFunc("GET /nodes/{id}/logs", s.handleNodeLogs)
	authed.HandleFunc("GET /nodes/{id}/metrics", s.handleNodeMetrics)
	authed.HandleFunc("GET /nodes/{id}/traffic", s.handleNodeTraffic)
	authed.HandleFunc("POST /nodes/{id}/revoke", s.handleRevokeNode)

	authed.HandleFunc("GET /groups", s.handleListGroups)
	authed.HandleFunc("POST /groups", s.handleCreateGroup)
	authed.HandleFunc("PATCH /groups/{id}", s.handleUpdateGroup)
	authed.HandleFunc("DELETE /groups/{id}", s.handleDeleteGroup)

	authed.HandleFunc("GET /templates", s.handleListTemplates)
	authed.HandleFunc("POST /templates", s.handleCreateTemplate)
	authed.HandleFunc("GET /templates/{id}", s.handleGetTemplate)
	authed.HandleFunc("PUT /templates/{id}", s.handleUpdateTemplate)
	authed.HandleFunc("DELETE /templates/{id}", s.handleDeleteTemplate)
	authed.HandleFunc("PUT /templates/{id}/targets", s.handleSetTemplateTargets)

	authed.HandleFunc("GET /nodes/{id}/inbounds", s.handleListInbounds)
	authed.HandleFunc("POST /nodes/{id}/inbounds", s.handleCreateInbound)
	authed.HandleFunc("PATCH /inbounds/{id}", s.handleUpdateInbound)
	authed.HandleFunc("DELETE /inbounds/{id}", s.handleDeleteInbound)

	authed.HandleFunc("GET /nodes/{id}/flux", s.handleGetNodeFlux)
	authed.HandleFunc("PUT /nodes/{id}/flux", s.handleSetNodeFlux)
	authed.HandleFunc("GET /nodes/{id}/channels", s.handleListChannels)
	authed.HandleFunc("POST /nodes/{id}/channels", s.handleCreateChannel)
	authed.HandleFunc("PATCH /channels/{id}", s.handleUpdateChannel)
	authed.HandleFunc("DELETE /channels/{id}", s.handleDeleteChannel)
	authed.HandleFunc("POST /channels/{id}/rotate", s.handleRotateChannel)

	authed.HandleFunc("GET /users", s.handleListUsers)
	authed.HandleFunc("POST /users", s.handleCreateUser)
	authed.HandleFunc("GET /users/{id}", s.handleGetUser)
	authed.HandleFunc("PATCH /users/{id}", s.handleUpdateUser)
	authed.HandleFunc("DELETE /users/{id}", s.handleDeleteUser)
	authed.HandleFunc("POST /users/{id}/reissue-token", s.handleReissueToken)
	authed.HandleFunc("POST /users/{id}/reset-traffic", s.handleResetTraffic)
	authed.HandleFunc("GET /users/{id}/devices", s.handleListDevices)
	authed.HandleFunc("DELETE /users/{id}/devices/{deviceID}", s.handleDeleteDevice)
	authed.HandleFunc("GET /users/{id}/traffic", s.handleUserTraffic)
	authed.HandleFunc("GET /users/{id}/subscription", s.handleUserSubscription)
	authed.HandleFunc("GET /users/{id}/servers", s.handleUserServers)
	authed.HandleFunc("POST /users/bulk", s.handleBulkUsers)

	authed.HandleFunc("GET /events", s.handleListEvents)
	authed.HandleFunc("GET /audit", s.handleListAudit)

	authed.HandleFunc("GET /settings", s.handleGetSettings)
	authed.HandleFunc("PUT /settings", s.handleSetSettings)

	authed.HandleFunc("POST /keys/reality", s.handleGenerateReality)
	authed.HandleFunc("POST /keys/shortid", s.handleGenerateShortID)
	authed.HandleFunc("POST /keys/uuid", s.handleGenerateUUID)
	authed.HandleFunc("POST /keys/password", s.handleGeneratePassword)
	authed.HandleFunc("POST /keys/shadowsocks", s.handleGenerateShadowsocks)
	authed.HandleFunc("POST /keys/flux-secret", s.handleGenerateFluxSecret)
	authed.HandleFunc("GET /meta", s.handleMeta)

	mux.Handle("/", s.requireAdmin(authed))
	return s.recoverPanics(mux)
}

// ---------------------------------------------------------------------------
// Errors and responses
// ---------------------------------------------------------------------------

// apiError is the one error shape the UI has to understand.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Field names the input that was wrong, for form validation.
	Field string `json:"field,omitempty"`
}

// Error codes. The UI words each one for its user.
const (
	codeBadRequest   = "bad_request"
	codeUnauthorized = "unauthorized"
	codeForbidden    = "forbidden"
	codeNotFound     = "not_found"
	codeConflict     = "conflict"
	codeRateLimited  = "rate_limited"
	codeInternal     = "internal"
	codeNotConnected = "node_not_connected"
	codeTOTPRequired = "totp_required"
	codeLocked       = "account_locked"
)

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The panel answers with data about a private deployment; no cache
	// anywhere in between.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status is already written, so this can only be logged.
		s.log.Warn("could not write a response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: message}})
}

func (s *Server) writeFieldError(w http.ResponseWriter, code, field, message string) {
	s.writeJSON(w, http.StatusBadRequest,
		map[string]apiError{"error": {Code: code, Message: message, Field: field}})
}

// writeStoreError maps a store error to a status. Keeping this in one place is
// what stops a missing row from becoming a 500 somewhere.
func (s *Server) writeStoreError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusNotFound, codeNotFound, what+" was not found")
	case store.IsDuplicate(err):
		s.writeError(w, http.StatusConflict, codeConflict, what+" already exists")
	case store.IsForeignKeyViolation(err):
		s.writeError(w, http.StatusConflict, codeConflict,
			what+" refers to something that does not exist, or is still in use")
	case errors.Is(err, store.ErrDeviceLimit):
		s.writeError(w, http.StatusForbidden, codeForbidden, "the device limit is reached")
	case errors.Is(err, noderpc.ErrNotConnected):
		s.writeError(w, http.StatusConflict, codeNotConnected, "the node's agent is not connected")
	default:
		s.log.Error("request failed", "what", what, "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "something went wrong")
	}
}

// decodeJSON reads a request body, refusing unknown fields so a typo in the UI
// is an error rather than a silently ignored setting.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	// 1 MiB: the largest legitimate body is a settings object with an HTML
	// block in it.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "could not read the request: "+err.Error())
		return false
	}
	return true
}

// pathID reads a numeric path parameter.
func (s *Server) pathID(w http.ResponseWriter, r *http.Request, name string) (uint64, bool) {
	raw := r.PathValue(name)
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, fmt.Sprintf("%s must be a number", name))
		return 0, false
	}
	return id, true
}

func queryInt(r *http.Request, name string, fallback int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func queryBool(r *http.Request, name string) bool {
	switch strings.ToLower(r.URL.Query().Get(name)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

type adminContextKey struct{}

// adminFromContext returns the authenticated administrator.
func adminFromContext(ctx context.Context) *store.Admin {
	admin, _ := ctx.Value(adminContextKey{}).(*store.Admin)
	return admin
}

// requireAdmin rejects anything without a valid session.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || cookie.Value == "" {
			s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "not signed in")
			return
		}
		admin, err := s.store.AdminBySession(r.Context(), cookie.Value)
		if err != nil {
			// An expired or unknown session: clear the cookie so the UI stops
			// sending it.
			s.clearSessionCookie(w)
			s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "the session has expired")
			return
		}
		ctx := context.WithValue(r.Context(), adminContextKey{}, admin)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recoverPanics turns a panic in a handler into a 500 rather than a dropped
// connection, and logs it with the request so it can be found.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error("a handler panicked",
					"method", r.Method, "path", r.URL.Path, "panic", recovered)
				s.writeError(w, http.StatusInternalServerError, codeInternal, "something went wrong")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// audit records an administrator's action. Every handler that changes
// something calls it, because "who did this" has to be answerable.
func (s *Server) audit(r *http.Request, action, objectType, objectID string, details map[string]any) {
	admin := adminFromContext(r.Context())
	entry := store.NewAudit{
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		IP:         s.clientIP(r),
		Details:    details,
	}
	if admin != nil {
		entry.AdminID = &admin.ID
		entry.AdminUsername = admin.Username
	}
	if err := s.store.RecordAudit(r.Context(), entry); err != nil {
		s.log.Warn("could not record an audit entry", "action", action, "error", err)
	}
}

// clientIP returns the address to attribute a request to.
//
// X-Forwarded-For is believed only from a configured proxy. Taking it from
// anyone would let a client claim any address, which would defeat both the
// rate limiter and the device ledger.
func (s *Server) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if !s.trustedProxy(host) {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	// The left-most entry is the original client; the rest were added by
	// proxies along the way.
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

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// rateLimiter is a fixed-window counter per key.
//
// A token bucket would be smoother, but the two things being limited here -
// login attempts and subscription fetches - only need "no more than N a
// minute from one address", and a counter is easy to reason about.
type rateLimiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
	// lastSweep is when stale buckets were last dropped, so the map does not
	// grow with every address that ever connected.
	lastSweep time.Time
}

type bucket struct {
	count int
	start time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:     limit,
		window:    window,
		buckets:   map[string]*bucket{},
		lastSweep: time.Now(),
	}
}

// Allow reports whether a request from key may proceed.
func (l *rateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) > 10*l.window {
		for k, b := range l.buckets {
			if now.Sub(b.start) > l.window {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.buckets[key]
	if !ok || now.Sub(b.start) > l.window {
		l.buckets[key] = &bucket{count: 1, start: now}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// RetryAfter is how long the caller should wait, for the Retry-After header.
func (l *rateLimiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return 0
	}
	remaining := l.window - time.Since(b.start)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.store.DB.PingContext(ctx); err != nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "degraded",
			"error":  "the database is unreachable",
		})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleMeta returns the fixed lists the UI builds its dropdowns from, so the
// two cannot drift apart.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"protocols": []map[string]any{
			{"value": store.ProtoVLESS, "label": "VLESS", "networks": xrayNetworks, "securities": xraySecurities},
			{"value": store.ProtoVMess, "label": "VMess", "networks": xrayNetworks, "securities": xraySecurities},
			{"value": store.ProtoTrojan, "label": "Trojan", "networks": xrayNetworks, "securities": []string{"tls"}},
			{"value": store.ProtoShadowsocks, "label": "Shadowsocks", "networks": []string{"raw"}, "securities": []string{"none"}},
			{"value": store.ProtoShadowsocks2022, "label": "Shadowsocks 2022", "networks": []string{"raw"}, "securities": []string{"none"}},
			{"value": store.ProtoHysteria2, "label": "Hysteria2", "networks": []string{"hysteria"}, "securities": []string{"tls"}},
			{"value": store.ProtoWNDNS, "label": "WhiteNet DNS tunnel", "networks": []string{"dns"}, "securities": []string{"none"}},
		},
		"flux_carriers":       fluxCarrierMeta(),
		"shadowsocks_methods": shadowsocksMethodMeta(),
		"finalmask_udp":       finalMaskUDP,
		"finalmask_tcp":       finalMaskTCP,
		"user_statuses":       []string{store.UserActive, store.UserDisabled, store.UserExpired, store.UserLimited},
		"node_statuses":       []string{store.NodeOnline, store.NodeOffline, store.NodeDegraded},
		"reset_strategies":    []string{"manual", "daily", "weekly", "monthly"},
		"flux_modes":          []string{"l4", "l3"},
	})
}

var (
	xrayNetworks   = []string{"raw", "xhttp", "ws", "httpupgrade", "grpc", "kcp"}
	xraySecurities = []string{"none", "tls", "reality"}
	finalMaskUDP   = []string{
		"header-srtp", "header-utp", "header-dtls", "header-wechat",
		"header-wireguard", "header-dns", "mkcp-original", "mkcp-aes128gcm",
		"noise", "salamander",
	}
	finalMaskTCP = []string{"header-custom", "fragment", "sudoku"}
)

// setSessionCookie issues the session cookie.
//
// HttpOnly so a script cannot read it, SameSite=Lax so a cross-site form
// cannot use it, and Secure whenever the panel is reached over https - which
// it always is in a real deployment, behind the reverse proxy.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(SessionTTL),
		MaxAge:   int(SessionTTL.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// requestIsSecure reports whether the browser reached the panel over https.
// Behind a reverse proxy the request itself is plain http, so the proxy's
// header is what says - and it is only believed from a trusted proxy.
func (s *Server) requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !s.trustedProxy(host) {
		return false
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// requireAuthError is used by handlers that need an administrator but are
// reached through a path where one may be absent.
func (s *Server) requireAdminOrFail(w http.ResponseWriter, r *http.Request) (*store.Admin, bool) {
	admin := adminFromContext(r.Context())
	if admin == nil {
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "not signed in")
		return nil, false
	}
	return admin, true
}

// checkPasswordAndTOTP verifies both factors.
//
// The TOTP check is only reached when the password was right, so a wrong code
// does not reveal whether the password was - and a wrong password costs the
// same whether or not the account has two-factor enabled.
func (s *Server) checkPasswordAndTOTP(admin *store.Admin, password, code string) error {
	if err := auth.CheckPassword(password, admin.PasswordHash); err != nil {
		return err
	}
	if !admin.TOTPEnabled {
		return nil
	}
	if code == "" {
		return errTOTPRequired
	}
	secretValue, err := s.box.OpenString(admin.TOTPSecret)
	if err != nil {
		return fmt.Errorf("api: could not read the two-factor secret: %w", err)
	}
	return auth.CheckTOTP(secretValue, code, time.Now())
}

var errTOTPRequired = errors.New("api: a one-time code is required")
