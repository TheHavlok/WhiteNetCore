package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/auth"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// handleSetupNeeded says whether the panel has any administrator yet. The UI
// shows the first-run form when it does not.
func (s *Server) handleSetupNeeded(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.CountAdmins(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "administrators")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"setup_needed": count == 0})
}

// handleSetup creates the first administrator.
//
// It is only usable while there is none: after that the endpoint refuses, so
// it cannot be used to add an account to a running panel.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	count, err := s.store.CountAdmins(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "administrators")
		return
	}
	if count > 0 {
		s.writeError(w, http.StatusForbidden, codeForbidden,
			"this panel already has an administrator; sign in instead")
		return
	}
	if err := validateUsername(req.Username); err != nil {
		s.writeFieldError(w, codeBadRequest, "username", err.Error())
		return
	}
	if err := validatePassword(req.Password); err != nil {
		s.writeFieldError(w, codeBadRequest, "password", err.Error())
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.writeStoreError(w, err, "the password")
		return
	}
	admin, err := s.store.CreateAdmin(r.Context(), req.Username, hash, "admin")
	if err != nil {
		s.writeStoreError(w, err, "the administrator")
		return
	}

	token, err := s.store.CreateAdminSession(r.Context(), admin.ID,
		r.UserAgent(), s.clientIP(r), SessionTTL)
	if err != nil {
		s.writeStoreError(w, err, "the session")
		return
	}
	s.setSessionCookie(w, r, token)

	_ = s.store.RecordAudit(r.Context(), store.NewAudit{
		AdminID: &admin.ID, AdminUsername: admin.Username,
		Action: "admin.setup", ObjectType: "admin", ObjectID: fmt.Sprint(admin.ID),
		IP: s.clientIP(r),
	})
	s.log.Info("the first administrator was created", "username", admin.Username)
	s.writeJSON(w, http.StatusCreated, adminResponse(admin))
}

// handleLogin signs an administrator in.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginLimiter.Allow(ip) {
		w.Header().Set("Retry-After", fmt.Sprint(int(s.loginLimiter.RetryAfter(ip).Seconds())+1))
		s.writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many attempts; wait a moment")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	admin, err := s.store.AdminByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The same answer as a wrong password, so the endpoint does not
			// say which usernames exist.
			s.log.Warn("failed sign-in", "username", req.Username, "ip", ip, "reason", "no such account")
			s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "wrong username or password")
			return
		}
		s.writeStoreError(w, err, "the administrator")
		return
	}

	if !admin.IsActive {
		s.writeError(w, http.StatusForbidden, codeForbidden, "this account is disabled")
		return
	}
	if admin.Locked(time.Now()) {
		s.writeError(w, http.StatusTooManyRequests, codeLocked,
			"too many failed attempts; this account is locked for a few minutes")
		return
	}

	switch err := s.checkPasswordAndTOTP(admin, req.Password, req.Code); {
	case err == nil:
		// fall through

	case errors.Is(err, errTOTPRequired):
		// Not a failure: the password was right and the UI should now ask for
		// the code. It is deliberately not counted as a failed attempt.
		s.writeError(w, http.StatusUnauthorized, codeTOTPRequired, "enter the code from your authenticator")
		return

	case errors.Is(err, auth.ErrWrongPassword), errors.Is(err, auth.ErrWrongCode):
		if err := s.store.RecordLoginFailure(r.Context(), admin.ID,
			loginFailureThreshold, loginLockDuration); err != nil {
			s.log.Warn("could not record a failed sign-in", "error", err)
		}
		s.log.Warn("failed sign-in", "username", admin.Username, "ip", ip)
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "wrong username or password")
		return

	default:
		s.writeStoreError(w, err, "the sign-in")
		return
	}

	// The hash is quietly upgraded when the parameters have been raised since
	// it was made; the user never notices.
	if auth.NeedsRehash(admin.PasswordHash) {
		if hash, err := auth.HashPassword(req.Password); err == nil {
			if err := s.store.SetAdminPassword(r.Context(), admin.ID, hash); err != nil {
				s.log.Warn("could not upgrade a password hash", "error", err)
			}
		}
	}

	if err := s.store.RecordLoginSuccess(r.Context(), admin.ID, ip); err != nil {
		s.log.Warn("could not record a sign-in", "error", err)
	}
	token, err := s.store.CreateAdminSession(r.Context(), admin.ID, r.UserAgent(), ip, SessionTTL)
	if err != nil {
		s.writeStoreError(w, err, "the session")
		return
	}
	s.setSessionCookie(w, r, token)

	_ = s.store.RecordAudit(r.Context(), store.NewAudit{
		AdminID: &admin.ID, AdminUsername: admin.Username,
		Action: "admin.login", ObjectType: "admin", ObjectID: fmt.Sprint(admin.ID), IP: ip,
	})
	s.log.Info("administrator signed in", "username", admin.Username, "ip", ip)
	s.writeJSON(w, http.StatusOK, adminResponse(admin))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookie); err == nil && cookie.Value != "" {
		if err := s.store.DeleteAdminSession(r.Context(), cookie.Value); err != nil {
			s.log.Warn("could not delete a session", "error", err)
		}
	}
	s.clearSessionCookie(w)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdminOrFail(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, adminResponse(admin))
}

// handleChangePassword replaces the signed-in administrator's password.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdminOrFail(w, r)
	if !ok {
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
		Code    string `json:"code"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	// The current password is required even though the session proves who
	// this is: a borrowed session must not be enough to lock the owner out.
	if err := s.checkPasswordAndTOTP(admin, req.Current, req.Code); err != nil {
		if errors.Is(err, errTOTPRequired) {
			s.writeError(w, http.StatusUnauthorized, codeTOTPRequired, "enter the code from your authenticator")
			return
		}
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "the current password is wrong")
		return
	}
	if err := validatePassword(req.New); err != nil {
		s.writeFieldError(w, codeBadRequest, "new", err.Error())
		return
	}

	hash, err := auth.HashPassword(req.New)
	if err != nil {
		s.writeStoreError(w, err, "the password")
		return
	}
	if err := s.store.SetAdminPassword(r.Context(), admin.ID, hash); err != nil {
		s.writeStoreError(w, err, "the password")
		return
	}
	// Every other session is invalidated: a password change is what someone
	// does when they think a session has leaked.
	if err := s.store.DeleteAdminSessions(r.Context(), admin.ID); err != nil {
		s.log.Warn("could not clear sessions after a password change", "error", err)
	}
	token, err := s.store.CreateAdminSession(r.Context(), admin.ID, r.UserAgent(), s.clientIP(r), SessionTTL)
	if err != nil {
		s.writeStoreError(w, err, "the session")
		return
	}
	s.setSessionCookie(w, r, token)

	s.audit(r, "admin.password_changed", "admin", fmt.Sprint(admin.ID), nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTOTPStart produces a secret and the otpauth URL to scan.
//
// Nothing is enabled yet: the secret is stored but `totp_enabled` stays off
// until a code proves the authenticator has it, so a half-finished setup
// cannot lock anyone out.
func (s *Server) handleTOTPStart(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdminOrFail(w, r)
	if !ok {
		return
	}
	if admin.TOTPEnabled {
		s.writeError(w, http.StatusConflict, codeConflict,
			"two-factor is already on; turn it off first")
		return
	}
	secretValue, err := auth.NewTOTPSecret()
	if err != nil {
		s.writeStoreError(w, err, "the two-factor secret")
		return
	}
	sealed, err := s.box.SealString(secretValue)
	if err != nil {
		s.writeStoreError(w, err, "the two-factor secret")
		return
	}
	if err := s.store.SetAdminTOTP(r.Context(), admin.ID, sealed, false); err != nil {
		s.writeStoreError(w, err, "the two-factor secret")
		return
	}

	issuer := "WhiteNet"
	if branding, err := s.store.Branding(r.Context()); err == nil && branding.AppName != "" {
		issuer = branding.AppName
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"secret": secretValue,
		"url":    auth.TOTPURL(issuer, admin.Username, secretValue),
	})
}

// handleTOTPConfirm turns two-factor on once a code checks out.
func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdminOrFail(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if len(admin.TOTPSecret) == 0 {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "start the two-factor setup first")
		return
	}
	secretValue, err := s.box.OpenString(admin.TOTPSecret)
	if err != nil {
		s.writeStoreError(w, err, "the two-factor secret")
		return
	}
	if err := auth.CheckTOTP(secretValue, req.Code, time.Now()); err != nil {
		s.writeFieldError(w, codeBadRequest, "code", "that code does not match")
		return
	}
	if err := s.store.SetAdminTOTP(r.Context(), admin.ID, admin.TOTPSecret, true); err != nil {
		s.writeStoreError(w, err, "two-factor")
		return
	}
	s.audit(r, "admin.totp_enabled", "admin", fmt.Sprint(admin.ID), nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTOTPDisable turns two-factor off, which needs the password and a
// current code: otherwise a borrowed session could remove the second factor.
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdminOrFail(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if err := s.checkPasswordAndTOTP(admin, req.Password, req.Code); err != nil {
		if errors.Is(err, errTOTPRequired) {
			s.writeError(w, http.StatusUnauthorized, codeTOTPRequired, "enter the code from your authenticator")
			return
		}
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "the password or code is wrong")
		return
	}
	if err := s.store.SetAdminTOTP(r.Context(), admin.ID, nil, false); err != nil {
		s.writeStoreError(w, err, "two-factor")
		return
	}
	s.audit(r, "admin.totp_disabled", "admin", fmt.Sprint(admin.ID), nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdminOrFail(w, r)
	if !ok {
		return
	}
	sessions, err := s.store.AdminSessions(r.Context(), admin.ID)
	if err != nil {
		s.writeStoreError(w, err, "the sessions")
		return
	}
	out := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, map[string]any{
			"id":           session.ID,
			"user_agent":   session.UserAgent.String,
			"ip":           session.IP.String,
			"created_at":   session.CreatedAt,
			"last_seen_at": session.LastSeenAt,
			"expires_at":   session.ExpiresAt,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func adminResponse(admin *store.Admin) map[string]any {
	return map[string]any{
		"id":            admin.ID,
		"username":      admin.Username,
		"role":          admin.Role,
		"totp_enabled":  admin.TOTPEnabled,
		"last_login_at": nullTime(admin.LastLoginAt),
	}
}

func validateUsername(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 {
		return errors.New("a username is 3 to 64 characters")
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == '@':
		default:
			return fmt.Errorf("a username cannot contain %q", string(r))
		}
	}
	return nil
}

// validatePassword sets a floor rather than a pattern. Length is what makes a
// password hard to guess; insisting on a symbol mostly produces "Password1!".
func validatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("a password must be at least 12 characters")
	}
	if len(password) > 256 {
		return errors.New("a password must be at most 256 characters")
	}
	return nil
}
