package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const adminColumns = `id, username, password_hash, totp_secret, totp_enabled, role,
	is_active, failed_logins, locked_until, last_login_at, last_login_ip,
	created_at, updated_at`

// CreateAdmin adds an administrator. The hash and the encrypted TOTP secret
// are produced by the caller: this layer never sees a password.
func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash, role string) (*Admin, error) {
	if role == "" {
		role = "admin"
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)`,
		username, passwordHash, role)
	if err != nil {
		return nil, fmt.Errorf("store: create admin: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.AdminByID(ctx, uint64(id))
}

// AdminByID reads one administrator.
func (s *Store) AdminByID(ctx context.Context, id uint64) (*Admin, error) {
	var a Admin
	err := s.DB.GetContext(ctx, &a, `SELECT `+adminColumns+` FROM admins WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: admin %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: admin %d: %w", id, err)
	}
	return &a, nil
}

// AdminByUsername reads one administrator by name.
func (s *Store) AdminByUsername(ctx context.Context, username string) (*Admin, error) {
	var a Admin
	err := s.DB.GetContext(ctx, &a, `SELECT `+adminColumns+` FROM admins WHERE username = ?`, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: admin %s: %w", username, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: admin %s: %w", username, err)
	}
	return &a, nil
}

// ListAdmins returns every administrator.
func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	var out []Admin
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT `+adminColumns+` FROM admins ORDER BY username`); err != nil {
		return nil, fmt.Errorf("store: list admins: %w", err)
	}
	return out, nil
}

// CountAdmins is how the panel decides whether to create the first account.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	if err := s.DB.GetContext(ctx, &n, `SELECT COUNT(*) FROM admins`); err != nil {
		return 0, fmt.Errorf("store: count admins: %w", err)
	}
	return n, nil
}

// SetAdminPassword replaces the hash.
func (s *Store) SetAdminPassword(ctx context.Context, id uint64, passwordHash string) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE admins SET password_hash = ?, failed_logins = 0, locked_until = NULL WHERE id = ?`,
		passwordHash, id); err != nil {
		return fmt.Errorf("store: set admin %d password: %w", id, err)
	}
	return nil
}

// SetAdminTOTP stores or clears the encrypted TOTP secret.
func (s *Store) SetAdminTOTP(ctx context.Context, id uint64, encryptedSecret []byte, enabled bool) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE admins SET totp_secret = ?, totp_enabled = ? WHERE id = ?`,
		nullBytes(encryptedSecret), enabled, id); err != nil {
		return fmt.Errorf("store: set admin %d two-factor: %w", id, err)
	}
	return nil
}

// SetAdminActive enables or disables an account.
func (s *Store) SetAdminActive(ctx context.Context, id uint64, active bool) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE admins SET is_active = ? WHERE id = ?`, active, id); err != nil {
		return fmt.Errorf("store: set admin %d active: %w", id, err)
	}
	return nil
}

// DeleteAdmin removes an account.
func (s *Store) DeleteAdmin(ctx context.Context, id uint64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM admins WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete admin %d: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("store: admin %d: %w", id, ErrNotFound)
	}
	return nil
}

// RecordLoginFailure counts a failed attempt and locks the account once there
// have been too many.
//
// The lock is on the row rather than on the client address: an attacker with a
// botnet has many addresses and only one username to guess at.
func (s *Store) RecordLoginFailure(ctx context.Context, id uint64, threshold int, lockFor time.Duration) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE admins SET
			failed_logins = failed_logins + 1,
			locked_until = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END
		 WHERE id = ?`,
		threshold, time.Now().UTC().Add(lockFor), id); err != nil {
		return fmt.Errorf("store: record login failure for admin %d: %w", id, err)
	}
	return nil
}

// RecordLoginSuccess clears the failure count and stamps the login.
func (s *Store) RecordLoginSuccess(ctx context.Context, id uint64, ip string) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE admins SET failed_logins = 0, locked_until = NULL, last_login_at = ?, last_login_ip = ?
		 WHERE id = ?`,
		time.Now().UTC(), nullString(ip), id); err != nil {
		return fmt.Errorf("store: record login for admin %d: %w", id, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// CreateAdminSession issues a session token and returns the plaintext, which
// is only ever in the cookie. The database keeps the hash, so a dump of this
// table cannot be replayed.
func (s *Store) CreateAdminSession(ctx context.Context, adminID uint64, userAgent, ip string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO admin_sessions (admin_id, token_hash, user_agent, ip, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		adminID, sum[:], nullString(truncate(userAgent, 255)), nullString(ip),
		time.Now().UTC().Add(ttl)); err != nil {
		return "", fmt.Errorf("store: create admin session: %w", err)
	}
	return token, nil
}

// AdminBySession resolves a session token to its administrator, refreshing the
// last-seen stamp.
func (s *Store) AdminBySession(ctx context.Context, token string) (*Admin, error) {
	sum := sha256.Sum256([]byte(token))
	var a Admin
	err := s.DB.GetContext(ctx, &a,
		`SELECT `+prefixColumns(adminColumns, "a")+` FROM admins a
		 JOIN admin_sessions s ON s.admin_id = a.id
		 WHERE s.token_hash = ? AND s.expires_at > ? AND a.is_active = 1`,
		sum[:], time.Now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: session: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: session: %w", err)
	}
	// Best effort: a failed touch must not fail the request.
	_, _ = s.DB.ExecContext(ctx,
		`UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?`, time.Now().UTC(), sum[:])
	return &a, nil
}

// DeleteAdminSession logs one session out.
func (s *Store) DeleteAdminSession(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE token_hash = ?`, sum[:]); err != nil {
		return fmt.Errorf("store: delete admin session: %w", err)
	}
	return nil
}

// DeleteAdminSessions logs an administrator out everywhere, which is what a
// password change should do.
func (s *Store) DeleteAdminSessions(ctx context.Context, adminID uint64) error {
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE admin_id = ?`, adminID); err != nil {
		return fmt.Errorf("store: delete admin %d sessions: %w", adminID, err)
	}
	return nil
}

// PruneAdminSessions removes expired sessions.
func (s *Store) PruneAdminSessions(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("store: prune admin sessions: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// AdminSessionInfo is a row of the "where am I logged in" list.
type AdminSessionInfo struct {
	ID         uint64         `db:"id"`
	UserAgent  sql.NullString `db:"user_agent"`
	IP         sql.NullString `db:"ip"`
	CreatedAt  time.Time      `db:"created_at"`
	LastSeenAt time.Time      `db:"last_seen_at"`
	ExpiresAt  time.Time      `db:"expires_at"`
}

// AdminSessions lists an administrator's live sessions.
func (s *Store) AdminSessions(ctx context.Context, adminID uint64) ([]AdminSessionInfo, error) {
	var out []AdminSessionInfo
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT id, user_agent, ip, created_at, last_seen_at, expires_at
		 FROM admin_sessions WHERE admin_id = ? AND expires_at > ? ORDER BY last_seen_at DESC`,
		adminID, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("store: admin %d sessions: %w", adminID, err)
	}
	return out, nil
}
