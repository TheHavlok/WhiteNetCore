package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// ErrNoChannel is returned when no flux channel is free for a user. The
// subscription endpoint turns it into "every channel on this node is busy",
// which is a real answer rather than a failure.
var ErrNoChannel = errors.New("store: no free flux channel")

const channelColumns = `id, uuid, node_id, name, transport, url, params,
	encryption_key, session_context, credentials,
	enabled, session_active, last_error, created_at, updated_at`

// ---------------------------------------------------------------------------
// The exit process per node
// ---------------------------------------------------------------------------

// SetNodeOpenFlux configures the node's exit process.
func (s *Store) SetNodeOpenFlux(ctx context.Context, nodeID uint64, enabled bool, mode string, params JSONMap) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_openflux (node_id, enabled, mode, params) VALUES (?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), mode = VALUES(mode), params = VALUES(params)`,
			nodeID, enabled, mode, params); err != nil {
			return fmt.Errorf("store: set node %d flux config: %w", nodeID, err)
		}
		return bumpNodeVersionTx(ctx, tx, nodeID)
	})
}

// NodeOpenFluxConfig reads a node's exit configuration, or nil when the node
// has none - which is the normal case and means the core stays down.
func (s *Store) NodeOpenFluxConfig(ctx context.Context, nodeID uint64) (*NodeOpenFlux, error) {
	var cfg NodeOpenFlux
	err := s.DB.GetContext(ctx, &cfg,
		`SELECT node_id, enabled, mode, params, created_at, updated_at
		 FROM node_openflux WHERE node_id = ?`, nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: node %d flux config: %w", nodeID, err)
	}
	return &cfg, nil
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

// CreateChannel adds a channel to a node's pool. The key and credentials
// arrive encrypted: the caller has the master key, this layer does not.
func (s *Store) CreateChannel(ctx context.Context, c OpenFluxChannel) (*OpenFluxChannel, error) {
	var id uint64
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO openflux_channels (uuid, node_id, name, transport, url, params,
				encryption_key, session_context, credentials, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.NewString(), c.NodeID, c.Name, c.Transport, c.URL, c.Params,
			nullBytes(c.EncryptionKey), c.SessionContext, nullBytes(c.Credentials), c.Enabled)
		if err != nil {
			return fmt.Errorf("store: create flux channel: %w", err)
		}
		lastID, _ := res.LastInsertId()
		id = uint64(lastID)
		return bumpNodeVersionTx(ctx, tx, c.NodeID)
	})
	if err != nil {
		return nil, err
	}
	return s.ChannelByID(ctx, id)
}

// ChannelByID reads one channel.
func (s *Store) ChannelByID(ctx context.Context, id uint64) (*OpenFluxChannel, error) {
	var c OpenFluxChannel
	err := s.DB.GetContext(ctx, &c, `SELECT `+channelColumns+` FROM openflux_channels WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: flux channel %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: flux channel %d: %w", id, err)
	}
	return &c, nil
}

// NodeChannels returns a node's channels.
func (s *Store) NodeChannels(ctx context.Context, nodeID uint64) ([]OpenFluxChannel, error) {
	var out []OpenFluxChannel
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT `+channelColumns+` FROM openflux_channels WHERE node_id = ? ORDER BY id`, nodeID); err != nil {
		return nil, fmt.Errorf("store: node %d channels: %w", nodeID, err)
	}
	return out, nil
}

// ChannelUpdate is the partial update the API accepts.
type ChannelUpdate struct {
	Name           *string
	Transport      *string
	URL            *string
	Params         *JSONMap
	EncryptionKey  *[]byte
	SessionContext *string
	Credentials    *[]byte
	Enabled        *bool
}

// UpdateChannel applies an update. Rotating the key is how a lease is revoked
// the hard way: the agent restarts the channel and the old session stops
// decrypting.
func (s *Store) UpdateChannel(ctx context.Context, id uint64, update ChannelUpdate) (*OpenFluxChannel, error) {
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		var c OpenFluxChannel
		if err := tx.GetContext(ctx, &c,
			`SELECT `+channelColumns+` FROM openflux_channels WHERE id = ? FOR UPDATE`, id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: flux channel %d: %w", id, ErrNotFound)
			}
			return fmt.Errorf("store: flux channel %d: %w", id, err)
		}
		if update.Name != nil {
			c.Name = *update.Name
		}
		if update.Transport != nil {
			c.Transport = *update.Transport
		}
		if update.URL != nil {
			c.URL = *update.URL
		}
		if update.Params != nil {
			c.Params = *update.Params
		}
		if update.EncryptionKey != nil {
			c.EncryptionKey = *update.EncryptionKey
		}
		if update.SessionContext != nil {
			c.SessionContext = sql.NullString{String: *update.SessionContext, Valid: *update.SessionContext != ""}
		}
		if update.Credentials != nil {
			c.Credentials = *update.Credentials
		}
		if update.Enabled != nil {
			c.Enabled = *update.Enabled
		}

		if _, err := tx.ExecContext(ctx,
			`UPDATE openflux_channels SET name = ?, transport = ?, url = ?, params = ?,
			 encryption_key = ?, session_context = ?, credentials = ?, enabled = ? WHERE id = ?`,
			c.Name, c.Transport, c.URL, c.Params, nullBytes(c.EncryptionKey),
			c.SessionContext, nullBytes(c.Credentials), c.Enabled, id); err != nil {
			return fmt.Errorf("store: update flux channel %d: %w", id, err)
		}
		return bumpNodeVersionTx(ctx, tx, c.NodeID)
	})
	if err != nil {
		return nil, err
	}
	return s.ChannelByID(ctx, id)
}

// DeleteChannel removes a channel and its lease history.
func (s *Store) DeleteChannel(ctx context.Context, id uint64) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error {
		var nodeID uint64
		err := tx.GetContext(ctx, &nodeID, `SELECT node_id FROM openflux_channels WHERE id = ?`, id)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: flux channel %d: %w", id, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("store: flux channel %d: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM openflux_channels WHERE id = ?`, id); err != nil {
			return fmt.Errorf("store: delete flux channel %d: %w", id, err)
		}
		return bumpNodeVersionTx(ctx, tx, nodeID)
	})
}

// SetChannelStatus records what the agent reported about a channel.
func (s *Store) SetChannelStatus(ctx context.Context, id uint64, sessionActive bool, lastError string) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE openflux_channels SET session_active = ?, last_error = ? WHERE id = ?`,
		sessionActive, nullString(lastError), id); err != nil {
		return fmt.Errorf("store: set flux channel %d status: %w", id, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Leases
// ---------------------------------------------------------------------------

// AcquireChannel leases a free channel on one of the user's nodes.
//
// A flux channel carries one client at a time, so this is where that is
// enforced. The database does the enforcing: `active` is 1 while held and NULL
// once released, and the unique index on (channel_id, active) makes a second
// live lease impossible. Two clients racing get one winner and one
// ErrNoChannel, without the application having to lock anything.
func (s *Store) AcquireChannel(ctx context.Context, userID uint64, nodeID uint64, deviceID *uint64, ttl time.Duration) (*OpenFluxLease, *OpenFluxChannel, error) {
	var lease OpenFluxLease
	var channel OpenFluxChannel

	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		// Expire stale leases first, so a client that vanished frees its
		// channel instead of holding it until someone notices.
		if _, err := tx.ExecContext(ctx,
			`UPDATE openflux_leases SET active = NULL, released_at = ?, release_reason = 'expired'
			 WHERE active = 1 AND expires_at < ?`,
			time.Now().UTC(), time.Now().UTC()); err != nil {
			return fmt.Errorf("store: expire leases: %w", err)
		}

		// A user who already holds a lease on this node gets the same channel
		// back rather than a second one: reconnecting must not consume the
		// pool.
		existing := OpenFluxLease{}
		err := tx.GetContext(ctx, &existing,
			`SELECT l.id, l.channel_id, l.user_id, l.device_id, l.active,
				l.acquired_at, l.renewed_at, l.expires_at, l.released_at, l.release_reason
			 FROM openflux_leases l
			 JOIN openflux_channels c ON c.id = l.channel_id
			 WHERE l.user_id = ? AND l.active = 1 AND c.node_id = ?
			 LIMIT 1`, userID, nodeID)
		switch {
		case err == nil:
			if _, err := tx.ExecContext(ctx,
				`UPDATE openflux_leases SET renewed_at = ?, expires_at = ? WHERE id = ?`,
				time.Now().UTC(), time.Now().UTC().Add(ttl), existing.ID); err != nil {
				return fmt.Errorf("store: renew lease: %w", err)
			}
			lease = existing
			lease.ExpiresAt = time.Now().UTC().Add(ttl)
			return tx.GetContext(ctx, &channel,
				`SELECT `+channelColumns+` FROM openflux_channels WHERE id = ?`, existing.ChannelID)
		case errors.Is(err, sql.ErrNoRows):
			// fall through and take a free one
		default:
			return fmt.Errorf("store: existing lease: %w", err)
		}

		// A free channel is an enabled one on this node with no live lease.
		err = tx.GetContext(ctx, &channel,
			`SELECT `+channelColumns+` FROM openflux_channels c
			 WHERE c.node_id = ? AND c.enabled = 1
			   AND NOT EXISTS (SELECT 1 FROM openflux_leases l WHERE l.channel_id = c.id AND l.active = 1)
			 ORDER BY c.id LIMIT 1`, nodeID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoChannel
		}
		if err != nil {
			return fmt.Errorf("store: find free channel: %w", err)
		}

		var device any
		if deviceID != nil {
			device = *deviceID
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO openflux_leases (channel_id, user_id, device_id, active, expires_at)
			 VALUES (?, ?, ?, 1, ?)`,
			channel.ID, userID, device, time.Now().UTC().Add(ttl))
		if err != nil {
			// The unique index rejected it, which means another client took
			// this channel in between. Report it as "none free" and let the
			// caller retry.
			if IsDuplicate(err) {
				return ErrNoChannel
			}
			return fmt.Errorf("store: acquire lease: %w", err)
		}
		lastID, _ := res.LastInsertId()
		return tx.GetContext(ctx, &lease,
			`SELECT id, channel_id, user_id, device_id, active, acquired_at, renewed_at,
				expires_at, released_at, release_reason
			 FROM openflux_leases WHERE id = ?`, lastID)
	})
	if err != nil {
		return nil, nil, err
	}
	return &lease, &channel, nil
}

// RenewLease extends a lease the client is still using.
func (s *Store) RenewLease(ctx context.Context, leaseID, userID uint64, ttl time.Duration) (*OpenFluxLease, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE openflux_leases SET renewed_at = ?, expires_at = ?
		 WHERE id = ? AND user_id = ? AND active = 1`,
		time.Now().UTC(), time.Now().UTC().Add(ttl), leaseID, userID)
	if err != nil {
		return nil, fmt.Errorf("store: renew lease %d: %w", leaseID, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		// Either it is not theirs or it already lapsed; both mean "ask for a
		// new one".
		return nil, fmt.Errorf("store: lease %d: %w", leaseID, ErrNotFound)
	}
	var lease OpenFluxLease
	if err := s.DB.GetContext(ctx, &lease,
		`SELECT id, channel_id, user_id, device_id, active, acquired_at, renewed_at,
			expires_at, released_at, release_reason
		 FROM openflux_leases WHERE id = ?`, leaseID); err != nil {
		return nil, fmt.Errorf("store: read lease %d: %w", leaseID, err)
	}
	return &lease, nil
}

// ReleaseLease hands a channel back, so it does not sit idle until it expires.
func (s *Store) ReleaseLease(ctx context.Context, leaseID, userID uint64, reason string) error {
	if reason == "" {
		reason = "released"
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE openflux_leases SET active = NULL, released_at = ?, release_reason = ?
		 WHERE id = ? AND user_id = ? AND active = 1`,
		time.Now().UTC(), reason, leaseID, userID)
	if err != nil {
		return fmt.Errorf("store: release lease %d: %w", leaseID, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("store: lease %d: %w", leaseID, ErrNotFound)
	}
	return nil
}

// ExpireLeases releases every lease past its expiry. The panel runs this on a
// timer as well as on acquisition, so a pool recovers even when nobody is
// asking for a channel.
func (s *Store) ExpireLeases(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE openflux_leases SET active = NULL, released_at = ?, release_reason = 'expired'
		 WHERE active = 1 AND expires_at < ?`,
		time.Now().UTC(), time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("store: expire leases: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// RevokeUserLeases releases every lease a user holds, which is what happens
// when they are disabled or run out of traffic.
func (s *Store) RevokeUserLeases(ctx context.Context, userID uint64) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE openflux_leases SET active = NULL, released_at = ?, release_reason = 'revoked'
		 WHERE user_id = ? AND active = 1`,
		time.Now().UTC(), userID); err != nil {
		return fmt.Errorf("store: revoke user %d leases: %w", userID, err)
	}
	return nil
}

// ChannelOccupancy is what the panel shows next to a node's flux pool.
type ChannelOccupancy struct {
	NodeID uint64 `db:"node_id"`
	Total  int    `db:"total"`
	Leased int    `db:"leased"`
	Active int    `db:"active_sessions"`
}

// Occupancy returns the pool usage per node.
func (s *Store) Occupancy(ctx context.Context) ([]ChannelOccupancy, error) {
	var out []ChannelOccupancy
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT c.node_id,
			COUNT(*) AS total,
			SUM(CASE WHEN EXISTS (
				SELECT 1 FROM openflux_leases l WHERE l.channel_id = c.id AND l.active = 1
			) THEN 1 ELSE 0 END) AS leased,
			SUM(CASE WHEN c.session_active = 1 THEN 1 ELSE 0 END) AS active_sessions
		 FROM openflux_channels c
		 WHERE c.enabled = 1
		 GROUP BY c.node_id`); err != nil {
		return nil, fmt.Errorf("store: channel occupancy: %w", err)
	}
	return out, nil
}

// LeaseByID reads one lease, for the renew and release endpoints.
func (s *Store) LeaseByID(ctx context.Context, id uint64) (*OpenFluxLease, error) {
	var lease OpenFluxLease
	err := s.DB.GetContext(ctx, &lease,
		`SELECT id, channel_id, user_id, device_id, active, acquired_at, renewed_at,
			expires_at, released_at, release_reason
		 FROM openflux_leases WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: lease %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: lease %d: %w", id, err)
	}
	return &lease, nil
}
