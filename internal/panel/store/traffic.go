package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// TrafficDelta is one entry of an agent's report.
//
// A delta with a user id is that user's traffic; one with only an inbound tag
// is the inbound's total. Xray reports both and they are not derivable from
// each other, so they travel together and are stored separately.
type TrafficDelta struct {
	UserID        uint64
	InboundTag    string
	UplinkBytes   uint64
	DownlinkBytes uint64
}

// ApplyTrafficReport records a report from a node.
//
// The batch id makes it idempotent: it is the primary key of
// `traffic_batches`, so a report an agent resends after a dropped connection
// is rejected rather than counted twice. That is what makes retrying safe,
// which in turn is what lets the agent reset Xray's counters on every read.
//
// The returned slice lists the users who have now gone over a limit, so the
// caller can disable them without a second pass over the table.
func (s *Store) ApplyTrafficReport(ctx context.Context, nodeID uint64, at time.Time, batchID string, deltas []TrafficDelta) (overLimit []uint64, err error) {
	if batchID == "" {
		return nil, fmt.Errorf("store: traffic report has no batch id")
	}
	day := at.UTC().Format("2006-01-02")

	err = s.Tx(ctx, func(tx *sqlx.Tx) error {
		// The insert is the idempotency check. A duplicate means this report
		// has already been applied, and the right response is to do nothing
		// and say so quietly.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO traffic_batches (node_id, batch_id) VALUES (?, ?)`, nodeID, batchID); err != nil {
			if IsDuplicate(err) {
				return nil
			}
			return fmt.Errorf("store: record traffic batch: %w", err)
		}

		touched := map[uint64]bool{}
		for _, delta := range deltas {
			if delta.UplinkBytes == 0 && delta.DownlinkBytes == 0 {
				continue
			}
			if delta.UserID == 0 {
				// An inbound total. Nothing aggregates these yet beyond the
				// node's own charts, so they are not stored per inbound: the
				// node's metrics already carry its network counters.
				continue
			}

			if _, err := tx.ExecContext(ctx,
				`INSERT INTO user_traffic_daily (user_id, node_id, day, uplink_bytes, downlink_bytes)
				 VALUES (?, ?, ?, ?, ?)
				 ON DUPLICATE KEY UPDATE
					uplink_bytes = uplink_bytes + VALUES(uplink_bytes),
					downlink_bytes = downlink_bytes + VALUES(downlink_bytes)`,
				delta.UserID, nodeID, day, delta.UplinkBytes, delta.DownlinkBytes); err != nil {
				return fmt.Errorf("store: add daily traffic for user %d: %w", delta.UserID, err)
			}

			// The running total is what limits are checked against, so it is
			// kept on the user row and never aggregated on the hot path.
			if _, err := tx.ExecContext(ctx,
				`UPDATE users SET traffic_used = traffic_used + ? WHERE id = ?`,
				delta.UplinkBytes+delta.DownlinkBytes, delta.UserID); err != nil {
				return fmt.Errorf("store: add total traffic for user %d: %w", delta.UserID, err)
			}
			touched[delta.UserID] = true
		}

		if len(touched) == 0 {
			return nil
		}
		ids := make([]uint64, 0, len(touched))
		for id := range touched {
			ids = append(ids, id)
		}
		query, args, err := sqlx.In(
			`SELECT id FROM users
			 WHERE id IN (?) AND traffic_limit > 0 AND traffic_used >= traffic_limit AND status = ?`,
			ids, UserActive)
		if err != nil {
			return fmt.Errorf("store: check limits: %w", err)
		}
		if err := tx.SelectContext(ctx, &overLimit, tx.Rebind(query), args...); err != nil {
			return fmt.Errorf("store: check limits: %w", err)
		}
		return nil
	})
	return overLimit, err
}

// EnforceLimits moves users past their expiry or allowance out of `active`.
//
// It is run on a timer as well as after a traffic report, because an expiry
// passes without anyone sending anything. Returns the ids it changed so the
// caller can release their flux leases and bump the nodes.
func (s *Store) EnforceLimits(ctx context.Context) (expired, limited []uint64, err error) {
	now := time.Now().UTC()
	err = s.Tx(ctx, func(tx *sqlx.Tx) error {
		if err := tx.SelectContext(ctx, &expired,
			`SELECT id FROM users WHERE status = ? AND expires_at IS NOT NULL AND expires_at <= ?`,
			UserActive, now); err != nil {
			return fmt.Errorf("store: find expired users: %w", err)
		}
		if err := tx.SelectContext(ctx, &limited,
			`SELECT id FROM users WHERE status = ? AND traffic_limit > 0 AND traffic_used >= traffic_limit`,
			UserActive); err != nil {
			return fmt.Errorf("store: find users over their limit: %w", err)
		}

		if len(expired) > 0 {
			query, args, err := sqlx.In(`UPDATE users SET status = ? WHERE id IN (?)`, UserExpired, expired)
			if err != nil {
				return fmt.Errorf("store: expire users: %w", err)
			}
			if _, err := tx.ExecContext(ctx, tx.Rebind(query), args...); err != nil {
				return fmt.Errorf("store: expire users: %w", err)
			}
		}
		if len(limited) > 0 {
			query, args, err := sqlx.In(`UPDATE users SET status = ? WHERE id IN (?)`, UserLimited, limited)
			if err != nil {
				return fmt.Errorf("store: limit users: %w", err)
			}
			if _, err := tx.ExecContext(ctx, tx.Rebind(query), args...); err != nil {
				return fmt.Errorf("store: limit users: %w", err)
			}
		}

		// A user who is no longer active must come off every node, so the
		// nodes in their groups need a new state.
		var groups []uint64
		for _, id := range append(append([]uint64{}, expired...), limited...) {
			userGroups, err := userGroupIDsTx(ctx, tx, id)
			if err != nil {
				return err
			}
			groups = append(groups, userGroups...)
		}
		return bumpNodesForUserGroupsTx(ctx, tx, groups)
	})
	return expired, limited, err
}

// UserTrafficPoint is one day of a user's traffic.
type UserTrafficPoint struct {
	Day           time.Time `db:"day"`
	UplinkBytes   uint64    `db:"uplink_bytes"`
	DownlinkBytes uint64    `db:"downlink_bytes"`
}

// UserTrafficHistory returns a user's daily traffic over the last n days.
func (s *Store) UserTrafficHistory(ctx context.Context, userID uint64, days int) ([]UserTrafficPoint, error) {
	if days <= 0 {
		days = 30
	}
	var out []UserTrafficPoint
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT day, SUM(uplink_bytes) AS uplink_bytes, SUM(downlink_bytes) AS downlink_bytes
		 FROM user_traffic_daily
		 WHERE user_id = ? AND day >= ?
		 GROUP BY day ORDER BY day`,
		userID, time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")); err != nil {
		return nil, fmt.Errorf("store: user %d traffic history: %w", userID, err)
	}
	return out, nil
}

// NodeTrafficPoint is one day of a node's traffic.
type NodeTrafficPoint struct {
	Day           time.Time `db:"day"`
	UplinkBytes   uint64    `db:"uplink_bytes"`
	DownlinkBytes uint64    `db:"downlink_bytes"`
}

// NodeTrafficHistory returns a node's daily traffic over the last n days.
func (s *Store) NodeTrafficHistory(ctx context.Context, nodeID uint64, days int) ([]NodeTrafficPoint, error) {
	if days <= 0 {
		days = 30
	}
	var out []NodeTrafficPoint
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT day, SUM(uplink_bytes) AS uplink_bytes, SUM(downlink_bytes) AS downlink_bytes
		 FROM user_traffic_daily
		 WHERE node_id = ? AND day >= ?
		 GROUP BY day ORDER BY day`,
		nodeID, time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")); err != nil {
		return nil, fmt.Errorf("store: node %d traffic history: %w", nodeID, err)
	}
	return out, nil
}

// PruneTrafficBatches removes the idempotency ledger's old rows. They only
// have to outlive an agent's retry window.
func (s *Store) PruneTrafficBatches(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM traffic_batches WHERE received_at < ?`, time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, fmt.Errorf("store: prune traffic batches: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// PruneTrafficDaily removes daily traffic rows past the retention window.
func (s *Store) PruneTrafficDaily(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format("2006-01-02")
	res, err := s.DB.ExecContext(ctx, `DELETE FROM user_traffic_daily WHERE day < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: prune daily traffic: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}
