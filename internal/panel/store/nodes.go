package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// ErrNotFound is returned when a row that was asked for by id does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrTokenSpent is returned when an enrolment token has already been used or
// has expired. Both are the same answer to an agent: this token is no good.
var ErrTokenSpent = errors.New("store: the enrolment token is not usable")

const nodeColumns = `id, uuid, name, address, country_code, display_name, notes,
	enabled, status, status_reason, last_seen_at, connected_at,
	config_version, applied_version, apply_error,
	agent_version, xray_version, wndns_version, openflux_version,
	hostname, os, arch, cpu_cores, mem_total_bytes, online_users,
	created_at, updated_at`

// CreateNode inserts a node. The uuid is generated here rather than taken
// from the caller, because it is what agent certificates are issued for.
func (s *Store) CreateNode(ctx context.Context, name, address string, countryCode string, groupIDs []uint64) (*Node, error) {
	nodeUUID := uuid.NewString()
	var id uint64
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO nodes (uuid, name, address, country_code) VALUES (?, ?, ?, ?)`,
			nodeUUID, name, address, nullString(countryCode))
		if err != nil {
			return fmt.Errorf("store: create node: %w", err)
		}
		lastID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: create node: %w", err)
		}
		id = uint64(lastID)
		return setNodeGroupsTx(ctx, tx, id, groupIDs)
	})
	if err != nil {
		return nil, err
	}
	return s.NodeByID(ctx, id)
}

// NodeByID reads one node.
func (s *Store) NodeByID(ctx context.Context, id uint64) (*Node, error) {
	var node Node
	err := s.DB.GetContext(ctx, &node, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: node %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: node %d: %w", id, err)
	}
	return &node, nil
}

// NodeByUUID reads one node by the uuid its certificate asserts. This is the
// lookup the gRPC server does on every connection, so the uuid column is
// unique and indexed.
func (s *Store) NodeByUUID(ctx context.Context, nodeUUID string) (*Node, error) {
	var node Node
	err := s.DB.GetContext(ctx, &node, `SELECT `+nodeColumns+` FROM nodes WHERE uuid = ?`, nodeUUID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: node %s: %w", nodeUUID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: node %s: %w", nodeUUID, err)
	}
	return &node, nil
}

// ListNodes returns every node, newest last so the list is stable as nodes are
// added.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	var nodes []Node
	if err := s.DB.SelectContext(ctx, &nodes,
		`SELECT `+nodeColumns+` FROM nodes ORDER BY name, id`); err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	return nodes, nil
}

// NodeUpdate carries the fields an admin may change. A nil field is left
// alone, which is what lets the API accept a partial update without reading
// the row first.
type NodeUpdate struct {
	Name        *string
	Address     *string
	CountryCode *string
	DisplayName *string
	Notes       *string
	Enabled     *bool
	GroupIDs    *[]uint64
}

// UpdateNode applies an update and bumps the configuration version when
// something a node cares about changed.
func (s *Store) UpdateNode(ctx context.Context, id uint64, update NodeUpdate) (*Node, error) {
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		var sets []string
		var args []any
		add := func(column string, value any) {
			sets = append(sets, column+" = ?")
			args = append(args, value)
		}
		if update.Name != nil {
			add("name", *update.Name)
		}
		if update.Address != nil {
			add("address", *update.Address)
		}
		if update.CountryCode != nil {
			add("country_code", nullString(*update.CountryCode))
		}
		if update.DisplayName != nil {
			add("display_name", nullString(*update.DisplayName))
		}
		if update.Notes != nil {
			add("notes", nullString(*update.Notes))
		}
		if update.Enabled != nil {
			add("enabled", *update.Enabled)
		}
		if len(sets) > 0 {
			args = append(args, id)
			if _, err := tx.ExecContext(ctx,
				`UPDATE nodes SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...); err != nil {
				return fmt.Errorf("store: update node %d: %w", id, err)
			}
		}
		if update.GroupIDs != nil {
			if err := setNodeGroupsTx(ctx, tx, id, *update.GroupIDs); err != nil {
				return err
			}
		}
		// Groups decide which users a node serves, and `enabled` decides
		// whether it serves anyone, so either one changes the desired state.
		if update.GroupIDs != nil || update.Enabled != nil {
			return bumpNodeVersionTx(ctx, tx, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.NodeByID(ctx, id)
}

// DeleteNode removes a node and everything that belongs to it. The schema's
// cascades take care of inbounds, channels, metrics and certificates.
func (s *Store) DeleteNode(ctx context.Context, id uint64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete node %d: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return fmt.Errorf("store: node %d: %w", id, ErrNotFound)
	}
	return nil
}

func setNodeGroupsTx(ctx context.Context, tx *sqlx.Tx, nodeID uint64, groupIDs []uint64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_group_members WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("store: clear node groups: %w", err)
	}
	for _, groupID := range groupIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_group_members (node_id, group_id) VALUES (?, ?)`, nodeID, groupID); err != nil {
			return fmt.Errorf("store: add node %d to group %d: %w", nodeID, groupID, err)
		}
	}
	return nil
}

// NodeGroupIDs returns the groups a node belongs to.
func (s *Store) NodeGroupIDs(ctx context.Context, nodeID uint64) ([]uint64, error) {
	var ids []uint64
	if err := s.DB.SelectContext(ctx, &ids,
		`SELECT group_id FROM node_group_members WHERE node_id = ? ORDER BY group_id`, nodeID); err != nil {
		return nil, fmt.Errorf("store: node %d groups: %w", nodeID, err)
	}
	return ids, nil
}

// NodeGroupNames returns the group names a node belongs to, for the
// subscription's group field.
func (s *Store) NodeGroupNames(ctx context.Context, nodeID uint64) ([]string, error) {
	var names []string
	if err := s.DB.SelectContext(ctx, &names,
		`SELECT g.name FROM node_groups g
		 JOIN node_group_members m ON m.group_id = g.id
		 WHERE m.node_id = ? ORDER BY g.sort_order, g.name`, nodeID); err != nil {
		return nil, fmt.Errorf("store: node %d group names: %w", nodeID, err)
	}
	return names, nil
}

// BumpNodeVersion increases a node's configuration version, which is what
// makes the agent apply a new state. Every change that affects a node must go
// through this, or the node keeps serving the old configuration.
func (s *Store) BumpNodeVersion(ctx context.Context, nodeID uint64) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error { return bumpNodeVersionTx(ctx, tx, nodeID) })
}

func bumpNodeVersionTx(ctx context.Context, tx *sqlx.Tx, nodeID uint64) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE nodes SET config_version = config_version + 1 WHERE id = ?`, nodeID); err != nil {
		return fmt.Errorf("store: bump node %d version: %w", nodeID, err)
	}
	return nil
}

// BumpAllNodeVersions bumps every enabled node, for a change that affects the
// whole fleet - a user's limits, a group membership, a template.
func (s *Store) BumpAllNodeVersions(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE nodes SET config_version = config_version + 1`); err != nil {
		return fmt.Errorf("store: bump every node version: %w", err)
	}
	return nil
}

// BumpNodeVersionsInGroups bumps the nodes in the given groups. This is the
// common case: a user's group changed, so only the nodes they can reach need a
// new state.
func (s *Store) BumpNodeVersionsInGroups(ctx context.Context, groupIDs []uint64) error {
	if len(groupIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In(
		`UPDATE nodes SET config_version = config_version + 1
		 WHERE id IN (SELECT node_id FROM node_group_members WHERE group_id IN (?))`, groupIDs)
	if err != nil {
		return fmt.Errorf("store: bump nodes in groups: %w", err)
	}
	if _, err := s.DB.ExecContext(ctx, s.DB.Rebind(query), args...); err != nil {
		return fmt.Errorf("store: bump nodes in groups: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Enrolment tokens
// ---------------------------------------------------------------------------

// CreateNodeToken mints a single-use enrolment token and returns the
// plaintext, which is shown once and never stored.
func (s *Store) CreateNodeToken(ctx context.Context, nodeID uint64, adminID *uint64, ttl time.Duration) (plaintext string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: generate token: %w", err)
	}
	// URL-safe, because it travels in a curl command.
	plaintext = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))

	var createdBy any
	if adminID != nil {
		createdBy = *adminID
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO node_tokens (token_hash, node_id, created_by, expires_at) VALUES (?, ?, ?, ?)`,
		sum[:], nodeID, createdBy, time.Now().UTC().Add(ttl)); err != nil {
		return "", fmt.Errorf("store: create node token: %w", err)
	}
	return plaintext, nil
}

// SpendNodeToken checks a token and marks it used, returning the node it
// enrols.
//
// Everything happens in one transaction with a locking read, so two agents
// racing with the same token cannot both enrol: the second finds it spent.
func (s *Store) SpendNodeToken(ctx context.Context, plaintext, fromIP string) (*Node, error) {
	sum := sha256.Sum256([]byte(plaintext))
	var nodeID uint64
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		var row struct {
			ID        uint64       `db:"id"`
			NodeID    uint64       `db:"node_id"`
			ExpiresAt time.Time    `db:"expires_at"`
			UsedAt    sql.NullTime `db:"used_at"`
		}
		err := tx.GetContext(ctx, &row,
			`SELECT id, node_id, expires_at, used_at FROM node_tokens WHERE token_hash = ? FOR UPDATE`, sum[:])
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenSpent
		}
		if err != nil {
			return fmt.Errorf("store: read node token: %w", err)
		}
		if row.UsedAt.Valid {
			return ErrTokenSpent
		}
		if time.Now().UTC().After(row.ExpiresAt) {
			return ErrTokenSpent
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE node_tokens SET used_at = ?, used_ip = ? WHERE id = ?`,
			time.Now().UTC(), nullString(fromIP), row.ID); err != nil {
			return fmt.Errorf("store: spend node token: %w", err)
		}
		nodeID = row.NodeID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.NodeByID(ctx, nodeID)
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

// RecordNodeCert stores a certificate the CA issued, so a node can be
// de-authorised before it expires and the panel can warn before one lapses.
func (s *Store) RecordNodeCert(ctx context.Context, nodeID uint64, serial string, fingerprint []byte, certPEM string, notBefore, notAfter time.Time) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO node_certs (node_id, serial, fingerprint, cert_pem, not_before, not_after)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		nodeID, serial, fingerprint, certPEM, notBefore, notAfter); err != nil {
		return fmt.Errorf("store: record node certificate: %w", err)
	}
	return nil
}

// RevokeNodeCerts marks every certificate of a node revoked. The gRPC server
// checks this, so a revoked node is refused at the next connection even though
// its certificate still verifies.
func (s *Store) RevokeNodeCerts(ctx context.Context, nodeID uint64) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE node_certs SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), nodeID); err != nil {
		return fmt.Errorf("store: revoke node %d certificates: %w", nodeID, err)
	}
	return nil
}

// CertRevoked reports whether a specific certificate was revoked.
func (s *Store) CertRevoked(ctx context.Context, fingerprint []byte) (bool, error) {
	var revoked sql.NullTime
	err := s.DB.GetContext(ctx, &revoked,
		`SELECT revoked_at FROM node_certs WHERE fingerprint = ? ORDER BY id DESC LIMIT 1`, fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		// A certificate the panel has no record of is not trusted: it was
		// either issued by a CA that is no longer current, or the row was
		// removed with the node.
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: certificate status: %w", err)
	}
	return revoked.Valid, nil
}

// ---------------------------------------------------------------------------
// Heartbeat and status
// ---------------------------------------------------------------------------

// NodeConnected records that an agent opened a stream.
func (s *Store) NodeConnected(ctx context.Context, nodeID uint64, agentVersion, xrayVersion, wndnsVersion, fluxVersion string, host NodeHost) error {
	now := time.Now().UTC()
	_, err := s.DB.ExecContext(ctx,
		`UPDATE nodes SET
			status = ?, status_reason = NULL,
			connected_at = ?, last_seen_at = ?,
			agent_version = ?, xray_version = ?, wndns_version = ?, openflux_version = ?,
			hostname = ?, os = ?, arch = ?, cpu_cores = ?, mem_total_bytes = ?
		 WHERE id = ?`,
		NodeOnline, now, now,
		// Versions are whatever a core's banner said, and a core that gets
		// chattier must not break a node's heartbeat, so they are clipped to
		// the column rather than trusted to fit.
		nullString(clip(agentVersion, 64)), nullString(clip(xrayVersion, 64)),
		nullString(clip(wndnsVersion, 64)), nullString(clip(fluxVersion, 64)),
		nullString(clip(host.Hostname, 255)), nullString(clip(host.OS, 64)), nullString(clip(host.Arch, 32)),
		nullInt64(int64(host.CPUCores)), nullInt64(int64(host.MemTotalBytes)),
		nodeID)
	if err != nil {
		return fmt.Errorf("store: node %d connected: %w", nodeID, err)
	}
	return nil
}

// NodeHost is the host information an agent reports on connect.
type NodeHost struct {
	Hostname      string
	OS            string
	Arch          string
	CPUCores      uint32
	MemTotalBytes uint64
}

// NodeHeartbeat records a heartbeat.
func (s *Store) NodeHeartbeat(ctx context.Context, nodeID uint64, onlineUsers uint32, degradedReason string) error {
	status := NodeOnline
	var reason any
	if degradedReason != "" {
		status = NodeDegraded
		reason = degradedReason
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE nodes SET status = ?, status_reason = ?, last_seen_at = ?, online_users = ? WHERE id = ?`,
		status, reason, time.Now().UTC(), onlineUsers, nodeID)
	if err != nil {
		return fmt.Errorf("store: node %d heartbeat: %w", nodeID, err)
	}
	return nil
}

// NodeDisconnected records that the stream closed.
func (s *Store) NodeDisconnected(ctx context.Context, nodeID uint64, reason string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE nodes SET status = ?, status_reason = ?, online_users = 0 WHERE id = ?`,
		NodeOffline, nullString(reason), nodeID)
	if err != nil {
		return fmt.Errorf("store: node %d disconnected: %w", nodeID, err)
	}
	return nil
}

// MarkStaleNodesOffline moves nodes that stopped sending heartbeats to
// offline.
//
// This is what makes a node that was killed rather than shut down show up as
// offline: nothing closed its stream, so only the missing heartbeats say so.
func (s *Store) MarkStaleNodesOffline(ctx context.Context, after time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-after)
	res, err := s.DB.ExecContext(ctx,
		`UPDATE nodes SET status = ?, status_reason = ?, online_users = 0
		 WHERE status <> ? AND (last_seen_at IS NULL OR last_seen_at < ?)`,
		NodeOffline, "no heartbeat", NodeOffline, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: mark stale nodes offline: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// SetNodeApplied records the version an agent confirmed, and the error when it
// could not.
func (s *Store) SetNodeApplied(ctx context.Context, nodeID uint64, version uint64, applyError string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE nodes SET applied_version = ?, apply_error = ? WHERE id = ?`,
		version, nullString(applyError), nodeID)
	if err != nil {
		return fmt.Errorf("store: node %d applied version: %w", nodeID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Desired state snapshots
// ---------------------------------------------------------------------------

// SaveDesiredState stores the rendered state for a version.
//
// Keeping the snapshot makes a reconnect a single read instead of a re-render,
// and makes "what did we actually send that node" answerable afterwards.
func (s *Store) SaveDesiredState(ctx context.Context, nodeID, version uint64, payload []byte) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO node_desired_state (node_id, version, payload) VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE payload = VALUES(payload)`,
		nodeID, version, payload); err != nil {
		return fmt.Errorf("store: save desired state for node %d: %w", nodeID, err)
	}
	return nil
}

// DesiredState reads a stored snapshot.
func (s *Store) DesiredState(ctx context.Context, nodeID, version uint64) ([]byte, error) {
	var payload []byte
	err := s.DB.GetContext(ctx, &payload,
		`SELECT payload FROM node_desired_state WHERE node_id = ? AND version = ?`, nodeID, version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: desired state %d/%d: %w", nodeID, version, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: desired state %d/%d: %w", nodeID, version, err)
	}
	return payload, nil
}

// PruneDesiredStates keeps the newest few snapshots per node. Older ones are
// only of forensic interest and they carry secrets, so they do not live
// forever.
func (s *Store) PruneDesiredStates(ctx context.Context, keep int) error {
	if keep < 1 {
		keep = 1
	}
	// One statement per node, because MariaDB cannot delete from a table it
	// is selecting a window over.
	var nodeIDs []uint64
	if err := s.DB.SelectContext(ctx, &nodeIDs, `SELECT DISTINCT node_id FROM node_desired_state`); err != nil {
		return fmt.Errorf("store: prune desired states: %w", err)
	}
	for _, nodeID := range nodeIDs {
		var cutoff uint64
		err := s.DB.GetContext(ctx, &cutoff,
			`SELECT version FROM node_desired_state WHERE node_id = ? ORDER BY version DESC LIMIT 1 OFFSET ?`,
			nodeID, keep-1)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("store: prune desired states for node %d: %w", nodeID, err)
		}
		if _, err := s.DB.ExecContext(ctx,
			`DELETE FROM node_desired_state WHERE node_id = ? AND version < ?`, nodeID, cutoff); err != nil {
			return fmt.Errorf("store: prune desired states for node %d: %w", nodeID, err)
		}
	}
	return nil
}

// clip shortens a value to what its column holds. A value that does not fit
// is a cosmetic problem; an insert that fails over it is not.
func clip(v string, max int) string {
	if len(v) <= max {
		return v
	}
	return v[:max]
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
