package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

// InsertMetrics stores a batch of samples from one node.
func (s *Store) InsertMetrics(ctx context.Context, nodeID uint64, samples []MetricSample) error {
	if len(samples) == 0 {
		return nil
	}
	// One multi-row insert: a node reporting every 30 seconds is not much, but
	// a fleet of them doing it one statement at a time is pointless chatter.
	placeholders := make([]string, 0, len(samples))
	args := make([]any, 0, len(samples)*13)
	for _, sample := range samples {
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		args = append(args,
			nodeID, sample.At.UTC(),
			sample.CPUPercent, sample.Load1,
			sample.MemUsedBytes, sample.MemTotalBytes,
			sample.DiskUsedBytes, sample.DiskTotalBytes,
			sample.NetRxBytes, sample.NetTxBytes,
			sample.UptimeSeconds, sample.OnlineUsers, sample.TCPConnections)
	}
	query := `INSERT INTO node_metrics
		(node_id, at, cpu_percent, load1, mem_used_bytes, mem_total_bytes,
		 disk_used_bytes, disk_total_bytes, net_rx_bytes, net_tx_bytes,
		 uptime_seconds, online_users, tcp_connections)
		VALUES ` + strings.Join(placeholders, ", ")
	if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("store: insert metrics for node %d: %w", nodeID, err)
	}
	return nil
}

// MetricsRange returns raw samples for a window, for the hour and day charts.
func (s *Store) MetricsRange(ctx context.Context, nodeID uint64, from, to time.Time) ([]MetricSample, error) {
	var out []MetricSample
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT node_id, at, cpu_percent, load1, mem_used_bytes, mem_total_bytes,
			disk_used_bytes, disk_total_bytes, net_rx_bytes, net_tx_bytes,
			uptime_seconds, online_users, tcp_connections
		 FROM node_metrics WHERE node_id = ? AND at BETWEEN ? AND ? ORDER BY at`,
		nodeID, from.UTC(), to.UTC()); err != nil {
		return nil, fmt.Errorf("store: metrics for node %d: %w", nodeID, err)
	}
	return out, nil
}

// HourlyPoint is one row of the rollup.
type HourlyPoint struct {
	NodeID         uint64          `db:"node_id"`
	Hour           time.Time       `db:"hour"`
	Samples        uint32          `db:"samples"`
	CPUPercentAvg  sql.NullFloat64 `db:"cpu_percent_avg"`
	CPUPercentMax  sql.NullFloat64 `db:"cpu_percent_max"`
	MemUsedAvg     sql.NullInt64   `db:"mem_used_avg"`
	DiskUsedMax    sql.NullInt64   `db:"disk_used_max"`
	NetRxDelta     sql.NullInt64   `db:"net_rx_delta"`
	NetTxDelta     sql.NullInt64   `db:"net_tx_delta"`
	OnlineUsersAvg sql.NullFloat64 `db:"online_users_avg"`
	OnlineUsersMax sql.NullInt64   `db:"online_users_max"`
}

// RollupHourly folds raw samples into the hourly table.
//
// The network columns are absolute counters, so the hourly figure is the
// difference between the first and last sample in the hour. An hour in which
// the node rebooted therefore shows a smaller delta rather than a negative
// one, which is the honest answer: the counters restarted and the traffic
// before the reboot is in the previous hour.
func (s *Store) RollupHourly(ctx context.Context, until time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO node_metrics_hourly
			(node_id, hour, samples, cpu_percent_avg, cpu_percent_max, mem_used_avg,
			 disk_used_max, net_rx_delta, net_tx_delta, online_users_avg, online_users_max)
		 SELECT node_id,
			DATE_FORMAT(at, '%Y-%m-%d %H:00:00') AS hour,
			COUNT(*),
			AVG(cpu_percent), MAX(cpu_percent), AVG(mem_used_bytes),
			MAX(disk_used_bytes),
			GREATEST(CAST(MAX(net_rx_bytes) AS SIGNED) - CAST(MIN(net_rx_bytes) AS SIGNED), 0),
			GREATEST(CAST(MAX(net_tx_bytes) AS SIGNED) - CAST(MIN(net_tx_bytes) AS SIGNED), 0),
			AVG(online_users), MAX(online_users)
		 FROM node_metrics
		 WHERE at < ?
		 GROUP BY node_id, hour
		 ON DUPLICATE KEY UPDATE
			samples = VALUES(samples),
			cpu_percent_avg = VALUES(cpu_percent_avg),
			cpu_percent_max = VALUES(cpu_percent_max),
			mem_used_avg = VALUES(mem_used_avg),
			disk_used_max = VALUES(disk_used_max),
			net_rx_delta = VALUES(net_rx_delta),
			net_tx_delta = VALUES(net_tx_delta),
			online_users_avg = VALUES(online_users_avg),
			online_users_max = VALUES(online_users_max)`,
		until.UTC())
	if err != nil {
		return 0, fmt.Errorf("store: roll up metrics: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// HourlyRange returns the rollup for a window, for the week chart.
func (s *Store) HourlyRange(ctx context.Context, nodeID uint64, from, to time.Time) ([]HourlyPoint, error) {
	var out []HourlyPoint
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT node_id, hour, samples, cpu_percent_avg, cpu_percent_max, mem_used_avg,
			disk_used_max, net_rx_delta, net_tx_delta, online_users_avg, online_users_max
		 FROM node_metrics_hourly WHERE node_id = ? AND hour BETWEEN ? AND ? ORDER BY hour`,
		nodeID, from.UTC(), to.UTC()); err != nil {
		return nil, fmt.Errorf("store: hourly metrics for node %d: %w", nodeID, err)
	}
	return out, nil
}

// PruneMetrics removes raw samples past the retention window. This is the only
// table that grows on its own, so this is where disk use is bounded.
func (s *Store) PruneMetrics(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM node_metrics WHERE at < ?`, time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, fmt.Errorf("store: prune metrics: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// PruneHourlyMetrics removes rollup rows past the retention window.
func (s *Store) PruneHourlyMetrics(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM node_metrics_hourly WHERE hour < ?`, time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, fmt.Errorf("store: prune hourly metrics: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// NewEvent is an entry for the fleet journal.
type NewEvent struct {
	At       time.Time
	Severity string
	Type     string
	Core     string
	NodeID   *uint64
	UserID   *uint64
	Message  string
	Details  map[string]any
}

// RecordEvent appends to the journal.
func (s *Store) RecordEvent(ctx context.Context, event NewEvent) error {
	at := event.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	severity := event.Severity
	if severity == "" {
		severity = "info"
	}

	var details any
	if len(event.Details) > 0 {
		raw, err := json.Marshal(event.Details)
		if err != nil {
			return fmt.Errorf("store: marshal event details: %w", err)
		}
		details = string(raw)
	}
	var nodeID, userID any
	if event.NodeID != nil {
		nodeID = *event.NodeID
	}
	if event.UserID != nil {
		userID = *event.UserID
	}

	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO events (at, severity, type, core, node_id, user_id, message, details)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		at.UTC(), severity, event.Type, nullString(event.Core), nodeID, userID,
		truncate(event.Message, 1024), details); err != nil {
		return fmt.Errorf("store: record event: %w", err)
	}
	return nil
}

// EventFilter narrows the journal.
type EventFilter struct {
	NodeID   uint64
	UserID   uint64
	Severity string
	Type     string
	Since    time.Time
	Limit    int
	Offset   int
}

// ListEvents reads the journal, newest first.
func (s *Store) ListEvents(ctx context.Context, filter EventFilter) ([]Event, int, error) {
	var where []string
	var args []any
	if filter.NodeID != 0 {
		where = append(where, "node_id = ?")
		args = append(args, filter.NodeID)
	}
	if filter.UserID != 0 {
		where = append(where, "user_id = ?")
		args = append(args, filter.UserID)
	}
	if filter.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, filter.Severity)
	}
	if filter.Type != "" {
		where = append(where, "type = ?")
		args = append(args, filter.Type)
	}
	if !filter.Since.IsZero() {
		where = append(where, "at >= ?")
		args = append(args, filter.Since.UTC())
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.DB.GetContext(ctx, &total, `SELECT COUNT(*) FROM events`+clause, args...); err != nil {
		return nil, 0, fmt.Errorf("store: count events: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, at, severity, type, core, node_id, user_id, message, details
		 FROM events` + clause + fmt.Sprintf(" ORDER BY at DESC, id DESC LIMIT %d OFFSET %d", limit, filter.Offset)

	var out []Event
	if err := s.DB.SelectContext(ctx, &out, query, args...); err != nil {
		return nil, 0, fmt.Errorf("store: list events: %w", err)
	}
	return out, total, nil
}

// PruneEvents removes journal entries past the retention window.
func (s *Store) PruneEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM events WHERE at < ?`, time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, fmt.Errorf("store: prune events: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// ---------------------------------------------------------------------------
// Admin audit
// ---------------------------------------------------------------------------

// NewAudit is an entry for the audit log.
type NewAudit struct {
	AdminID       *uint64
	AdminUsername string
	Action        string
	ObjectType    string
	ObjectID      string
	IP            string
	Details       map[string]any
}

// RecordAudit appends to the audit log. Unlike the journal, this is never
// pruned by the metrics retention job: it is about accountability.
func (s *Store) RecordAudit(ctx context.Context, entry NewAudit) error {
	var details any
	if len(entry.Details) > 0 {
		raw, err := json.Marshal(entry.Details)
		if err != nil {
			return fmt.Errorf("store: marshal audit details: %w", err)
		}
		details = string(raw)
	}
	var adminID any
	if entry.AdminID != nil {
		adminID = *entry.AdminID
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO admin_audit (admin_id, admin_username, action, object_type, object_id, ip, details)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		adminID, nullString(entry.AdminUsername), entry.Action,
		nullString(entry.ObjectType), nullString(entry.ObjectID), nullString(entry.IP), details); err != nil {
		return fmt.Errorf("store: record audit entry: %w", err)
	}
	return nil
}

// AuditFilter narrows the audit log.
type AuditFilter struct {
	AdminID    uint64
	Action     string
	ObjectType string
	ObjectID   string
	Since      time.Time
	Limit      int
	Offset     int
}

// ListAudit reads the audit log, newest first.
func (s *Store) ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEntry, int, error) {
	var where []string
	var args []any
	if filter.AdminID != 0 {
		where = append(where, "admin_id = ?")
		args = append(args, filter.AdminID)
	}
	if filter.Action != "" {
		where = append(where, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.ObjectType != "" {
		where = append(where, "object_type = ?")
		args = append(args, filter.ObjectType)
	}
	if filter.ObjectID != "" {
		where = append(where, "object_id = ?")
		args = append(args, filter.ObjectID)
	}
	if !filter.Since.IsZero() {
		where = append(where, "at >= ?")
		args = append(args, filter.Since.UTC())
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.DB.GetContext(ctx, &total, `SELECT COUNT(*) FROM admin_audit`+clause, args...); err != nil {
		return nil, 0, fmt.Errorf("store: count audit entries: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, at, admin_id, admin_username, action, object_type, object_id, ip, details
		 FROM admin_audit` + clause + fmt.Sprintf(" ORDER BY at DESC, id DESC LIMIT %d OFFSET %d", limit, filter.Offset)

	var out []AuditEntry
	if err := s.DB.SelectContext(ctx, &out, query, args...); err != nil {
		return nil, 0, fmt.Errorf("store: list audit entries: %w", err)
	}
	return out, total, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
