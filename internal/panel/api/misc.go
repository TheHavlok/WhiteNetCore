package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/keygen"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

// handleDashboard is the one query the landing page needs, so it does not have
// to fan out into a dozen requests.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the nodes")
		return
	}
	var online, offline, degraded, outOfSync int
	var onlineUsers uint32
	for _, node := range nodes {
		switch node.Status {
		case store.NodeOnline:
			online++
		case store.NodeDegraded:
			degraded++
		default:
			offline++
		}
		if !node.InSync() {
			outOfSync++
		}
		onlineUsers += node.OnlineUsers
	}

	// Only the counts matter here, so the limit is one row each: the filter
	// returns the total that matched regardless of the limit.
	_, total, err := s.store.ListUsers(r.Context(), store.UserFilter{Limit: 1})
	if err != nil {
		s.writeStoreError(w, err, "the users")
		return
	}
	_, activeCount, err := s.store.ListUsers(r.Context(), store.UserFilter{Status: store.UserActive, Limit: 1})
	if err != nil {
		s.writeStoreError(w, err, "the users")
		return
	}
	_, expiringCount, err := s.store.ListUsers(r.Context(), store.UserFilter{
		Status: store.UserActive, ExpiringWithin: 7 * 24 * time.Hour, Limit: 1,
	})
	if err != nil {
		s.writeStoreError(w, err, "the users")
		return
	}

	// Traffic over the last week, summed across nodes.
	var weekTraffic uint64
	for _, node := range nodes {
		points, err := s.store.NodeTrafficHistory(r.Context(), node.ID, 7)
		if err != nil {
			continue
		}
		for _, point := range points {
			weekTraffic += point.UplinkBytes + point.DownlinkBytes
		}
	}

	occupancy, err := s.store.Occupancy(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the flux pools")
		return
	}
	var fluxTotal, fluxLeased, fluxActive int
	for _, entry := range occupancy {
		fluxTotal += entry.Total
		fluxLeased += entry.Leased
		fluxActive += entry.Active
	}

	events, _, err := s.store.ListEvents(r.Context(), store.EventFilter{Limit: 10})
	if err != nil {
		s.writeStoreError(w, err, "the events")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"nodes": map[string]any{
			"total":       len(nodes),
			"online":      online,
			"offline":     offline,
			"degraded":    degraded,
			"out_of_sync": outOfSync,
		},
		"users": map[string]any{
			"total":            total,
			"active":           activeCount,
			"expiring_in_week": expiringCount,
			"online_now":       onlineUsers,
		},
		"traffic": map[string]any{
			"last_7_days_bytes": weekTraffic,
		},
		"flux": map[string]any{
			"channels":        fluxTotal,
			"leased":          fluxLeased,
			"active_sessions": fluxActive,
		},
		"recent_events": eventsResponse(events),
	})
}

// ---------------------------------------------------------------------------
// Events and audit
// ---------------------------------------------------------------------------

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	filter := store.EventFilter{
		Severity: r.URL.Query().Get("severity"),
		Type:     r.URL.Query().Get("type"),
		Limit:    queryInt(r, "limit", 100),
		Offset:   queryInt(r, "offset", 0),
	}
	if nodeID := queryInt(r, "node_id", 0); nodeID > 0 {
		filter.NodeID = uint64(nodeID)
	}
	if userID := queryInt(r, "user_id", 0); userID > 0 {
		filter.UserID = uint64(userID)
	}
	if hours := queryInt(r, "hours", 0); hours > 0 {
		filter.Since = time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	}

	events, total, err := s.store.ListEvents(r.Context(), filter)
	if err != nil {
		s.writeStoreError(w, err, "the events")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"events": eventsResponse(events),
		"total":  total,
	})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	filter := store.AuditFilter{
		Action:     r.URL.Query().Get("action"),
		ObjectType: r.URL.Query().Get("object_type"),
		ObjectID:   r.URL.Query().Get("object_id"),
		Limit:      queryInt(r, "limit", 100),
		Offset:     queryInt(r, "offset", 0),
	}
	if adminID := queryInt(r, "admin_id", 0); adminID > 0 {
		filter.AdminID = uint64(adminID)
	}
	if hours := queryInt(r, "hours", 0); hours > 0 {
		filter.Since = time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	}

	entries, total, err := s.store.ListAudit(r.Context(), filter)
	if err != nil {
		s.writeStoreError(w, err, "the audit log")
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, map[string]any{
			"id":          entry.ID,
			"at":          entry.At,
			"admin":       entry.AdminUsername.String,
			"action":      entry.Action,
			"object_type": entry.ObjectType.String,
			"object_id":   entry.ObjectID.String,
			"ip":          entry.IP.String,
			"details":     entry.Details,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"entries": out, "total": total})
}

func eventsResponse(events []store.Event) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for _, event := range events {
		entry := map[string]any{
			"id":       event.ID,
			"at":       event.At,
			"severity": event.Severity,
			"type":     event.Type,
			"core":     event.Core.String,
			"message":  event.Message,
			"details":  event.Details,
		}
		if event.NodeID.Valid {
			entry["node_id"] = event.NodeID.Int64
		}
		if event.UserID.Valid {
			entry["user_id"] = event.UserID.Int64
		}
		out = append(out, entry)
	}
	return out
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	branding, err := s.store.Branding(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the settings")
		return
	}
	domains, err := s.store.Domains(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the settings")
		return
	}
	defaults, err := s.store.UserDefaults(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the settings")
		return
	}
	subscription, err := s.store.SubscriptionSettings(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the settings")
		return
	}
	fingerprint, err := s.rpc.CAFingerprint(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the certificate authority")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"branding":       branding,
		"domains":        domains,
		"user_defaults":  defaults,
		"subscription":   subscription,
		"ca_fingerprint": fingerprint,
	})
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Branding     *store.Branding             `json:"branding"`
		Domains      *store.Domains              `json:"domains"`
		UserDefaults *store.UserDefaults         `json:"user_defaults"`
		Subscription *store.SubscriptionSettings `json:"subscription"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if req.Branding != nil {
		if err := s.store.SetSetting(r.Context(), store.SettingBranding, req.Branding); err != nil {
			s.writeStoreError(w, err, "the branding")
			return
		}
	}
	if req.Domains != nil {
		if err := s.store.SetSetting(r.Context(), store.SettingDomains, req.Domains); err != nil {
			s.writeStoreError(w, err, "the domains")
			return
		}
	}
	if req.UserDefaults != nil {
		if err := s.store.SetSetting(r.Context(), store.SettingUserDefaults, req.UserDefaults); err != nil {
			s.writeStoreError(w, err, "the defaults")
			return
		}
	}
	if req.Subscription != nil {
		if req.Subscription.UpdateIntervalHours <= 0 {
			s.writeFieldError(w, codeBadRequest, "subscription.update_interval_hours",
				"the refresh interval must be at least one hour")
			return
		}
		if err := s.store.SetSetting(r.Context(), store.SettingSubscription, req.Subscription); err != nil {
			s.writeStoreError(w, err, "the subscription settings")
			return
		}
	}

	s.audit(r, "settings.update", "settings", "", nil)
	s.handleGetSettings(w, r)
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

func (s *Server) handleGenerateReality(w http.ResponseWriter, r *http.Request) {
	pair, err := keygen.NewRealityKeyPair()
	if err != nil {
		s.writeStoreError(w, err, "the key pair")
		return
	}
	// A set of short ids comes with it: an inbound needs at least one, and
	// generating them together is one button instead of two.
	shortIDs, err := keygen.NewShortIDs(4, 8)
	if err != nil {
		s.writeStoreError(w, err, "the short ids")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"private_key": pair.PrivateKey,
		"public_key":  pair.PublicKey,
		"short_ids":   shortIDs,
	})
}

func (s *Server) handleGenerateShortID(w http.ResponseWriter, r *http.Request) {
	count := queryInt(r, "count", 1)
	if count < 1 || count > 16 {
		count = 1
	}
	size := queryInt(r, "bytes", 8)
	ids, err := keygen.NewShortIDs(count, size)
	if err != nil {
		s.writeFieldError(w, codeBadRequest, "bytes", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"short_ids": ids})
}

func (s *Server) handleGenerateUUID(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"uuid": keygen.NewUUID()})
}

func (s *Server) handleGeneratePassword(w http.ResponseWriter, r *http.Request) {
	password, err := keygen.NewPassword()
	if err != nil {
		s.writeStoreError(w, err, "the password")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"password": password})
}

func (s *Server) handleGenerateShadowsocks(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Query().Get("method")
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	key, err := keygen.NewShadowsocks2022Key(method)
	if err != nil {
		s.writeFieldError(w, codeBadRequest, "method", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"method":    method,
		"password":  key,
		"multiuser": keygen.SupportsMultipleUsers(method),
	})
}

func (s *Server) handleGenerateFluxSecret(w http.ResponseWriter, r *http.Request) {
	secretValue, err := keygen.NewFluxSecret()
	if err != nil {
		s.writeStoreError(w, err, "the secret")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"secret": secretValue})
}

func base64PNG(png []byte) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}
