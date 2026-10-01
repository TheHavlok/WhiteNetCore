package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/nodepb"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the nodes")
		return
	}
	occupancy, err := s.store.Occupancy(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the flux pools")
		return
	}
	byNode := map[uint64]store.ChannelOccupancy{}
	for _, entry := range occupancy {
		byNode[entry.NodeID] = entry
	}

	out := make([]map[string]any, 0, len(nodes))
	for i := range nodes {
		node := nodes[i]
		groups, err := s.store.NodeGroupIDs(r.Context(), node.ID)
		if err != nil {
			s.writeStoreError(w, err, "the node's groups")
			return
		}
		entry := s.nodeResponse(&node, groups)
		if pool, ok := byNode[node.ID]; ok {
			entry["flux_pool"] = map[string]any{
				"total":           pool.Total,
				"leased":          pool.Leased,
				"active_sessions": pool.Active,
			}
		}
		out = append(out, entry)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	node, err := s.store.NodeByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	groups, err := s.store.NodeGroupIDs(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node's groups")
		return
	}
	s.writeJSON(w, http.StatusOK, s.nodeResponse(node, groups))
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Address     string   `json:"address"`
		CountryCode string   `json:"country_code"`
		GroupIDs    []uint64 `json:"group_ids"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeFieldError(w, codeBadRequest, "name", "a node needs a name")
		return
	}

	node, err := s.store.CreateNode(r.Context(), req.Name, strings.TrimSpace(req.Address),
		strings.ToUpper(strings.TrimSpace(req.CountryCode)), req.GroupIDs)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}

	// The install command comes back with the node, because adding a node and
	// getting the command are one action as far as an operator is concerned.
	command, err := s.installCommand(r, node)
	if err != nil {
		s.writeStoreError(w, err, "the install command")
		return
	}

	s.audit(r, "node.create", "node", node.UUID, map[string]any{"name": node.Name})
	groups, _ := s.store.NodeGroupIDs(r.Context(), node.ID)
	response := s.nodeResponse(node, groups)
	response["install"] = command
	s.writeJSON(w, http.StatusCreated, response)
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Name        *string   `json:"name"`
		Address     *string   `json:"address"`
		CountryCode *string   `json:"country_code"`
		DisplayName *string   `json:"display_name"`
		Notes       *string   `json:"notes"`
		Enabled     *bool     `json:"enabled"`
		GroupIDs    *[]uint64 `json:"group_ids"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	node, err := s.store.UpdateNode(r.Context(), id, store.NodeUpdate{
		Name:        req.Name,
		Address:     req.Address,
		CountryCode: req.CountryCode,
		DisplayName: req.DisplayName,
		Notes:       req.Notes,
		Enabled:     req.Enabled,
		GroupIDs:    req.GroupIDs,
	})
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}

	// The change is in the database; now tell the node, if it is listening.
	s.pushState(r, node.ID)

	s.audit(r, "node.update", "node", node.UUID, nil)
	groups, _ := s.store.NodeGroupIDs(r.Context(), id)
	s.writeJSON(w, http.StatusOK, s.nodeResponse(node, groups))
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	node, err := s.store.NodeByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	// Revoke first, so an agent that reconnects during the delete is refused
	// rather than served.
	if err := s.store.RevokeNodeCerts(r.Context(), id); err != nil {
		s.log.Warn("could not revoke the node's certificates", "node", node.UUID, "error", err)
	}
	s.rpc.Hub().Disconnect(id)

	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	s.audit(r, "node.delete", "node", node.UUID, map[string]any{"name": node.Name})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRevokeNode cuts a node off without deleting it: the certificates stop
// working and the connection is closed, but the configuration stays so it can
// be re-enrolled.
func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	node, err := s.store.NodeByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	if err := s.store.RevokeNodeCerts(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the certificates")
		return
	}
	s.rpc.Hub().Disconnect(id)
	if err := s.store.NodeDisconnected(r.Context(), id, "certificate revoked"); err != nil {
		s.log.Warn("could not record the disconnect", "node", node.UUID, "error", err)
	}

	s.audit(r, "node.revoke", "node", node.UUID, nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleInstallCommand returns a fresh one-time token and the command to run.
func (s *Server) handleInstallCommand(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	node, err := s.store.NodeByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	command, err := s.installCommand(r, node)
	if err != nil {
		s.writeStoreError(w, err, "the install command")
		return
	}
	s.audit(r, "node.install_token", "node", node.UUID, nil)
	s.writeJSON(w, http.StatusOK, command)
}

// installCommand mints a token and assembles everything the installer needs.
//
// The token is single use and short lived, and the CA fingerprint is in the
// command so the agent can verify the panel before it trusts anything it
// sends - which is what makes a one-line curl-to-bash install defensible.
func (s *Server) installCommand(r *http.Request, node *store.Node) (map[string]any, error) {
	admin := adminFromContext(r.Context())
	var adminID *uint64
	if admin != nil {
		adminID = &admin.ID
	}

	token, err := s.store.CreateNodeToken(r.Context(), node.ID, adminID, s.cfg.Node.TokenTTL.Duration())
	if err != nil {
		return nil, err
	}
	fingerprint, err := s.rpc.CAFingerprint(r.Context())
	if err != nil {
		return nil, err
	}

	domains, err := s.store.Domains(r.Context())
	if err != nil {
		return nil, err
	}
	panelURL := domains.PanelURL
	if panelURL == "" {
		// Fall back to however this request arrived, which is right often
		// enough that a fresh panel works before anything is configured.
		panelURL = requestBaseURL(r)
	}
	agentEndpoint := domains.AgentEndpoint
	if agentEndpoint == "" {
		agentEndpoint = s.cfg.GRPC.Advertise
	}
	if agentEndpoint == "" {
		agentEndpoint = defaultAgentEndpoint(panelURL, s.cfg.GRPC.Listen)
	}

	command := fmt.Sprintf(
		"curl -fsSL %s/install.sh | bash -s -- --token %s --main %s --ca-fingerprint %s",
		strings.TrimRight(panelURL, "/"), token, agentEndpoint, fingerprint)

	return map[string]any{
		"command":        command,
		"token":          token,
		"main":           agentEndpoint,
		"ca_fingerprint": fingerprint,
		"expires_at":     time.Now().UTC().Add(s.cfg.Node.TokenTTL.Duration()),
		"script_url":     strings.TrimRight(panelURL, "/") + "/install.sh",
	}, nil
}

// handleRestartCore restarts one of a node's cores.
func (s *Server) handleRestartCore(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Core string `json:"core"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	core, ok := parseCore(req.Core)
	if !ok {
		s.writeFieldError(w, codeBadRequest, "core", "core must be xray, wndns or openflux")
		return
	}
	node, err := s.store.NodeByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	if err := s.rpc.Hub().SendCommand(id, &nodepb.Command{
		CommandId: fmt.Sprintf("restart-%d-%d", id, time.Now().UnixNano()),
		Type:      nodepb.CommandType_COMMAND_RESTART_CORE,
		Core:      core,
	}); err != nil {
		s.writeStoreError(w, err, "the command")
		return
	}
	s.audit(r, "node.restart_core", "node", node.UUID, map[string]any{"core": req.Core})
	s.writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

// handleResyncNode bumps the node's version and pushes, which is the way out
// of a disagreement between the panel and a node about what is running.
func (s *Server) handleResyncNode(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	node, err := s.store.NodeByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	if err := s.store.BumpNodeVersion(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	s.pushState(r, id)
	s.audit(r, "node.resync", "node", node.UUID, nil)
	s.writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

// handleNodeLogs fetches a core's log from the node.
func (s *Server) handleNodeLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	core, ok := parseCore(r.URL.Query().Get("core"))
	if !ok {
		s.writeFieldError(w, codeBadRequest, "core", "core must be xray, wndns or openflux")
		return
	}
	lines := queryInt(r, "lines", 200)
	if lines < 1 || lines > 5000 {
		lines = 200
	}

	text, err := s.rpc.FetchLog(r.Context(), id, core, lines, 20*time.Second)
	if err != nil {
		s.writeStoreError(w, err, "the node's log")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"core": r.URL.Query().Get("core"), "text": text})
}

// handleNodeMetrics returns a node's charts.
//
// The window decides the source: up to a day comes from raw samples, longer
// from the hourly rollup, because scanning a week of raw samples for a chart
// that is 168 pixels wide is wasted work.
func (s *Server) handleNodeMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	window := r.URL.Query().Get("window")
	now := time.Now().UTC()

	switch window {
	case "", "hour":
		samples, err := s.store.MetricsRange(r.Context(), id, now.Add(-time.Hour), now)
		if err != nil {
			s.writeStoreError(w, err, "the metrics")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"window":     "hour",
			"resolution": "raw",
			"points":     rawPoints(samples),
		})

	case "day":
		samples, err := s.store.MetricsRange(r.Context(), id, now.Add(-24*time.Hour), now)
		if err != nil {
			s.writeStoreError(w, err, "the metrics")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"window":     "day",
			"resolution": "raw",
			"points":     rawPoints(samples),
		})

	case "week":
		points, err := s.store.HourlyRange(r.Context(), id, now.Add(-7*24*time.Hour), now)
		if err != nil {
			s.writeStoreError(w, err, "the metrics")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"window":     "week",
			"resolution": "hourly",
			"points":     hourlyPoints(points),
		})

	default:
		s.writeFieldError(w, codeBadRequest, "window", "window must be hour, day or week")
	}
}

func (s *Server) handleNodeTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	days := queryInt(r, "days", 30)
	points, err := s.store.NodeTrafficHistory(r.Context(), id, days)
	if err != nil {
		s.writeStoreError(w, err, "the traffic")
		return
	}
	out := make([]map[string]any, 0, len(points))
	for _, point := range points {
		out = append(out, map[string]any{
			"day":      point.Day.Format("2006-01-02"),
			"uplink":   point.UplinkBytes,
			"downlink": point.DownlinkBytes,
			"total":    point.UplinkBytes + point.DownlinkBytes,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"days": out})
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// pushState tells a node about a change. A node that is not connected is not
// an error: it will pick the state up when it reconnects, which is the whole
// point of the version number.
func (s *Server) pushState(r *http.Request, nodeID uint64) {
	if !s.rpc.Hub().Connected(nodeID) {
		return
	}
	if err := s.rpc.PushState(r.Context(), nodeID); err != nil {
		s.log.Warn("could not push the state to a node", "node", nodeID, "error", err)
	}
}

// pushStateToAll pushes to every connected node whose version has moved, for a
// change that affects more than one.
func (s *Server) pushStateToAll(r *http.Request) {
	s.rpc.PushToConnected(r.Context())
}

func (s *Server) nodeResponse(node *store.Node, groupIDs []uint64) map[string]any {
	if groupIDs == nil {
		groupIDs = []uint64{}
	}
	return map[string]any{
		"id":            node.ID,
		"uuid":          node.UUID,
		"name":          node.Name,
		"display_name":  node.DisplayName.String,
		"address":       node.Address,
		"country_code":  node.CountryCode.String,
		"notes":         node.Notes.String,
		"enabled":       node.Enabled,
		"status":        node.Status,
		"status_reason": node.StatusReason.String,
		"connected":     s.rpc.Hub().Connected(node.ID),
		"last_seen_at":  nullTime(node.LastSeenAt),
		"connected_at":  nullTime(node.ConnectedAt),

		"config_version":  node.ConfigVersion,
		"applied_version": node.AppliedVersion,
		"in_sync":         node.InSync(),
		"apply_error":     node.ApplyError.String,

		"agent_version":    node.AgentVersion.String,
		"xray_version":     node.XrayVersion.String,
		"wndns_version":    node.WNDNSVersion.String,
		"openflux_version": node.OpenFluxVersion.String,

		"hostname":        node.Hostname.String,
		"os":              node.OS.String,
		"arch":            node.Arch.String,
		"cpu_cores":       nullInt64(node.CPUCores),
		"mem_total_bytes": nullInt64(node.MemTotalBytes),
		"online_users":    node.OnlineUsers,

		"group_ids":  groupIDs,
		"created_at": node.CreatedAt,
	}
}

func rawPoints(samples []store.MetricSample) []map[string]any {
	out := make([]map[string]any, 0, len(samples))
	for _, sample := range samples {
		out = append(out, map[string]any{
			"at":           sample.At,
			"cpu_percent":  nullFloat(sample.CPUPercent),
			"load1":        nullFloat(sample.Load1),
			"mem_used":     nullInt64(sample.MemUsedBytes),
			"mem_total":    nullInt64(sample.MemTotalBytes),
			"disk_used":    nullInt64(sample.DiskUsedBytes),
			"disk_total":   nullInt64(sample.DiskTotalBytes),
			"net_rx":       nullInt64(sample.NetRxBytes),
			"net_tx":       nullInt64(sample.NetTxBytes),
			"uptime":       nullInt64(sample.UptimeSeconds),
			"online_users": nullInt64(sample.OnlineUsers),
			"tcp_conns":    nullInt64(sample.TCPConnections),
		})
	}
	return out
}

func hourlyPoints(points []store.HourlyPoint) []map[string]any {
	out := make([]map[string]any, 0, len(points))
	for _, point := range points {
		out = append(out, map[string]any{
			"at":               point.Hour,
			"samples":          point.Samples,
			"cpu_percent":      nullFloat(point.CPUPercentAvg),
			"cpu_percent_max":  nullFloat(point.CPUPercentMax),
			"mem_used":         nullInt64(point.MemUsedAvg),
			"disk_used":        nullInt64(point.DiskUsedMax),
			"net_rx_delta":     nullInt64(point.NetRxDelta),
			"net_tx_delta":     nullInt64(point.NetTxDelta),
			"online_users":     nullFloat(point.OnlineUsersAvg),
			"online_users_max": nullInt64(point.OnlineUsersMax),
		})
	}
	return out
}

func parseCore(name string) (nodepb.Core, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "xray":
		return nodepb.Core_CORE_XRAY, true
	case "wndns", "dns":
		return nodepb.Core_CORE_WNDNS, true
	case "openflux", "flux":
		return nodepb.Core_CORE_OPENFLUX, true
	default:
		return nodepb.Core_CORE_UNSPECIFIED, false
	}
}

// requestBaseURL reconstructs the panel's own URL from a request, for a fresh
// panel where the domain settings are still empty.
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

// defaultAgentEndpoint guesses the agent endpoint from the panel's URL and the
// configured listen address: the same host, the gRPC port.
func defaultAgentEndpoint(panelURL, listen string) string {
	host := panelURL
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	if h, _, err := splitHostPort(host); err == nil && h != "" {
		host = h
	}
	_, port, err := splitHostPort(listen)
	if err != nil || port == "" {
		port = "8443"
	}
	return host + ":" + port
}

func splitHostPort(address string) (host, port string, err error) {
	host, port, found := strings.Cut(address, ":")
	if !found {
		return address, "", nil
	}
	return host, port, nil
}

func nullTime(v sql.NullTime) any {
	if !v.Valid {
		return nil
	}
	return v.Time
}

func nullInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func nullFloat(v sql.NullFloat64) any {
	if !v.Valid {
		return nil
	}
	return v.Float64
}
