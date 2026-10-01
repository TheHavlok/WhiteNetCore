package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	"github.com/thehavlok/whitenet/internal/panel/keygen"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// handleGetNodeFlux returns a node's exit configuration and its pool.
func (s *Server) handleGetNodeFlux(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	cfg, err := s.store.NodeOpenFluxConfig(r.Context(), nodeID)
	if err != nil {
		s.writeStoreError(w, err, "the flux configuration")
		return
	}
	out := map[string]any{"enabled": false, "mode": "l4", "params": store.JSONMap{}}
	if cfg != nil {
		out = map[string]any{"enabled": cfg.Enabled, "mode": cfg.Mode, "params": cfg.Params}
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleSetNodeFlux configures the exit process.
func (s *Server) handleSetNodeFlux(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Enabled bool              `json:"enabled"`
		Mode    string            `json:"mode"`
		Params  map[string]string `json:"params"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "l4"
	}
	if mode != "l3" && mode != "l4" {
		s.writeFieldError(w, codeBadRequest, "mode", "mode must be l3 or l4")
		return
	}

	node, err := s.store.NodeByID(r.Context(), nodeID)
	if err != nil {
		s.writeStoreError(w, err, "the node")
		return
	}
	// l3 is Linux-only and needs raw sockets. Saying so here saves an
	// operator from a node that reports a failure they cannot interpret.
	if mode == "l3" && node.OS.Valid && !strings.EqualFold(node.OS.String, "linux") {
		s.writeFieldError(w, codeBadRequest, "mode",
			"the l3 exit needs Linux and root; use l4 on this node")
		return
	}

	params := store.JSONMap{}
	for k, v := range req.Params {
		params[k] = v
	}
	if err := s.store.SetNodeOpenFlux(r.Context(), nodeID, req.Enabled, mode, params); err != nil {
		s.writeStoreError(w, err, "the flux configuration")
		return
	}
	s.pushState(r, nodeID)

	s.audit(r, "flux.configure", "node", node.UUID,
		map[string]any{"enabled": req.Enabled, "mode": mode})
	response := map[string]any{"enabled": req.Enabled, "mode": mode, "params": params}
	if mode == "l3" {
		// SNAT makes the kernel answer return packets with RST, which tears
		// the tunnel's flows down. The rule has to be installed on the node.
		response["warning"] = "the l3 exit needs an outbound RST filter on the node; " +
			"see docs/panel/PROTOCOLS.md"
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	channels, err := s.store.NodeChannels(r.Context(), nodeID)
	if err != nil {
		s.writeStoreError(w, err, "the channels")
		return
	}
	out := make([]map[string]any, 0, len(channels))
	for i := range channels {
		out = append(out, s.channelResponse(&channels[i], false))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"channels": out})
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Name           string            `json:"name"`
		Transport      string            `json:"transport"`
		URL            string            `json:"url"`
		Params         map[string]string `json:"params"`
		Secret         string            `json:"secret"`
		SessionContext string            `json:"session_context"`
		Credentials    map[string]string `json:"credentials"`
		Enabled        *bool             `json:"enabled"`
		// Count creates several identical channels at once, which is the
		// usual way to size a pool: ten documents for ten concurrent users.
		Count int `json:"count"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	params := map[string]string{}
	for k, v := range req.Params {
		params[k] = v
	}
	// A channel with no secret runs unauthenticated, so one is generated
	// rather than left empty.
	channelSecret := strings.TrimSpace(req.Secret)
	if channelSecret == "" {
		generated, err := keygen.NewFluxSecret()
		if err != nil {
			s.writeStoreError(w, err, "the channel secret")
			return
		}
		channelSecret = generated
	}
	if err := validateChannel(req.Transport, req.URL, params, channelSecret); err != nil {
		s.writeFieldError(w, codeBadRequest, "transport", err.Error())
		return
	}

	// Both peers derive the key from the same context, so it defaults to the
	// document URL - exactly what the flux stack does when none is given.
	sessionContext := strings.TrimSpace(req.SessionContext)
	if sessionContext == "" {
		sessionContext = req.URL
	}

	sealedSecret, err := s.box.SealString(channelSecret)
	if err != nil {
		s.writeStoreError(w, err, "the channel secret")
		return
	}
	var sealedCredentials []byte
	if len(req.Credentials) > 0 {
		raw, err := json.Marshal(req.Credentials)
		if err != nil {
			s.writeStoreError(w, err, "the channel credentials")
			return
		}
		sealedCredentials, err = s.box.Seal(raw)
		if err != nil {
			s.writeStoreError(w, err, "the channel credentials")
			return
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	count := req.Count
	if count < 1 {
		count = 1
	}
	if count > 100 {
		s.writeFieldError(w, codeBadRequest, "count", "at most 100 channels at a time")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Transport
	}

	created := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		channelName := name
		if count > 1 {
			channelName = fmt.Sprintf("%s %d", name, i+1)
		}
		// Each channel gets its own secret: sharing one would mean a revoked
		// channel takes the whole pool with it.
		secretValue := channelSecret
		if i > 0 {
			generated, err := keygen.NewFluxSecret()
			if err != nil {
				s.writeStoreError(w, err, "the channel secret")
				return
			}
			secretValue = generated
			sealedSecret, err = s.box.SealString(secretValue)
			if err != nil {
				s.writeStoreError(w, err, "the channel secret")
				return
			}
		}

		channel, err := s.store.CreateChannel(r.Context(), store.OpenFluxChannel{
			NodeID:         nodeID,
			Name:           channelName,
			Transport:      req.Transport,
			URL:            req.URL,
			Params:         toJSONMap(params),
			EncryptionKey:  sealedSecret,
			SessionContext: sql.NullString{String: sessionContext, Valid: sessionContext != ""},
			Credentials:    sealedCredentials,
			Enabled:        enabled,
		})
		if err != nil {
			s.writeStoreError(w, err, "the channel")
			return
		}
		created = append(created, s.channelResponse(channel, false))
	}

	s.pushState(r, nodeID)
	s.audit(r, "flux.create_channel", "node", fmt.Sprint(nodeID),
		map[string]any{"transport": req.Transport, "count": count})
	s.writeJSON(w, http.StatusCreated, map[string]any{"channels": created})
}

func (s *Server) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	existing, err := s.store.ChannelByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the channel")
		return
	}
	var req struct {
		Name           *string            `json:"name"`
		Transport      *string            `json:"transport"`
		URL            *string            `json:"url"`
		Params         *map[string]string `json:"params"`
		Secret         *string            `json:"secret"`
		SessionContext *string            `json:"session_context"`
		Credentials    *map[string]string `json:"credentials"`
		Enabled        *bool              `json:"enabled"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	update := store.ChannelUpdate{
		Name:           req.Name,
		Transport:      req.Transport,
		URL:            req.URL,
		SessionContext: req.SessionContext,
		Enabled:        req.Enabled,
	}
	if req.Params != nil {
		params := toJSONMap(*req.Params)
		update.Params = &params
	}
	if req.Secret != nil && *req.Secret != "" {
		sealed, err := s.box.SealString(*req.Secret)
		if err != nil {
			s.writeStoreError(w, err, "the channel secret")
			return
		}
		update.EncryptionKey = &sealed
	}
	if req.Credentials != nil {
		raw, err := json.Marshal(*req.Credentials)
		if err != nil {
			s.writeStoreError(w, err, "the channel credentials")
			return
		}
		sealed, err := s.box.Seal(raw)
		if err != nil {
			s.writeStoreError(w, err, "the channel credentials")
			return
		}
		update.Credentials = &sealed
	}

	// Validate the result rather than the request, so a partial update cannot
	// leave a channel that will not start.
	transport := existing.Transport
	if req.Transport != nil {
		transport = *req.Transport
	}
	url := existing.URL
	if req.URL != nil {
		url = *req.URL
	}
	params := map[string]string(existing.Params)
	if req.Params != nil {
		params = *req.Params
	}
	secretValue, err := s.box.OpenString(existing.EncryptionKey)
	if err != nil {
		s.writeStoreError(w, err, "the channel secret")
		return
	}
	if req.Secret != nil && *req.Secret != "" {
		secretValue = *req.Secret
	}
	if err := validateChannel(transport, url, params, secretValue); err != nil {
		s.writeFieldError(w, codeBadRequest, "transport", err.Error())
		return
	}

	channel, err := s.store.UpdateChannel(r.Context(), id, update)
	if err != nil {
		s.writeStoreError(w, err, "the channel")
		return
	}
	s.pushState(r, channel.NodeID)
	s.audit(r, "flux.update_channel", "channel", channel.UUID, nil)
	s.writeJSON(w, http.StatusOK, s.channelResponse(channel, false))
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	channel, err := s.store.ChannelByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the channel")
		return
	}
	if err := s.store.DeleteChannel(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the channel")
		return
	}
	s.pushState(r, channel.NodeID)
	s.audit(r, "flux.delete_channel", "channel", channel.UUID, nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRotateChannel gives a channel a new secret.
//
// This is how a lease is revoked the hard way: the agent restarts the channel
// with the new key and whoever was connected stops decrypting.
func (s *Server) handleRotateChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	channel, err := s.store.ChannelByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the channel")
		return
	}
	newSecret, err := keygen.NewFluxSecret()
	if err != nil {
		s.writeStoreError(w, err, "the channel secret")
		return
	}
	sealed, err := s.box.SealString(newSecret)
	if err != nil {
		s.writeStoreError(w, err, "the channel secret")
		return
	}
	updated, err := s.store.UpdateChannel(r.Context(), id, store.ChannelUpdate{EncryptionKey: &sealed})
	if err != nil {
		s.writeStoreError(w, err, "the channel")
		return
	}
	s.pushState(r, updated.NodeID)
	s.audit(r, "flux.rotate_channel", "channel", channel.UUID, nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) channelResponse(c *store.OpenFluxChannel, includeSecret bool) map[string]any {
	out := map[string]any{
		"id":              c.ID,
		"uuid":            c.UUID,
		"node_id":         c.NodeID,
		"name":            c.Name,
		"transport":       c.Transport,
		"url":             c.URL,
		"params":          c.Params,
		"session_context": c.SessionContext.String,
		"enabled":         c.Enabled,
		"session_active":  c.SessionActive,
		"last_error":      c.LastError.String,
		"has_secret":      len(c.EncryptionKey) > 0,
		"created_at":      c.CreatedAt,
	}
	// A channel's secret is a bearer credential for the exit, so it is shown
	// only where it is needed: the share-link builder asks for it explicitly.
	if includeSecret {
		if value, err := s.box.OpenString(c.EncryptionKey); err == nil {
			out["secret"] = value
		}
	}
	// The carrier's own label, so a list reads as names rather than slugs.
	if meta, ok := carrierLabels[c.Transport]; ok && meta.Label != "" {
		out["transport_label"] = meta.Label
	}
	// Whether this carrier may appear in a share link: MAX cannot, because
	// the token belongs to the exit's own account.
	out["shareable"] = c.Transport != fluxnode.CarrierOneMe
	return out
}

func toJSONMap(in map[string]string) store.JSONMap {
	out := store.JSONMap{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
