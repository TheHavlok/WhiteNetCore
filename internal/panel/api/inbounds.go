package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/thehavlok/whitenet/internal/panel/staterender"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the groups")
		return
	}
	counts, err := s.store.GroupCountsAll(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the group counts")
		return
	}
	byID := map[uint64]store.GroupCounts{}
	for _, entry := range counts {
		byID[entry.GroupID] = entry
	}

	out := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		entry := map[string]any{
			"id":          group.ID,
			"uuid":        group.UUID,
			"name":        group.Name,
			"description": group.Description.String,
			"sort_order":  group.SortOrder,
			"nodes":       byID[group.ID].Nodes,
			"users":       byID[group.ID].Users,
		}
		out = append(out, entry)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   int    `json:"sort_order"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeFieldError(w, codeBadRequest, "name", "a group needs a name")
		return
	}
	group, err := s.store.CreateGroup(r.Context(), req.Name, req.Description, req.SortOrder)
	if err != nil {
		s.writeStoreError(w, err, "the group")
		return
	}
	s.audit(r, "group.create", "group", group.UUID, map[string]any{"name": group.Name})
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id": group.ID, "uuid": group.UUID, "name": group.Name,
		"description": group.Description.String, "sort_order": group.SortOrder,
	})
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   int    `json:"sort_order"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	group, err := s.store.UpdateGroup(r.Context(), id, strings.TrimSpace(req.Name), req.Description, req.SortOrder)
	if err != nil {
		s.writeStoreError(w, err, "the group")
		return
	}
	s.audit(r, "group.update", "group", group.UUID, nil)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id": group.ID, "uuid": group.UUID, "name": group.Name,
		"description": group.Description.String, "sort_order": group.SortOrder,
	})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	group, err := s.store.GroupByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the group")
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the group")
		return
	}
	// Every node in that group now serves fewer users.
	s.pushStateToAll(r)
	s.audit(r, "group.delete", "group", group.UUID, map[string]any{"name": group.Name})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

// templateRequest is the shape the UI posts. Secrets arrive in the clear over
// https and are encrypted before they reach the database.
type templateRequest struct {
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`
	Network    string            `json:"network"`
	Security   string            `json:"security"`
	ListenPort *uint32           `json:"listen_port"`
	Params     map[string]string `json:"params"`
	Secrets    map[string]string `json:"secrets"`
	Enabled    *bool             `json:"enabled"`
}

func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.store.ListTemplates(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the templates")
		return
	}
	out := make([]map[string]any, 0, len(templates))
	for i := range templates {
		targets, err := s.store.TemplateTargets(r.Context(), templates[i].ID)
		if err != nil {
			s.writeStoreError(w, err, "the template targets")
			return
		}
		out = append(out, s.templateResponse(&templates[i], targets, false))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"templates": out})
}

func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	template, err := s.store.TemplateByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	targets, err := s.store.TemplateTargets(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the template targets")
		return
	}
	// The edit form needs the secrets, so this one endpoint returns them.
	s.writeJSON(w, http.StatusOK, s.templateResponse(template, targets, true))
}

func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req templateRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	template, ok := s.buildTemplate(w, r, req, nil)
	if !ok {
		return
	}
	created, err := s.store.CreateTemplate(r.Context(), *template)
	if err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	s.audit(r, "template.create", "template", created.UUID, map[string]any{
		"name": created.Name, "protocol": created.Protocol,
	})
	s.writeJSON(w, http.StatusCreated, s.templateResponse(created, nil, false))
}

func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	existing, err := s.store.TemplateByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	var req templateRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	template, ok := s.buildTemplate(w, r, req, existing)
	if !ok {
		return
	}
	updated, err := s.store.UpdateTemplate(r.Context(), id, *template)
	if err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	// Updating a template re-renders every instance, so every node that has
	// one needs the new state.
	s.pushStateToAll(r)
	s.audit(r, "template.update", "template", updated.UUID, nil)
	s.writeJSON(w, http.StatusOK, s.templateResponse(updated, nil, false))
}

func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	template, err := s.store.TemplateByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	if err := s.store.DeleteTemplate(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	s.pushStateToAll(r)
	s.audit(r, "template.delete", "template", template.UUID, map[string]any{"name": template.Name})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSetTemplateTargets applies a template to nodes and groups.
func (s *Server) handleSetTemplateTargets(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		NodeIDs  []uint64 `json:"node_ids"`
		GroupIDs []uint64 `json:"group_ids"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	template, err := s.store.TemplateByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the template")
		return
	}
	if err := s.store.SetTemplateTargets(r.Context(), id, req.NodeIDs, req.GroupIDs); err != nil {
		s.writeStoreError(w, err, "the template targets")
		return
	}
	s.pushStateToAll(r)
	s.audit(r, "template.set_targets", "template", template.UUID, map[string]any{
		"node_ids": req.NodeIDs, "group_ids": req.GroupIDs,
	})

	targets, err := s.store.TemplateTargets(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the template targets")
		return
	}
	s.writeJSON(w, http.StatusOK, s.templateResponse(template, targets, false))
}

// buildTemplate validates a request and encrypts its secrets.
//
// When editing, secrets the form left out keep their stored value: the UI
// shows a password field blank rather than echoing a key back, so an empty
// field means "unchanged", not "remove".
func (s *Server) buildTemplate(w http.ResponseWriter, r *http.Request, req templateRequest, existing *store.InboundTemplate) (*store.InboundTemplate, bool) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.writeFieldError(w, codeBadRequest, "name", "a template needs a name")
		return nil, false
	}
	if !validProtocol(req.Protocol) {
		s.writeFieldError(w, codeBadRequest, "protocol", "unknown protocol "+req.Protocol)
		return nil, false
	}
	security := req.Security
	if security == "" {
		security = "none"
	}
	if !validSecurity(security) {
		s.writeFieldError(w, codeBadRequest, "security", "security must be none, tls or reality")
		return nil, false
	}

	params := store.JSONMap{}
	for k, v := range req.Params {
		params[k] = v
	}
	secrets := map[string]string{}
	if existing != nil {
		stored, err := staterender.OpenSecrets(s.box, existing.Secrets)
		if err != nil {
			s.writeStoreError(w, err, "the template secrets")
			return nil, false
		}
		secrets = stored
	}
	for k, v := range req.Secrets {
		if v == "" {
			// An explicit empty value removes the secret; a key the form did
			// not send at all keeps its stored value.
			delete(secrets, k)
			continue
		}
		secrets[k] = v
	}

	if err := validateInbound(req.Protocol, req.Network, security, params, secrets); err != nil {
		s.writeFieldError(w, codeBadRequest, "params", err.Error())
		return nil, false
	}

	sealed, err := staterender.SealSecrets(s.box, secrets)
	if err != nil {
		s.writeStoreError(w, err, "the template secrets")
		return nil, false
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var port sql.NullInt64
	if req.ListenPort != nil && *req.ListenPort > 0 {
		port = sql.NullInt64{Int64: int64(*req.ListenPort), Valid: true}
	}

	return &store.InboundTemplate{
		Name:       name,
		Protocol:   req.Protocol,
		Network:    req.Network,
		Security:   security,
		ListenPort: port,
		Params:     params,
		Secrets:    sealed,
		Enabled:    enabled,
	}, true
}

func (s *Server) templateResponse(t *store.InboundTemplate, targets []store.TemplateTarget, includeSecrets bool) map[string]any {
	nodeIDs := []uint64{}
	groupIDs := []uint64{}
	for _, target := range targets {
		if target.NodeID.Valid {
			nodeIDs = append(nodeIDs, uint64(target.NodeID.Int64))
		}
		if target.GroupID.Valid {
			groupIDs = append(groupIDs, uint64(target.GroupID.Int64))
		}
	}

	out := map[string]any{
		"id":        t.ID,
		"uuid":      t.UUID,
		"name":      t.Name,
		"protocol":  t.Protocol,
		"network":   t.Network,
		"security":  t.Security,
		"params":    t.Params,
		"enabled":   t.Enabled,
		"node_ids":  nodeIDs,
		"group_ids": groupIDs,
	}
	if t.ListenPort.Valid {
		out["listen_port"] = t.ListenPort.Int64
	} else {
		out["listen_port"] = nil
	}
	if includeSecrets {
		secrets, err := staterender.OpenSecrets(s.box, t.Secrets)
		if err == nil {
			out["secrets"] = secrets
		}
	} else {
		// The list only says which secrets exist, not what they are.
		out["secret_keys"] = secretKeyNames(s.box, t.Secrets)
	}
	return out
}

// ---------------------------------------------------------------------------
// Per-node inbounds
// ---------------------------------------------------------------------------

func (s *Server) handleListInbounds(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	inbounds, err := s.store.NodeInbounds(r.Context(), nodeID)
	if err != nil {
		s.writeStoreError(w, err, "the inbounds")
		return
	}
	out := make([]map[string]any, 0, len(inbounds))
	for i := range inbounds {
		out = append(out, s.inboundResponse(&inbounds[i], false))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"inbounds": out})
}

func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Tag           string            `json:"tag"`
		Protocol      string            `json:"protocol"`
		Network       string            `json:"network"`
		Security      string            `json:"security"`
		ListenAddress string            `json:"listen_address"`
		ListenPort    uint32            `json:"listen_port"`
		Params        map[string]string `json:"params"`
		Secrets       map[string]string `json:"secrets"`
		ForwardToTag  string            `json:"forward_to_tag"`
		Published     *bool             `json:"published"`
		Enabled       *bool             `json:"enabled"`
		SortOrder     int               `json:"sort_order"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	tag := strings.TrimSpace(req.Tag)
	if err := validateTag(tag); err != nil {
		s.writeFieldError(w, codeBadRequest, "tag", err.Error())
		return
	}
	if !validProtocol(req.Protocol) {
		s.writeFieldError(w, codeBadRequest, "protocol", "unknown protocol "+req.Protocol)
		return
	}
	if req.ListenPort == 0 || req.ListenPort > 65535 {
		s.writeFieldError(w, codeBadRequest, "listen_port", "a port is 1 to 65535")
		return
	}
	security := req.Security
	if security == "" {
		security = "none"
	}
	if !validSecurity(security) {
		s.writeFieldError(w, codeBadRequest, "security", "security must be none, tls or reality")
		return
	}

	params := store.JSONMap{}
	for k, v := range req.Params {
		params[k] = v
	}
	secrets := map[string]string{}
	for k, v := range req.Secrets {
		if v != "" {
			secrets[k] = v
		}
	}
	if err := validateInbound(req.Protocol, req.Network, security, params, secrets); err != nil {
		s.writeFieldError(w, codeBadRequest, "params", err.Error())
		return
	}
	sealed, err := staterender.SealSecrets(s.box, secrets)
	if err != nil {
		s.writeStoreError(w, err, "the inbound secrets")
		return
	}

	published := true
	if req.Published != nil {
		published = *req.Published
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	// The inbound a DNS tunnel forwards into is internal: it must not appear
	// in anyone's subscription, or the chain would be bypassable.
	if req.ForwardToTag != "" && req.Protocol != store.ProtoWNDNS {
		s.writeFieldError(w, codeBadRequest, "forward_to_tag",
			"only a wndns inbound forwards into another one")
		return
	}

	inbound := store.NodeInbound{
		NodeID:        nodeID,
		Tag:           tag,
		Protocol:      req.Protocol,
		Network:       req.Network,
		Security:      security,
		ListenAddress: strings.TrimSpace(req.ListenAddress),
		ListenPort:    req.ListenPort,
		Overrides:     store.JSONMap{},
		Params:        params,
		Secrets:       sealed,
		Published:     published,
		Enabled:       enabled,
		SortOrder:     req.SortOrder,
	}
	if req.ForwardToTag != "" {
		inbound.ForwardToTag = sql.NullString{String: req.ForwardToTag, Valid: true}
	}

	created, err := s.store.CreateInbound(r.Context(), inbound)
	if err != nil {
		s.writeStoreError(w, err, "the inbound")
		return
	}
	s.pushState(r, nodeID)
	s.audit(r, "inbound.create", "inbound", fmt.Sprint(created.ID), map[string]any{
		"node_id": nodeID, "tag": created.Tag, "protocol": created.Protocol,
	})
	s.writeJSON(w, http.StatusCreated, s.inboundResponse(created, false))
}

func (s *Server) handleUpdateInbound(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	existing, err := s.store.InboundByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the inbound")
		return
	}

	var req struct {
		ListenAddress *string            `json:"listen_address"`
		ListenPort    *uint32            `json:"listen_port"`
		Overrides     *map[string]string `json:"overrides"`
		Params        *map[string]string `json:"params"`
		Secrets       *map[string]string `json:"secrets"`
		ForwardToTag  *string            `json:"forward_to_tag"`
		Published     *bool              `json:"published"`
		Enabled       *bool              `json:"enabled"`
		SortOrder     *int               `json:"sort_order"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	update := store.InboundUpdate{
		ListenAddress: req.ListenAddress,
		ListenPort:    req.ListenPort,
		ForwardToTag:  req.ForwardToTag,
		Published:     req.Published,
		Enabled:       req.Enabled,
		SortOrder:     req.SortOrder,
	}
	if req.Overrides != nil {
		overrides := store.JSONMap{}
		for k, v := range *req.Overrides {
			overrides[k] = v
		}
		update.Overrides = &overrides
	}
	if req.Params != nil {
		// A one-off inbound's parameters are edited directly; a template
		// instance's come from the template plus overrides, so sending params
		// for one would be overwritten on the next template change.
		if existing.TemplateID.Valid {
			s.writeFieldError(w, codeBadRequest, "params",
				"this inbound comes from a template; change the template, or set overrides on this node")
			return
		}
		params := store.JSONMap{}
		for k, v := range *req.Params {
			params[k] = v
		}
		update.Params = &params
	}
	if req.Secrets != nil {
		secrets, err := staterender.OpenSecrets(s.box, existing.Secrets)
		if err != nil {
			s.writeStoreError(w, err, "the inbound secrets")
			return
		}
		for k, v := range *req.Secrets {
			if v == "" {
				delete(secrets, k)
				continue
			}
			secrets[k] = v
		}
		sealed, err := staterender.SealSecrets(s.box, secrets)
		if err != nil {
			s.writeStoreError(w, err, "the inbound secrets")
			return
		}
		update.Secrets = &sealed
	}

	updated, err := s.store.UpdateInbound(r.Context(), id, update)
	if err != nil {
		s.writeStoreError(w, err, "the inbound")
		return
	}
	s.pushState(r, updated.NodeID)
	s.audit(r, "inbound.update", "inbound", fmt.Sprint(id), map[string]any{"tag": updated.Tag})
	s.writeJSON(w, http.StatusOK, s.inboundResponse(updated, false))
}

func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	inbound, err := s.store.InboundByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the inbound")
		return
	}
	if err := s.store.DeleteInbound(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the inbound")
		return
	}
	s.pushState(r, inbound.NodeID)
	s.audit(r, "inbound.delete", "inbound", fmt.Sprint(id), map[string]any{"tag": inbound.Tag})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) inboundResponse(in *store.NodeInbound, includeSecrets bool) map[string]any {
	out := map[string]any{
		"id":             in.ID,
		"node_id":        in.NodeID,
		"tag":            in.Tag,
		"protocol":       in.Protocol,
		"network":        in.Network,
		"security":       in.Security,
		"listen_address": in.ListenAddress,
		"listen_port":    in.ListenPort,
		"params":         in.Params,
		"overrides":      in.Overrides,
		"forward_to_tag": in.ForwardToTag.String,
		"published":      in.Published,
		"enabled":        in.Enabled,
		"sort_order":     in.SortOrder,
		"from_template":  in.TemplateID.Valid,
	}
	if in.TemplateID.Valid {
		out["template_id"] = in.TemplateID.Int64
	} else {
		out["template_id"] = nil
	}
	if includeSecrets {
		if secrets, err := staterender.OpenSecrets(s.box, in.Secrets); err == nil {
			out["secrets"] = secrets
		}
	} else {
		out["secret_keys"] = secretKeyNames(s.box, in.Secrets)
	}
	return out
}

// secretKeyNames lists which secrets an inbound has without revealing them, so
// the UI can show "Reality private key: set" without echoing it back.
func secretKeyNames(box *secretBox, encrypted []byte) []string {
	secrets, err := staterender.OpenSecrets(box, encrypted)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(secrets))
	for key := range secrets {
		out = append(out, key)
	}
	sortStrings(out)
	return out
}
