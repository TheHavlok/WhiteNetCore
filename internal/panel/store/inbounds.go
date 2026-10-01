package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

const templateColumns = `id, uuid, name, protocol, network, security, listen_port,
	params, secrets, enabled, created_at, updated_at`

const inboundColumns = `id, node_id, template_id, tag, protocol, network, security,
	listen_address, listen_port, overrides, params, secrets,
	forward_to_tag, published, enabled, sort_order, created_at, updated_at`

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

// CreateTemplate stores a reusable inbound definition.
func (s *Store) CreateTemplate(ctx context.Context, t InboundTemplate) (*InboundTemplate, error) {
	templateUUID := uuid.NewString()
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO inbound_templates (uuid, name, protocol, network, security, listen_port, params, secrets, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		templateUUID, t.Name, t.Protocol, t.Network, t.Security, t.ListenPort,
		t.Params, nullBytes(t.Secrets), t.Enabled)
	if err != nil {
		return nil, fmt.Errorf("store: create template: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.TemplateByID(ctx, uint64(id))
}

// TemplateByID reads one template.
func (s *Store) TemplateByID(ctx context.Context, id uint64) (*InboundTemplate, error) {
	var t InboundTemplate
	err := s.DB.GetContext(ctx, &t, `SELECT `+templateColumns+` FROM inbound_templates WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: template %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: template %d: %w", id, err)
	}
	return &t, nil
}

// ListTemplates returns every template.
func (s *Store) ListTemplates(ctx context.Context) ([]InboundTemplate, error) {
	var out []InboundTemplate
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT `+templateColumns+` FROM inbound_templates ORDER BY name`); err != nil {
		return nil, fmt.Errorf("store: list templates: %w", err)
	}
	return out, nil
}

// UpdateTemplate replaces a template's definition and bumps every node that
// has an inbound from it, so the change actually reaches the fleet.
func (s *Store) UpdateTemplate(ctx context.Context, id uint64, t InboundTemplate) (*InboundTemplate, error) {
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE inbound_templates SET name = ?, protocol = ?, network = ?, security = ?,
			 listen_port = ?, params = ?, secrets = ?, enabled = ? WHERE id = ?`,
			t.Name, t.Protocol, t.Network, t.Security, t.ListenPort,
			t.Params, nullBytes(t.Secrets), t.Enabled, id); err != nil {
			return fmt.Errorf("store: update template %d: %w", id, err)
		}
		// Re-render the instances: the effective parameters are
		// template + overrides, computed on write so the agent gets them
		// resolved.
		if err := reapplyTemplateTx(ctx, tx, id); err != nil {
			return err
		}
		return bumpTemplateNodesTx(ctx, tx, id)
	})
	if err != nil {
		return nil, err
	}
	return s.TemplateByID(ctx, id)
}

// DeleteTemplate removes a template. The instances it created stay, with their
// template link cleared: deleting a template must not take a node's inbounds
// down with it.
func (s *Store) DeleteTemplate(ctx context.Context, id uint64) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error {
		if err := bumpTemplateNodesTx(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inbound_templates WHERE id = ?`, id); err != nil {
			return fmt.Errorf("store: delete template %d: %w", id, err)
		}
		return nil
	})
}

// TemplateTarget is where a template applies.
type TemplateTarget struct {
	ID         uint64        `db:"id"`
	TemplateID uint64        `db:"template_id"`
	TargetKind string        `db:"target_kind"`
	NodeID     sql.NullInt64 `db:"node_id"`
	GroupID    sql.NullInt64 `db:"group_id"`
}

// SetTemplateTargets replaces a template's targets and reconciles the
// instances: an inbound is created on every node now in scope and removed from
// the nodes that are not.
func (s *Store) SetTemplateTargets(ctx context.Context, templateID uint64, nodeIDs, groupIDs []uint64) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error {
		// Bump the nodes that are losing the template too, so they stop
		// serving it.
		if err := bumpTemplateNodesTx(ctx, tx, templateID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM inbound_template_targets WHERE template_id = ?`, templateID); err != nil {
			return fmt.Errorf("store: clear template targets: %w", err)
		}
		for _, nodeID := range nodeIDs {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO inbound_template_targets (template_id, target_kind, node_id)
				 VALUES (?, 'node', ?)`, templateID, nodeID); err != nil {
				return fmt.Errorf("store: target template at node %d: %w", nodeID, err)
			}
		}
		for _, groupID := range groupIDs {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO inbound_template_targets (template_id, target_kind, group_id)
				 VALUES (?, 'group', ?)`, templateID, groupID); err != nil {
				return fmt.Errorf("store: target template at group %d: %w", groupID, err)
			}
		}
		if err := reapplyTemplateTx(ctx, tx, templateID); err != nil {
			return err
		}
		return bumpTemplateNodesTx(ctx, tx, templateID)
	})
}

// TemplateTargets reads a template's targets.
func (s *Store) TemplateTargets(ctx context.Context, templateID uint64) ([]TemplateTarget, error) {
	var out []TemplateTarget
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT id, template_id, target_kind, node_id, group_id
		 FROM inbound_template_targets WHERE template_id = ? ORDER BY id`, templateID); err != nil {
		return nil, fmt.Errorf("store: template %d targets: %w", templateID, err)
	}
	return out, nil
}

// reapplyTemplateTx makes the instances match the template's targets.
//
// A node that is in scope gets an inbound if it has none from this template;
// one that is out of scope loses it. A node's overrides survive, because
// re-targeting a template must not discard the port someone set on a node.
func reapplyTemplateTx(ctx context.Context, tx *sqlx.Tx, templateID uint64) error {
	var t InboundTemplate
	err := tx.GetContext(ctx, &t, `SELECT `+templateColumns+` FROM inbound_templates WHERE id = ?`, templateID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: read template %d: %w", templateID, err)
	}

	var wantedNodes []uint64
	if err := tx.SelectContext(ctx, &wantedNodes,
		`SELECT DISTINCT n.id FROM nodes n
		 LEFT JOIN node_group_members m ON m.node_id = n.id
		 JOIN inbound_template_targets t ON
		   (t.target_kind = 'node' AND t.node_id = n.id) OR
		   (t.target_kind = 'group' AND t.group_id = m.group_id)
		 WHERE t.template_id = ?`, templateID); err != nil {
		return fmt.Errorf("store: template %d scope: %w", templateID, err)
	}

	wanted := map[uint64]bool{}
	for _, nodeID := range wantedNodes {
		wanted[nodeID] = true
	}

	var existing []NodeInbound
	if err := tx.SelectContext(ctx, &existing,
		`SELECT `+inboundColumns+` FROM node_inbounds WHERE template_id = ?`, templateID); err != nil {
		return fmt.Errorf("store: template %d instances: %w", templateID, err)
	}

	have := map[uint64]NodeInbound{}
	for _, inbound := range existing {
		have[inbound.NodeID] = inbound
		if !wanted[inbound.NodeID] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM node_inbounds WHERE id = ?`, inbound.ID); err != nil {
				return fmt.Errorf("store: remove template instance %d: %w", inbound.ID, err)
			}
		}
	}

	for nodeID := range wanted {
		existingInbound, present := have[nodeID]
		overrides := JSONMap{}
		if present {
			overrides = existingInbound.Overrides
		}
		effective := t.Params.Merge(overrides)

		port := uint32(0)
		if t.ListenPort.Valid {
			port = uint32(t.ListenPort.Int64)
		}
		if v := overrides["listen_port"]; v != "" {
			port = uint32(atoiOr(v, int(port)))
		}
		if port == 0 {
			return fmt.Errorf("store: template %s has no port and node %d does not override one", t.Name, nodeID)
		}

		if present {
			if _, err := tx.ExecContext(ctx,
				`UPDATE node_inbounds SET protocol = ?, network = ?, security = ?,
				 listen_port = ?, params = ?, secrets = ?, enabled = ? WHERE id = ?`,
				t.Protocol, t.Network, t.Security, port, effective, nullBytes(t.Secrets),
				t.Enabled, existingInbound.ID); err != nil {
				return fmt.Errorf("store: update template instance %d: %w", existingInbound.ID, err)
			}
			continue
		}

		tag := templateTag(t.Name, port)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_inbounds (node_id, template_id, tag, protocol, network, security,
				listen_port, overrides, params, secrets, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			nodeID, templateID, tag, t.Protocol, t.Network, t.Security,
			port, overrides, effective, nullBytes(t.Secrets), t.Enabled); err != nil {
			return fmt.Errorf("store: create template instance on node %d: %w", nodeID, err)
		}
	}
	return nil
}

// templateTag builds the Xray tag for a template instance. It includes the
// port so two instances of different templates cannot collide, and it is
// stable because traffic counters are keyed by it.
func templateTag(templateName string, port uint32) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == ' ' || r == '_':
			return '-'
		default:
			return -1
		}
	}, templateName)
	if slug == "" {
		slug = "inbound"
	}
	if len(slug) > 40 {
		slug = slug[:40]
	}
	return fmt.Sprintf("%s-%d", slug, port)
}

func bumpTemplateNodesTx(ctx context.Context, tx *sqlx.Tx, templateID uint64) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE nodes SET config_version = config_version + 1
		 WHERE id IN (SELECT node_id FROM node_inbounds WHERE template_id = ?)`, templateID); err != nil {
		return fmt.Errorf("store: bump template %d nodes: %w", templateID, err)
	}
	// Nodes newly in scope have no instance yet, so they are bumped by target
	// as well.
	if _, err := tx.ExecContext(ctx,
		`UPDATE nodes SET config_version = config_version + 1
		 WHERE id IN (
			SELECT DISTINCT n.id FROM nodes n
			LEFT JOIN node_group_members m ON m.node_id = n.id
			JOIN inbound_template_targets t ON
			  (t.target_kind = 'node' AND t.node_id = n.id) OR
			  (t.target_kind = 'group' AND t.group_id = m.group_id)
			WHERE t.template_id = ?
		 )`, templateID); err != nil {
		return fmt.Errorf("store: bump template %d target nodes: %w", templateID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Per-node inbounds
// ---------------------------------------------------------------------------

// CreateInbound adds a one-off inbound to a node.
func (s *Store) CreateInbound(ctx context.Context, in NodeInbound) (*NodeInbound, error) {
	var id uint64
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO node_inbounds (node_id, template_id, tag, protocol, network, security,
				listen_address, listen_port, overrides, params, secrets,
				forward_to_tag, published, enabled, sort_order)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.NodeID, in.TemplateID, in.Tag, in.Protocol, in.Network, in.Security,
			in.ListenAddress, in.ListenPort, in.Overrides, in.Params, nullBytes(in.Secrets),
			in.ForwardToTag, in.Published, in.Enabled, in.SortOrder)
		if err != nil {
			return fmt.Errorf("store: create inbound: %w", err)
		}
		lastID, _ := res.LastInsertId()
		id = uint64(lastID)
		return bumpNodeVersionTx(ctx, tx, in.NodeID)
	})
	if err != nil {
		return nil, err
	}
	return s.InboundByID(ctx, id)
}

// InboundByID reads one inbound.
func (s *Store) InboundByID(ctx context.Context, id uint64) (*NodeInbound, error) {
	var in NodeInbound
	err := s.DB.GetContext(ctx, &in, `SELECT `+inboundColumns+` FROM node_inbounds WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: inbound %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: inbound %d: %w", id, err)
	}
	return &in, nil
}

// NodeInbounds returns a node's inbounds in display order.
func (s *Store) NodeInbounds(ctx context.Context, nodeID uint64) ([]NodeInbound, error) {
	var out []NodeInbound
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT `+inboundColumns+` FROM node_inbounds WHERE node_id = ? ORDER BY sort_order, tag`,
		nodeID); err != nil {
		return nil, fmt.Errorf("store: node %d inbounds: %w", nodeID, err)
	}
	return out, nil
}

// InboundUpdate is the partial update the API accepts.
type InboundUpdate struct {
	ListenAddress *string
	ListenPort    *uint32
	Overrides     *JSONMap
	Params        *JSONMap
	Secrets       *[]byte
	ForwardToTag  *string
	Published     *bool
	Enabled       *bool
	SortOrder     *int
}

// UpdateInbound applies an update.
//
// For a template instance the overrides are what change, and the effective
// parameters are recomputed from the template so the agent never has to merge
// anything.
func (s *Store) UpdateInbound(ctx context.Context, id uint64, update InboundUpdate) (*NodeInbound, error) {
	var nodeID uint64
	err := s.Tx(ctx, func(tx *sqlx.Tx) error {
		var in NodeInbound
		if err := tx.GetContext(ctx, &in,
			`SELECT `+inboundColumns+` FROM node_inbounds WHERE id = ? FOR UPDATE`, id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: inbound %d: %w", id, ErrNotFound)
			}
			return fmt.Errorf("store: inbound %d: %w", id, err)
		}
		nodeID = in.NodeID

		if update.Overrides != nil {
			in.Overrides = *update.Overrides
		}
		if update.Params != nil {
			in.Params = *update.Params
		}
		if update.Secrets != nil {
			in.Secrets = *update.Secrets
		}
		if update.ListenAddress != nil {
			in.ListenAddress = *update.ListenAddress
		}
		if update.ListenPort != nil {
			in.ListenPort = *update.ListenPort
		}
		if update.ForwardToTag != nil {
			in.ForwardToTag = sql.NullString{String: *update.ForwardToTag, Valid: *update.ForwardToTag != ""}
		}
		if update.Published != nil {
			in.Published = *update.Published
		}
		if update.Enabled != nil {
			in.Enabled = *update.Enabled
		}
		if update.SortOrder != nil {
			in.SortOrder = *update.SortOrder
		}

		// A template instance's effective parameters are the template's,
		// with this node's overrides on top.
		if in.TemplateID.Valid && update.Overrides != nil {
			var t InboundTemplate
			if err := tx.GetContext(ctx, &t,
				`SELECT `+templateColumns+` FROM inbound_templates WHERE id = ?`, in.TemplateID.Int64); err == nil {
				in.Params = t.Params.Merge(in.Overrides)
				if v := in.Overrides["listen_port"]; v != "" {
					in.ListenPort = uint32(atoiOr(v, int(in.ListenPort)))
				}
			}
		}

		if _, err := tx.ExecContext(ctx,
			`UPDATE node_inbounds SET listen_address = ?, listen_port = ?, overrides = ?, params = ?,
			 secrets = ?, forward_to_tag = ?, published = ?, enabled = ?, sort_order = ? WHERE id = ?`,
			in.ListenAddress, in.ListenPort, in.Overrides, in.Params, nullBytes(in.Secrets),
			in.ForwardToTag, in.Published, in.Enabled, in.SortOrder, id); err != nil {
			return fmt.Errorf("store: update inbound %d: %w", id, err)
		}
		return bumpNodeVersionTx(ctx, tx, nodeID)
	})
	if err != nil {
		return nil, err
	}
	return s.InboundByID(ctx, id)
}

// DeleteInbound removes an inbound.
func (s *Store) DeleteInbound(ctx context.Context, id uint64) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error {
		var nodeID uint64
		err := tx.GetContext(ctx, &nodeID, `SELECT node_id FROM node_inbounds WHERE id = ?`, id)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: inbound %d: %w", id, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("store: inbound %d: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_inbounds WHERE id = ?`, id); err != nil {
			return fmt.Errorf("store: delete inbound %d: %w", id, err)
		}
		return bumpNodeVersionTx(ctx, tx, nodeID)
	})
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func atoiOr(v string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err != nil {
		return fallback
	}
	return n
}
