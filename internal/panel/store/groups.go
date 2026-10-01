package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

const groupColumns = `id, uuid, name, description, sort_order, created_at, updated_at`

// CreateGroup adds a node group. Groups are the only thing that links users to
// nodes, so creating one is cheap and deleting one takes access away.
func (s *Store) CreateGroup(ctx context.Context, name, description string, sortOrder int) (*Group, error) {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO node_groups (uuid, name, description, sort_order) VALUES (?, ?, ?, ?)`,
		uuid.NewString(), name, nullString(description), sortOrder)
	if err != nil {
		return nil, fmt.Errorf("store: create group: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GroupByID(ctx, uint64(id))
}

// GroupByID reads one group.
func (s *Store) GroupByID(ctx context.Context, id uint64) (*Group, error) {
	var g Group
	err := s.DB.GetContext(ctx, &g, `SELECT `+groupColumns+` FROM node_groups WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: group %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: group %d: %w", id, err)
	}
	return &g, nil
}

// ListGroups returns every group in display order.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	var out []Group
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT `+groupColumns+` FROM node_groups ORDER BY sort_order, name`); err != nil {
		return nil, fmt.Errorf("store: list groups: %w", err)
	}
	return out, nil
}

// UpdateGroup renames or reorders a group.
func (s *Store) UpdateGroup(ctx context.Context, id uint64, name, description string, sortOrder int) (*Group, error) {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE node_groups SET name = ?, description = ?, sort_order = ? WHERE id = ?`,
		name, nullString(description), sortOrder, id); err != nil {
		return nil, fmt.Errorf("store: update group %d: %w", id, err)
	}
	return s.GroupByID(ctx, id)
}

// DeleteGroup removes a group. Every node in it loses the users who reached it
// through that group, so the nodes are bumped before it goes.
func (s *Store) DeleteGroup(ctx context.Context, id uint64) error {
	return s.Tx(ctx, func(tx *sqlx.Tx) error {
		if err := bumpNodesForUserGroupsTx(ctx, tx, []uint64{id}); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM node_groups WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("store: delete group %d: %w", id, err)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return fmt.Errorf("store: group %d: %w", id, ErrNotFound)
		}
		return nil
	})
}

// GroupCounts is how many nodes and users a group has, for the admin UI.
type GroupCounts struct {
	GroupID uint64 `db:"group_id"`
	Nodes   int    `db:"nodes"`
	Users   int    `db:"users"`
}

// GroupCountsAll returns the counts for every group in one query, so the
// groups page does not make one request per row.
func (s *Store) GroupCountsAll(ctx context.Context) ([]GroupCounts, error) {
	var out []GroupCounts
	if err := s.DB.SelectContext(ctx, &out,
		`SELECT g.id AS group_id,
			(SELECT COUNT(*) FROM node_group_members m WHERE m.group_id = g.id) AS nodes,
			(SELECT COUNT(*) FROM user_group_members m WHERE m.group_id = g.id) AS users
		 FROM node_groups g ORDER BY g.sort_order, g.name`); err != nil {
		return nil, fmt.Errorf("store: group counts: %w", err)
	}
	return out, nil
}
