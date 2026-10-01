// Package store owns the database: the connection, the schema migrations and
// (from stage 3 on) the queries.
//
// Data access is sqlx over hand-written SQL rather than an ORM or generated
// code. Most of the panel's reads are filtered lists - search by name, filter
// by status and group, bulk updates over a set of ids - and those are clearer
// and faster to write as SQL with a builder than as generated methods plus
// escape hatches for the dynamic half.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/thehavlok/whitenet/internal/panel/config"
)

// Store is a handle on the database.
type Store struct {
	DB *sqlx.DB
}

// Open connects and verifies the connection. It does not migrate; call
// Migrate for that, so a deployment can choose when the schema changes.
func Open(ctx context.Context, cfg config.Database) (*Store, error) {
	db, err := sqlx.Open("mysql", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", cfg.Redacted(), err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime.Duration())

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping %s: %w", cfg.Redacted(), err)
	}
	return &Store{DB: db}, nil
}

// Close releases the pool.
func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

// Tx runs fn in a transaction, committing when it returns nil and rolling
// back otherwise. A panic also rolls back and is then re-raised, so a bug
// cannot leave a transaction open holding locks.
func (s *Store) Tx(ctx context.Context, fn func(*sqlx.Tx) error) error {
	tx, err := s.DB.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// MySQL error numbers the panel distinguishes.
const (
	errDuplicateEntry   = 1062
	errForeignKeyParent = 1452
	errForeignKeyChild  = 1451
	errLockDeadlock     = 1213
	errLockWaitTimeout  = 1205
)

// IsDuplicate reports whether err is a unique-constraint violation. The panel
// relies on this in two places where a constraint is the logic rather than a
// guard: leasing an OpenFlux channel (one live lease per channel) and
// accepting a traffic batch (one batch id per node).
func IsDuplicate(err error) bool {
	return mysqlErrNumber(err) == errDuplicateEntry
}

// IsForeignKeyViolation reports whether err is a foreign-key failure in
// either direction.
func IsForeignKeyViolation(err error) bool {
	n := mysqlErrNumber(err)
	return n == errForeignKeyParent || n == errForeignKeyChild
}

// IsRetryable reports whether err is a deadlock or lock-wait timeout, which
// the caller may retry unchanged.
func IsRetryable(err error) bool {
	n := mysqlErrNumber(err)
	return n == errLockDeadlock || n == errLockWaitTimeout
}

// IsNotFound reports whether err is the "no rows" sentinel.
func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

func mysqlErrNumber(err error) uint16 {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number
	}
	return 0
}

// errUnsupportedScan is the error a Scanner returns for a type it was not
// expecting, phrased so the column and the driver type both appear in a log.
func errUnsupportedScan(src any) error {
	return fmt.Errorf("store: cannot scan %T into a JSON map", src)
}
