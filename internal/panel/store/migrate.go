package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx"
)

// migrationFS holds the schema. Embedding it means the binary carries its own
// schema and a deployment is one file: no migration directory to copy, and no
// way for the files to drift from the code that expects them.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// The runner is deliberately ours rather than golang-migrate's. The file
// naming is golang-migrate's (NNNNNN_name.up.sql / .down.sql) so its CLI
// still works on this directory, but the library's own module pulls Docker
// and a test harness into the build graph for a job that is a version table
// and an ordered loop.
const migrationsTable = "schema_migrations"

// ErrDirty is returned when the version table says a migration failed
// halfway. Nothing else runs until an operator has looked at the schema and
// cleared the flag, because the next migration would be applying itself on
// top of an unknown state.
var ErrDirty = errors.New("store: schema is dirty")

// Migration is one versioned pair of statements.
type Migration struct {
	Version uint
	Name    string
	Up      string
	Down    string
}

// LoadMigrations parses the embedded directory. An unpaired or malformed file
// is an error rather than a skipped entry: a missing .down.sql only shows up
// when a rollback is needed, which is the worst time to discover it.
func LoadMigrations() ([]Migration, error) {
	return loadMigrations(migrationFS, "migrations")
}

func loadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}

	byVersion := map[uint]*Migration{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, name, direction, err := parseMigrationName(entry.Name())
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(fsys, dir+"/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", entry.Name(), err)
		}
		m := byVersion[version]
		if m == nil {
			m = &Migration{Version: version, Name: name}
			byVersion[version] = m
		}
		switch direction {
		case "up":
			m.Up = string(body)
		case "down":
			m.Down = string(body)
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if strings.TrimSpace(m.Up) == "" {
			return nil, fmt.Errorf("store: migration %06d_%s has no up statements", m.Version, m.Name)
		}
		if strings.TrimSpace(m.Down) == "" {
			return nil, fmt.Errorf("store: migration %06d_%s has no down statements", m.Version, m.Name)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })

	// Versions must be unique and start at 1; a gap is allowed, a zero is
	// not, because 0 is how "nothing applied" is represented.
	for i, m := range out {
		if m.Version == 0 {
			return nil, errors.New("store: migration version 0 is reserved")
		}
		if i > 0 && out[i-1].Version == m.Version {
			return nil, fmt.Errorf("store: duplicate migration version %d", m.Version)
		}
	}
	return out, nil
}

// parseMigrationName splits "000001_init.up.sql".
func parseMigrationName(filename string) (version uint, name, direction string, err error) {
	base := strings.TrimSuffix(filename, ".sql")

	base, direction, ok := cutLast(base, ".")
	if !ok || (direction != "up" && direction != "down") {
		return 0, "", "", fmt.Errorf("store: %s: expected a .up.sql or .down.sql suffix", filename)
	}

	versionPart, name, ok := strings.Cut(base, "_")
	if !ok {
		return 0, "", "", fmt.Errorf("store: %s: expected VERSION_name.%s.sql", filename, direction)
	}
	n, convErr := strconv.ParseUint(versionPart, 10, 32)
	if convErr != nil {
		return 0, "", "", fmt.Errorf("store: %s: %q is not a version number", filename, versionPart)
	}
	return uint(n), name, direction, nil
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// ensureVersionTable creates the bookkeeping table. It mirrors
// golang-migrate's layout (one row, version plus dirty flag) so the two can
// be swapped without touching the database.
func ensureVersionTable(ctx context.Context, db sqlx.ExecerContext) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS `+migrationsTable+` (
			version BIGINT UNSIGNED NOT NULL,
			dirty   TINYINT(1)      NOT NULL,
			PRIMARY KEY (version)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	if err != nil {
		return fmt.Errorf("store: create %s: %w", migrationsTable, err)
	}
	return nil
}

// SchemaVersion reports the applied version and whether the last migration
// left the schema dirty. Version 0 means nothing has been applied.
func SchemaVersion(ctx context.Context, db *sqlx.DB) (version uint, dirty bool, err error) {
	if err := ensureVersionTable(ctx, db); err != nil {
		return 0, false, err
	}
	row := struct {
		Version uint64 `db:"version"`
		Dirty   bool   `db:"dirty"`
	}{}
	err = db.GetContext(ctx, &row, `SELECT version, dirty FROM `+migrationsTable+` ORDER BY version DESC LIMIT 1`)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: read %s: %w", migrationsTable, err)
	}
	return uint(row.Version), row.Dirty, nil
}

// Migrate applies every pending migration in order. Already being current is
// not an error, so this is safe to call on every start.
//
// Each migration is marked dirty before it runs and clean after, which is
// what turns "the process was killed mid-migration" into a visible state
// rather than a silently half-applied schema. MariaDB has no transactional
// DDL, so that flag is the only honest signal available.
func Migrate(ctx context.Context, db *sqlx.DB) (applied []uint, err error) {
	migrations, err := LoadMigrations()
	if err != nil {
		return nil, err
	}
	current, dirty, err := SchemaVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	if dirty {
		return nil, fmt.Errorf("%w at version %d: inspect the schema, finish or undo that migration, then clear the flag", ErrDirty, current)
	}

	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if err := runMigration(ctx, db, m, directionUp); err != nil {
			return applied, err
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

// MigrateDown rolls back the newest steps migrations, or every one of them
// when steps is 0.
func MigrateDown(ctx context.Context, db *sqlx.DB, steps int) (reverted []uint, err error) {
	migrations, err := LoadMigrations()
	if err != nil {
		return nil, err
	}
	current, dirty, err := SchemaVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	if dirty {
		return nil, fmt.Errorf("%w at version %d: inspect the schema before rolling back", ErrDirty, current)
	}

	// Newest first.
	for i := len(migrations) - 1; i >= 0; i-- {
		m := migrations[i]
		if m.Version > current {
			continue
		}
		if steps > 0 && len(reverted) >= steps {
			break
		}
		if err := runMigration(ctx, db, m, directionDown); err != nil {
			return reverted, err
		}
		reverted = append(reverted, m.Version)
	}
	return reverted, nil
}

type direction string

const (
	directionUp   direction = "up"
	directionDown direction = "down"
)

// runMigration executes one direction of one migration and moves the version
// row. The body may hold several statements, which the driver allows because
// the DSN sets multiStatements.
func runMigration(ctx context.Context, db *sqlx.DB, m Migration, dir direction) error {
	body := m.Up
	if dir == directionDown {
		body = m.Down
	}

	if err := setVersion(ctx, db, m.Version, true); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("store: migration %06d_%s %s: %w", m.Version, m.Name, dir, err)
	}

	if dir == directionDown {
		// Rolling back means the previous version is now current, so the
		// row for this one goes away entirely.
		if _, err := db.ExecContext(ctx, `DELETE FROM `+migrationsTable+` WHERE version = ?`, m.Version); err != nil {
			return fmt.Errorf("store: clear version %d: %w", m.Version, err)
		}
		return nil
	}
	return setVersion(ctx, db, m.Version, false)
}

func setVersion(ctx context.Context, db *sqlx.DB, version uint, dirty bool) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO `+migrationsTable+` (version, dirty) VALUES (?, ?)
		 ON DUPLICATE KEY UPDATE dirty = VALUES(dirty)`, version, dirty)
	if err != nil {
		return fmt.Errorf("store: set version %d: %w", version, err)
	}
	return nil
}
