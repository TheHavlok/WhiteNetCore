package store

import (
	"strings"
	"testing"
	"testing/fstest"
)

// The embedded set must parse, which also catches a new migration added with
// a typo in its name or without a down file.
func TestLoadMigrationsEmbedded(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations embedded")
	}
	if migrations[0].Version != 1 || migrations[0].Name != "init" {
		t.Fatalf("first migration = %d_%s, want 000001_init", migrations[0].Version, migrations[0].Name)
	}
	// The initial migration must create the tables the rest of the panel
	// assumes exist; spot-check the ones other stages depend on.
	for _, table := range []string{"admins", "nodes", "node_inbounds", "users", "openflux_channels", "openflux_leases", "node_desired_state"} {
		if !strings.Contains(migrations[0].Up, "CREATE TABLE "+table+" (") {
			t.Errorf("000001_init does not create %s", table)
		}
		if !strings.Contains(migrations[0].Down, "DROP TABLE IF EXISTS "+table+";") {
			t.Errorf("000001_init does not drop %s", table)
		}
	}
}

func TestLoadMigrationsOrdersByVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"m/000002_second.up.sql":   {Data: []byte("SELECT 2;")},
		"m/000002_second.down.sql": {Data: []byte("SELECT -2;")},
		"m/000001_first.up.sql":    {Data: []byte("SELECT 1;")},
		"m/000001_first.down.sql":  {Data: []byte("SELECT -1;")},
		"m/000010_tenth.up.sql":    {Data: []byte("SELECT 10;")},
		"m/000010_tenth.down.sql":  {Data: []byte("SELECT -10;")},
		"m/README.txt":             {Data: []byte("ignored")},
	}
	migrations, err := loadMigrations(fsys, "m")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]uint, len(migrations))
	for i, m := range migrations {
		got[i] = m.Version
	}
	want := []uint{1, 2, 10}
	if len(got) != len(want) {
		t.Fatalf("versions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("versions = %v, want %v", got, want)
		}
	}
	if migrations[0].Up != "SELECT 1;" || migrations[0].Down != "SELECT -1;" {
		t.Fatalf("bodies not paired correctly: %+v", migrations[0])
	}
}

// A missing down file must fail at load time, not at rollback time.
func TestLoadMigrationsRejectsUnpaired(t *testing.T) {
	fsys := fstest.MapFS{
		"m/000001_first.up.sql": {Data: []byte("SELECT 1;")},
	}
	if _, err := loadMigrations(fsys, "m"); err == nil {
		t.Fatal("a migration without a down file was accepted")
	}
}

func TestLoadMigrationsRejectsEmptyBody(t *testing.T) {
	fsys := fstest.MapFS{
		"m/000001_first.up.sql":   {Data: []byte("SELECT 1;")},
		"m/000001_first.down.sql": {Data: []byte("   \n\t\n")},
	}
	if _, err := loadMigrations(fsys, "m"); err == nil {
		t.Fatal("a migration with an empty down body was accepted")
	}
}

func TestLoadMigrationsRejectsVersionZero(t *testing.T) {
	fsys := fstest.MapFS{
		"m/000000_zero.up.sql":   {Data: []byte("SELECT 1;")},
		"m/000000_zero.down.sql": {Data: []byte("SELECT -1;")},
	}
	if _, err := loadMigrations(fsys, "m"); err == nil {
		t.Fatal("version 0 was accepted")
	}
}

func TestParseMigrationName(t *testing.T) {
	cases := []struct {
		filename  string
		version   uint
		name      string
		direction string
		wantErr   bool
	}{
		{filename: "000001_init.up.sql", version: 1, name: "init", direction: "up"},
		{filename: "000123_add_devices.down.sql", version: 123, name: "add_devices", direction: "down"},
		{filename: "000001_init.sql", wantErr: true},          // no direction
		{filename: "000001_init.sideways.sql", wantErr: true}, // bad direction
		{filename: "init.up.sql", wantErr: true},              // no version
		{filename: "abc_init.up.sql", wantErr: true},          // version is not a number
	}
	for _, tc := range cases {
		version, name, dir, err := parseMigrationName(tc.filename)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: expected an error", tc.filename)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.filename, err)
			continue
		}
		if version != tc.version || name != tc.name || dir != tc.direction {
			t.Errorf("%s: got (%d, %q, %q), want (%d, %q, %q)",
				tc.filename, version, name, dir, tc.version, tc.name, tc.direction)
		}
	}
}
