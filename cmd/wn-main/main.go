// Command wn-main is the WhiteNet panel: the REST API, the admin UI, the
// subscription endpoint and the gRPC endpoint agents connect to.
//
// Stage 1 wires up configuration, logging and the schema. The servers
// themselves arrive in stage 3, and `serve` says so rather than starting
// something half-built.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/thehavlok/whitenet/internal/panel/app"
	"github.com/thehavlok/whitenet/internal/panel/config"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/store"
	"github.com/thehavlok/whitenet/internal/panel/webui"
	"github.com/thehavlok/whitenet/internal/wnlog"
)

const usage = `wn-main - WhiteNet panel

Usage:
  wn-main [-config FILE] serve
  wn-main [-config FILE] migrate up
  wn-main [-config FILE] migrate down [STEPS]
  wn-main [-config FILE] migrate version
  wn-main genkey
  wn-main link make|read|qr|import ...

Commands:
  serve             Run the panel (API, admin UI, subscriptions, agent endpoint)
  migrate up        Apply every pending schema migration
  migrate down      Roll back STEPS migrations, or all of them when STEPS is omitted
  migrate version   Print the applied schema version
  genkey            Print a fresh master key for the configuration
  link              Build and read whitenet:// links (wn-main link for details)

Flags:
  -config FILE      Configuration file (default: $WN_CONFIG, then ./main.toml)

Every configuration value can be overridden through the environment with the
WN_ prefix, e.g. WN_DB_PASSWORD, WN_MASTER_KEY.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wn-main: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("wn-main", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configPath := fs.String("config", defaultConfigPath(), "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return errors.New("no command given")
	}

	// genkey and link must work before there is any configuration at all.
	if rest[0] == "link" {
		return cmdLink(rest[1:])
	}
	if rest[0] == "genkey" {
		key, err := secret.NewMasterKey()
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// Interrupts cancel the context so a long migration or a running server
	// stops on the first Ctrl-C rather than being killed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch rest[0] {
	case "serve":
		return cmdServe(ctx, cfg)
	case "migrate":
		return cmdMigrate(ctx, cfg, rest[1:])
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", rest[0])
	}
}

func defaultConfigPath() string {
	if v, ok := os.LookupEnv("WN_CONFIG"); ok {
		return v
	}
	return "main.toml"
}

func cmdServe(ctx context.Context, cfg config.Config) error {
	log := wnlog.New(cfg.Log.Level, cfg.Log.Format)

	// Migrations run on start rather than as a separate step: a panel and its
	// schema are one deployable thing, and a half-upgraded pair is worse than
	// a moment of downtime.
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	applied, err := store.Migrate(ctx, st.DB)
	if err != nil {
		_ = st.Close()
		return err
	}
	if len(applied) > 0 {
		log.Info("applied schema migrations", "versions", applied)
	}
	if err := st.Close(); err != nil {
		return err
	}

	panel, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = panel.Close() }()

	if !webui.Built() {
		log.Warn("the admin interface is not built into this binary; the API is still available",
			"how", "cd web && npm install && npm run build, then rebuild")
	}
	return panel.Run(ctx)
}

func cmdMigrate(ctx context.Context, cfg config.Config, args []string) error {
	log := wnlog.New(cfg.Log.Level, cfg.Log.Format)
	if len(args) == 0 {
		return errors.New("migrate needs a subcommand: up, down or version")
	}

	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	switch args[0] {
	case "up":
		before, _, err := store.SchemaVersion(ctx, st.DB)
		if err != nil {
			return err
		}
		applied, err := store.Migrate(ctx, st.DB)
		if err != nil {
			return err
		}
		after, dirty, err := store.SchemaVersion(ctx, st.DB)
		if err != nil {
			return err
		}
		log.Info("migrated", "from", before, "to", after, "applied", applied, "dirty", dirty)
		return nil

	case "down":
		steps := 0
		if len(args) > 1 {
			if _, err := fmt.Sscanf(args[1], "%d", &steps); err != nil {
				return fmt.Errorf("migrate down: %q is not a number of steps", args[1])
			}
		}
		reverted, err := store.MigrateDown(ctx, st.DB, steps)
		if err != nil {
			return err
		}
		after, dirty, err := store.SchemaVersion(ctx, st.DB)
		if err != nil {
			return err
		}
		log.Info("rolled back", "reverted", reverted, "version", after, "dirty", dirty)
		return nil

	case "version":
		version, dirty, err := store.SchemaVersion(ctx, st.DB)
		if err != nil {
			return err
		}
		fmt.Printf("version=%d dirty=%t\n", version, dirty)
		return nil

	default:
		return fmt.Errorf("migrate: unknown subcommand %q", args[0])
	}
}
