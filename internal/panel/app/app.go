// Package app assembles Main: the database, the certificate authority, the
// agent endpoint, the REST API, the subscription endpoint, the admin UI and
// the background jobs.
//
// Everything is wired here so the binary stays thin and the dependencies
// between the parts are visible in one file rather than spread across
// constructors.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/thehavlok/whitenet/internal/panel/api"
	"github.com/thehavlok/whitenet/internal/panel/config"
	"github.com/thehavlok/whitenet/internal/panel/noderpc"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/staterender"
	"github.com/thehavlok/whitenet/internal/panel/store"
	"github.com/thehavlok/whitenet/internal/panel/subhttp"
	"github.com/thehavlok/whitenet/internal/panel/webui"
)

// App is a configured panel.
type App struct {
	cfg config.Config
	log *slog.Logger

	Store    *store.Store
	Box      *secret.Box
	CA       *noderpc.CAManager
	Hub      *noderpc.Hub
	Renderer *staterender.Renderer
	RPC      *noderpc.Server
	API      *api.Server
	Sub      *subhttp.Server
}

// New builds the panel from a configuration.
//
// It opens the database and makes sure the schema and the certificate
// authority exist, because a panel that starts without them only fails later,
// in the middle of something.
func New(ctx context.Context, cfg config.Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}

	box, err := secret.New(cfg.MasterKey)
	if err != nil {
		return nil, err
	}

	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}

	version, dirty, err := store.SchemaVersion(ctx, st.DB)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if dirty {
		_ = st.Close()
		return nil, fmt.Errorf("app: schema version %d is dirty: a migration failed halfway; "+
			"inspect the schema, finish or undo that migration, then clear the flag", version)
	}
	log.Info("database ready", "dsn", cfg.Database.Redacted(), "schema_version", version)

	ca := noderpc.NewCAManager(st, box)
	if _, err := ca.Ensure(ctx); err != nil {
		_ = st.Close()
		return nil, err
	}
	fingerprint, err := ca.Fingerprint(ctx)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	log.Info("node certificate authority ready", "fingerprint", fingerprint)

	hub := noderpc.NewHub()
	renderer := staterender.New(st, box, staterender.Settings{
		HeartbeatSeconds:     uint32(cfg.Node.HeartbeatInterval.Duration().Seconds()),
		MetricsSeconds:       uint32(cfg.Node.MetricsInterval.Duration().Seconds()),
		TrafficReportSeconds: uint32(cfg.Node.TrafficReportInterval.Duration().Seconds()),
	})

	rpc := noderpc.New(st, box, ca, hub, renderer, log, noderpc.Options{
		AgentCertTTL: cfg.Node.CertTTL.Duration(),
		Hosts:        agentHosts(ctx, st, cfg),
	})

	return &App{
		cfg:      cfg,
		log:      log,
		Store:    st,
		Box:      box,
		CA:       ca,
		Hub:      hub,
		Renderer: renderer,
		RPC:      rpc,
		API:      api.New(st, box, rpc, renderer, cfg, log),
		Sub:      subhttp.New(st, box, cfg, log),
	}, nil
}

// Close releases the database.
func (a *App) Close() error { return a.Store.Close() }

// Run starts every listener and the background jobs, and returns when the
// context is cancelled or something fails.
func (a *App) Run(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)

	grpcServer, grpcListener, err := a.RPC.Listen(ctx, a.cfg.GRPC.Listen)
	if err != nil {
		return err
	}
	a.log.Info("agent endpoint listening", "address", a.cfg.GRPC.Listen)

	httpServer := &http.Server{
		Addr:              a.cfg.HTTP.Listen,
		Handler:           a.handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       a.cfg.HTTP.ReadTimeout.Duration(),
		WriteTimeout:      a.cfg.HTTP.WriteTimeout.Duration(),
		// A subscription page on a slow phone connection should not hold a
		// connection open forever.
		IdleTimeout: 2 * time.Minute,
	}

	group.Go(func() error {
		if err := grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("app: agent endpoint: %w", err)
		}
		return nil
	})

	group.Go(func() error {
		a.log.Info("http listening",
			"address", a.cfg.HTTP.Listen, "panel_path", a.cfg.HTTP.PanelPath)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("app: http: %w", err)
		}
		return nil
	})

	group.Go(func() error {
		a.runJobs(ctx)
		return nil
	})

	group.Go(func() error {
		<-ctx.Done()
		a.log.Info("shutting down")

		// Stop accepting first, then give in-flight requests a moment.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			a.log.Warn("http did not shut down cleanly", "error", err)
		}
		// GracefulStop waits for agent streams to end, which they do as soon
		// as their contexts are cancelled.
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-shutdownCtx.Done():
			grpcServer.Stop()
		}
		return nil
	})

	return group.Wait()
}

// handler builds the HTTP routing.
//
// Three things share one port behind the reverse proxy: the admin UI on its
// configured path, the REST API under it, and the subscription endpoint at the
// root. The subscription has to be at the root because its links are public
// and short.
func (a *App) handler() http.Handler {
	mux := http.NewServeMux()

	panelPath := strings.TrimRight(a.cfg.HTTP.PanelPath, "/")
	if panelPath == "" {
		panelPath = "/admin"
	}

	// The API lives under the panel's path, so moving the panel to an
	// unguessable path moves the API with it.
	apiPrefix := panelPath + "/api/"
	mux.Handle(apiPrefix, http.StripPrefix(strings.TrimSuffix(apiPrefix, "/"), a.API.Routes()))

	// The admin UI, embedded in the binary.
	ui := webui.Handler(panelPath)
	mux.Handle(panelPath+"/", ui)
	// Without this, the path without a trailing slash 404s, which is what
	// anyone types.
	mux.HandleFunc(panelPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, panelPath+"/", http.StatusFound)
	})

	// The install script agents fetch. It is public on purpose: it carries no
	// secret, and the token is in the command the admin pastes.
	mux.HandleFunc("GET /install.sh", a.handleInstallScript)

	// The binaries the installer downloads. Serving them from the panel means
	// a node only has to be able to reach the panel, not GitHub.
	mux.Handle("GET /dist/", a.distHandler())

	// Subscriptions and leases at the root.
	mux.Handle("/", a.hostRouter(a.Sub.Routes()))

	return a.withSecurityHeaders(mux)
}

// hostRouter keeps the subscription endpoint on its own host when one is
// configured, so a blocked subscription domain cannot be used to reach the
// panel and vice versa.
func (a *App) hostRouter(subHandler http.Handler) http.Handler {
	subDomain := strings.ToLower(strings.TrimSpace(a.cfg.HTTP.SubDomain))
	panelDomain := strings.ToLower(strings.TrimSpace(a.cfg.HTTP.PanelDomain))
	if subDomain == "" && panelDomain == "" {
		return subHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if subDomain != "" && host != subDomain {
			// Not the subscription host: say nothing useful.
			http.NotFound(w, r)
			return
		}
		subHandler.ServeHTTP(w, r)
	})
}

// withSecurityHeaders adds the headers that apply to everything.
func (a *App) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// agentHosts decides which names Main's own certificate covers.
//
// Agents verify it against the pinned CA rather than public trust, so this
// only has to match however they dial - which is whatever went into their
// install command.
func agentHosts(ctx context.Context, st *store.Store, cfg config.Config) []string {
	hosts := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if host, _, err := net.SplitHostPort(value); err == nil && host != "" {
			value = host
		}
		value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
		value, _, _ = strings.Cut(value, "/")
		if value != "" && value != "0.0.0.0" && value != "::" {
			hosts[value] = true
		}
	}

	add(cfg.GRPC.Advertise)
	if domains, err := st.Domains(ctx); err == nil {
		add(domains.AgentEndpoint)
		add(domains.PanelURL)
	}
	// Localhost is always included so a panel can be tested on the box it
	// runs on.
	hosts["localhost"] = true
	hosts["127.0.0.1"] = true

	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	return out
}

// ---------------------------------------------------------------------------
// Background jobs
// ---------------------------------------------------------------------------

// runJobs runs the periodic work: marking nodes offline, rolling up metrics,
// enforcing limits, expiring leases and pruning.
//
// Each job logs its own failures and carries on. One of them failing must not
// stop the others, and none of them is worth stopping the panel over.
func (a *App) runJobs(ctx context.Context) {
	var wg sync.WaitGroup
	job := func(name string, every time.Duration, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(every)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Each run gets its own timeout, so a slow query cannot
					// stall the job forever.
					runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					if err := fn(runCtx); err != nil {
						a.log.Warn("a background job failed", "job", name, "error", err)
					}
					cancel()
				}
			}
		}()
	}

	// Nodes that stopped sending heartbeats. This is what makes a node that
	// was killed rather than shut down show up as offline.
	job("mark-offline", a.cfg.Node.HeartbeatInterval.Duration(), func(ctx context.Context) error {
		affected, err := a.Store.MarkStaleNodesOffline(ctx, a.cfg.Node.OfflineAfter.Duration())
		if err != nil {
			return err
		}
		if affected > 0 {
			a.log.Info("marked nodes offline", "count", affected)
			// A node going offline changes what subscriptions contain.
			a.Sub.InvalidateAll()
		}
		return nil
	})

	// Expiry and traffic limits. A traffic report enforces them immediately;
	// this catches an expiry, which passes without anyone sending anything.
	job("enforce-limits", time.Minute, func(ctx context.Context) error {
		expired, limited, err := a.Store.EnforceLimits(ctx)
		if err != nil {
			return err
		}
		if len(expired) == 0 && len(limited) == 0 {
			return nil
		}
		for _, userID := range append(append([]uint64{}, expired...), limited...) {
			if err := a.Store.RevokeUserLeases(ctx, userID); err != nil {
				a.log.Warn("could not release a user's leases", "user", userID, "error", err)
			}
			id := userID
			_ = a.Store.RecordEvent(ctx, store.NewEvent{
				Severity: "info", Type: "user_deactivated", UserID: &id,
				Message: "the user was deactivated: expired or out of traffic",
			})
		}
		a.log.Info("deactivated users", "expired", len(expired), "over_limit", len(limited))
		a.Sub.InvalidateAll()
		a.RPC.PushToConnected(ctx)
		return nil
	})

	// Leases whose client vanished, so a small pool recovers.
	job("expire-leases", time.Minute, func(ctx context.Context) error {
		affected, err := a.Store.ExpireLeases(ctx)
		if err != nil {
			return err
		}
		if affected > 0 {
			a.log.Debug("expired flux leases", "count", affected)
		}
		return nil
	})

	// The hourly rollup, so the week chart does not scan raw samples.
	job("rollup-metrics", 10*time.Minute, func(ctx context.Context) error {
		// Only complete hours are rolled up: the current one would be
		// rewritten on every run.
		until := time.Now().UTC().Truncate(time.Hour)
		_, err := a.Store.RollupHourly(ctx, until)
		return err
	})

	// Retention. Metrics are the only table that grows on its own, so this is
	// where disk use is bounded.
	job("prune", time.Hour, func(ctx context.Context) error {
		var errs []error
		if _, err := a.Store.PruneMetrics(ctx, a.cfg.Retention.RawMetrics.Duration()); err != nil {
			errs = append(errs, err)
		}
		if _, err := a.Store.PruneHourlyMetrics(ctx, a.cfg.Retention.HourlyMetrics.Duration()); err != nil {
			errs = append(errs, err)
		}
		if _, err := a.Store.PruneEvents(ctx, a.cfg.Retention.Events.Duration()); err != nil {
			errs = append(errs, err)
		}
		if _, err := a.Store.PruneTrafficDaily(ctx, a.cfg.Retention.TrafficDaily.Duration()); err != nil {
			errs = append(errs, err)
		}
		// The idempotency ledger only has to outlive an agent's retry window.
		if _, err := a.Store.PruneTrafficBatches(ctx, 48*time.Hour); err != nil {
			errs = append(errs, err)
		}
		if _, err := a.Store.PruneAdminSessions(ctx); err != nil {
			errs = append(errs, err)
		}
		// Old state snapshots carry secrets, so they do not live forever.
		if err := a.Store.PruneDesiredStates(ctx, 5); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	})

	wg.Wait()
}
