package stateapply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentconfig "github.com/thehavlok/whitenet/internal/agentd/config"
	"github.com/thehavlok/whitenet/internal/agentd/fluxpool"
	"github.com/thehavlok/whitenet/internal/agentd/supervisor"
	"github.com/thehavlok/whitenet/internal/agentd/wndnscfg"
	"github.com/thehavlok/whitenet/internal/agentd/xraycfg"
	"github.com/thehavlok/whitenet/internal/agentd/xrayctl"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

// Applier owns the node's cores and the state they are running.
//
// It is the only thing that writes core configurations or starts and stops
// them, so "what is this node running" has one answer and one owner.
type Applier struct {
	cfg  agentconfig.Config
	log  *slog.Logger
	xray *xrayctl.Client
	flux *fluxpool.Pool

	mu      sync.Mutex
	current *nodepb.NodeState
	// xraySup and dnsSup are nil until the corresponding core is wanted.
	xraySup *supervisor.Supervisor
	dnsSup  *supervisor.Supervisor
}

// Result is what an Apply did, for the StateApplied frame and the journal.
type Result struct {
	Version   uint64
	Plan      Plan
	Restarted []nodepb.Core
}

// New returns an applier. It does not touch the node: the caller loads the
// last state and applies it, so startup and a reconnect take the same path.
func New(cfg agentconfig.Config, log *slog.Logger) *Applier {
	if log == nil {
		log = slog.Default()
	}
	return &Applier{
		cfg:  cfg,
		log:  log,
		xray: xrayctl.New(cfg.Cores.XrayAPIAddress),
		flux: fluxpool.New(fluxpool.Options{
			CookieDir: cfg.CoreConfigDir(),
			Log:       log,
		}),
	}
}

// Current returns the state the node is running, or nil before the first
// apply.
func (a *Applier) Current() *nodepb.NodeState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current
}

// Version returns the state version the node is running, or 0.
func (a *Applier) Version() uint64 {
	return a.Current().GetVersion()
}

// LoadPersisted reads the last applied state from disk.
//
// This is what lets a node keep serving when Main is unreachable: the agent
// starts, finds the state it had, and brings the cores up from it without
// needing the panel at all.
func (a *Applier) LoadPersisted() (*nodepb.NodeState, error) {
	raw, err := os.ReadFile(a.cfg.StatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stateapply: read %s: %w", a.cfg.StatePath(), err)
	}
	state := &nodepb.NodeState{}
	if err := proto.Unmarshal(raw, state); err != nil {
		// A corrupt file must not stop the agent: it reconnects and Main
		// sends the state again.
		return nil, fmt.Errorf("stateapply: parse %s: %w", a.cfg.StatePath(), err)
	}
	return state, nil
}

// persist writes the state, atomically, so a crash mid-write cannot leave a
// half-written file that fails to parse on the next start.
func (a *Applier) persist(state *nodepb.NodeState) error {
	raw, err := proto.Marshal(state)
	if err != nil {
		return fmt.Errorf("stateapply: marshal state: %w", err)
	}
	path := a.cfg.StatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("stateapply: create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	// The state carries every user secret on this node, so it is never
	// readable by anyone else.
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("stateapply: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("stateapply: rename %s: %w", path, err)
	}
	return nil
}

// Apply brings the node in line with state.
//
// Applying the same state twice does nothing, which is what makes a reconnect
// cheap and a retry safe.
func (a *Applier) Apply(ctx context.Context, state *nodepb.NodeState) (Result, error) {
	if state == nil {
		return Result{}, errors.New("stateapply: nil state")
	}

	a.mu.Lock()
	current := a.current
	a.mu.Unlock()

	plan := PlanFor(current, state)
	result := Result{Version: state.GetVersion(), Plan: plan}

	if plan.Empty() {
		a.log.Debug("state unchanged", "version", state.GetVersion())
		a.mu.Lock()
		a.current = state
		a.mu.Unlock()
		// Still persist: the version moved even if nothing else did, and the
		// agent reports that version on its next reconnect.
		return result, a.persist(state)
	}

	a.log.Info("applying state",
		"version", state.GetVersion(), "reason", plan.Reason,
		"restart_xray", plan.RestartXray, "restart_wndns", plan.RestartWNDNS)

	var errs []error

	// Xray first: the DNS tunnel forwards into it, so the target has to exist
	// before the tunnel points at it.
	if plan.RestartXray {
		if err := a.applyXray(ctx, state); err != nil {
			errs = append(errs, err)
		} else {
			result.Restarted = append(result.Restarted, nodepb.Core_CORE_XRAY)
		}
	} else {
		if err := a.applyUserDeltas(ctx, state, plan); err != nil {
			errs = append(errs, err)
		}
	}

	switch {
	case plan.StopWNDNS:
		a.stopDNS()
	case plan.RestartWNDNS:
		if err := a.applyDNS(ctx, state); err != nil {
			errs = append(errs, err)
		} else {
			result.Restarted = append(result.Restarted, nodepb.Core_CORE_WNDNS)
		}
	}

	if plan.ApplyFlux {
		started, stopped, err := a.flux.Apply(ctx, state.GetOpenflux())
		if err != nil {
			errs = append(errs, err)
		}
		if len(started) > 0 || len(stopped) > 0 {
			result.Restarted = append(result.Restarted, nodepb.Core_CORE_OPENFLUX)
			a.log.Info("flux channels reconciled", "started", started, "stopped", stopped)
		}
	}

	if err := errors.Join(errs...); err != nil {
		// The state is not recorded as current when applying it failed, so
		// the next attempt plans the same work again rather than believing it
		// is already done.
		return result, err
	}

	a.mu.Lock()
	a.current = state
	a.mu.Unlock()
	return result, a.persist(state)
}

// applyXray writes the configuration and starts or restarts the process.
func (a *Applier) applyXray(ctx context.Context, state *nodepb.NodeState) error {
	raw, err := xraycfg.Generate(state, xraycfg.Options{
		APIAddress: a.cfg.Cores.XrayAPIAddress,
		LogLevel:   state.GetSettings().GetXrayLogLevel(),
	})
	if err != nil {
		return err
	}

	// No Xray inbounds means nothing for Xray to do. Running it anyway would
	// be a process that only answers its own API.
	if !hasXrayInbounds(state) {
		a.stopXray()
		return nil
	}

	path := filepath.Join(a.cfg.CoreConfigDir(), "xray.json")
	if err := writeFile(path, raw, 0o600); err != nil {
		return err
	}

	a.mu.Lock()
	sup := a.xraySup
	a.mu.Unlock()

	if sup == nil {
		logWriter, err := a.coreLog("xray")
		if err != nil {
			return err
		}
		sup = supervisor.New(supervisor.Spec{
			Name:      "xray",
			Path:      a.cfg.Binary(a.cfg.Cores.XrayBinary),
			Args:      []string{"run", "-c", path},
			Dir:       a.cfg.CoreConfigDir(),
			LogWriter: logWriter,
			// Ready is the API answering, not the process staying up: a
			// configuration Xray rejects leaves a process that exits, but a
			// port clash on one inbound can leave one that serves nothing.
			Ready: func(ctx context.Context) error {
				return a.xray.WaitReady(ctx, 200*time.Millisecond)
			},
			StartTimeout:      a.cfg.Cores.StartTimeout.Duration(),
			StopTimeout:       a.cfg.Cores.StopTimeout.Duration(),
			RestartBackoff:    a.cfg.Cores.RestartBackoff.Duration(),
			RestartBackoffMax: a.cfg.Cores.RestartBackoffMax.Duration(),
		}, a.log)
		a.mu.Lock()
		a.xraySup = sup
		a.mu.Unlock()
		// The API connection is per-process; a new process needs a new one.
		a.xray.Reset()
		return sup.Start(ctx)
	}

	a.xray.Reset()
	return sup.Restart(ctx)
}

// coreLog opens a core's log file.
//
// The cores log to files under the agent's directory rather than to the
// journal, because the panel has to be able to fetch them without the agent
// parsing journald's format or holding its permissions.
func (a *Applier) coreLog(name string) (io.Writer, error) {
	dir := filepath.Join(a.cfg.DataDir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("stateapply: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, name+".log")
	// Append, so a restart does not discard what the last run said about why
	// it died - which is exactly what an operator wants to read.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("stateapply: open %s: %w", path, err)
	}
	return file, nil
}

// applyUserDeltas adds and removes users through the Xray API.
func (a *Applier) applyUserDeltas(ctx context.Context, state *nodepb.NodeState, plan Plan) error {
	inbounds := map[string]*nodepb.Inbound{}
	for _, in := range state.GetInbounds() {
		inbounds[in.GetTag()] = in
	}

	var errs []error
	// Removals first: a changed credential is a remove plus an add of the
	// same account, and doing it the other way round would remove what was
	// just added.
	for tag, emails := range plan.RemoveUsers {
		for _, email := range emails {
			if err := a.xray.RemoveUser(ctx, tag, email); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for tag, users := range plan.AddUsers {
		inbound, ok := inbounds[tag]
		if !ok {
			errs = append(errs, fmt.Errorf("stateapply: inbound %s is not in the state", tag))
			continue
		}
		for _, user := range users {
			if err := a.xray.AddUser(ctx, inbound, user); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// applyDNS writes the tunnel's key and configuration and restarts it.
func (a *Applier) applyDNS(ctx context.Context, state *nodepb.NodeState) error {
	keyPath := filepath.Join(a.cfg.CoreConfigDir(), "wndns.key")
	cfg, err := wndnscfg.Build(state, wndnscfg.Options{
		KeyFile:  keyPath,
		LogLevel: state.GetSettings().GetXrayLogLevel(),
	})
	if err != nil {
		return err
	}
	if cfg == nil {
		a.stopDNS()
		return nil
	}

	if cfg.Key != "" {
		if err := writeFile(keyPath, []byte(cfg.Key), 0o600); err != nil {
			return err
		}
	}
	// The configuration is also written out, even though it is passed on the
	// command line: when a node misbehaves, this file is what an operator
	// looks at.
	configPath := filepath.Join(a.cfg.CoreConfigDir(), "wndns.json")
	if err := writeFile(configPath, cfg.JSON, 0o600); err != nil {
		return err
	}

	a.mu.Lock()
	sup := a.dnsSup
	a.mu.Unlock()

	if sup == nil {
		logWriter, err := a.coreLog("wndns")
		if err != nil {
			return err
		}
		sup = supervisor.New(supervisor.Spec{
			Name: "wndns",
			Path: a.cfg.Binary(a.cfg.Cores.WNDNSBinary),
			// The tunnel takes its configuration as a positional argument and
			// decides it is a server from the .json extension; -nowait stops
			// it waiting for a key press when something is wrong, which would
			// hang it under systemd.
			Args:              []string{configPath, "-nowait"},
			Dir:               a.cfg.CoreConfigDir(),
			LogWriter:         logWriter,
			StopTimeout:       a.cfg.Cores.StopTimeout.Duration(),
			RestartBackoff:    a.cfg.Cores.RestartBackoff.Duration(),
			RestartBackoffMax: a.cfg.Cores.RestartBackoffMax.Duration(),
		}, a.log)
		a.mu.Lock()
		a.dnsSup = sup
		a.mu.Unlock()
		return sup.Start(ctx)
	}
	return sup.Restart(ctx)
}

func (a *Applier) stopXray() {
	a.mu.Lock()
	sup := a.xraySup
	a.xraySup = nil
	a.mu.Unlock()
	if sup != nil {
		if err := sup.Stop(); err != nil {
			a.log.Warn("xray did not stop cleanly", "error", err)
		}
	}
	a.xray.Reset()
}

func (a *Applier) stopDNS() {
	a.mu.Lock()
	sup := a.dnsSup
	a.dnsSup = nil
	a.mu.Unlock()
	if sup != nil {
		if err := sup.Stop(); err != nil {
			a.log.Warn("the dns tunnel did not stop cleanly", "error", err)
		}
	}
}

// Stop shuts every core down. The agent calls it on its way out, so a node
// does not keep serving from a configuration nobody is maintaining.
func (a *Applier) Stop() {
	a.stopXray()
	a.stopDNS()
	a.flux.Stop()
	_ = a.xray.Close()
}

// RestartCore restarts one core on the panel's command.
func (a *Applier) RestartCore(ctx context.Context, core nodepb.Core) error {
	switch core {
	case nodepb.Core_CORE_XRAY:
		a.mu.Lock()
		sup := a.xraySup
		a.mu.Unlock()
		if sup == nil {
			return errors.New("stateapply: xray is not running on this node")
		}
		a.xray.Reset()
		return sup.Restart(ctx)

	case nodepb.Core_CORE_WNDNS:
		a.mu.Lock()
		sup := a.dnsSup
		a.mu.Unlock()
		if sup == nil {
			return errors.New("stateapply: the dns tunnel is not running on this node")
		}
		return sup.Restart(ctx)

	case nodepb.Core_CORE_OPENFLUX:
		// Flux runs in this process, so a restart means stopping every
		// channel and re-applying the state.
		a.flux.Stop()
		state := a.Current()
		if state == nil {
			return nil
		}
		_, _, err := a.flux.Apply(ctx, state.GetOpenflux())
		return err

	default:
		return fmt.Errorf("stateapply: unknown core %s", core)
	}
}

// CoreStatuses is what the heartbeat reports.
func (a *Applier) CoreStatuses() []*nodepb.CoreStatus {
	a.mu.Lock()
	xraySup, dnsSup := a.xraySup, a.dnsSup
	a.mu.Unlock()

	var out []*nodepb.CoreStatus
	if xraySup != nil {
		out = append(out, coreStatus(nodepb.Core_CORE_XRAY, xraySup.Status()))
	}
	if dnsSup != nil {
		out = append(out, coreStatus(nodepb.Core_CORE_WNDNS, dnsSup.Status()))
	}
	if a.flux.Running() {
		out = append(out, &nodepb.CoreStatus{
			Core:    nodepb.Core_CORE_OPENFLUX,
			Running: true,
		})
	}
	return out
}

func coreStatus(core nodepb.Core, status supervisor.Status) *nodepb.CoreStatus {
	out := &nodepb.CoreStatus{
		Core:         core,
		Running:      status.Running,
		RestartCount: status.Restarts,
		LastError:    status.LastError,
	}
	if !status.StartedAt.IsZero() {
		out.StartedAt = timestamp(status.StartedAt)
	}
	return out
}

// Xray returns the API client, so the agent's traffic reporter can read
// counters without the applier having to proxy every call.
func (a *Applier) Xray() *xrayctl.Client { return a.xray }

// Flux returns the channel pool, for the channel report.
func (a *Applier) Flux() *fluxpool.Pool { return a.flux }

// Supervisors returns the running supervisors' event channels, so the agent
// can forward core crashes to the panel's journal.
func (a *Applier) Supervisors() []*supervisor.Supervisor {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*supervisor.Supervisor
	if a.xraySup != nil {
		out = append(out, a.xraySup)
	}
	if a.dnsSup != nil {
		out = append(out, a.dnsSup)
	}
	return out
}

func hasXrayInbounds(state *nodepb.NodeState) bool {
	for _, in := range state.GetInbounds() {
		if in.GetEnabled() && in.GetCore() == nodepb.Core_CORE_XRAY {
			return true
		}
	}
	return false
}

// writeFile writes atomically and only when the content differs, so an
// unchanged configuration does not get a new modification time and confuse
// whoever is looking at the node.
func writeFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("stateapply: create %s: %w", filepath.Dir(path), err)
	}
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(content) {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return fmt.Errorf("stateapply: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("stateapply: rename %s: %w", path, err)
	}
	return nil
}
