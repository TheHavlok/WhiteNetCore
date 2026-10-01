// Package fluxpool runs the node's flux exit channels.
//
// A flux channel carries one client at a time, so a node serves a pool of
// them: one running exit instance per enabled channel. They run in this
// process rather than as children, because the flux stack is part of this
// repository now (see internal/flux) and ten channels would otherwise mean ten
// processes for what is ten goroutine trees.
//
// The pool reconciles rather than remembering: given the channels a desired
// state asks for, it starts what is missing, stops what is gone, and restarts
// only what actually changed. That makes applying the same state twice free,
// which is what lets a reconnecting agent re-apply without disturbing anyone's
// session.
package fluxpool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	fluxutils "github.com/thehavlok/whitenet/internal/flux/utils"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

// Options are what the agent knows and the state does not.
type Options struct {
	// CookieDir holds each channel's cookie jar, so a restart does not look
	// like a brand new browser to the carrier's website.
	CookieDir string
	Log       *slog.Logger
}

// Pool holds the running channels.
type Pool struct {
	opts Options
	log  *slog.Logger

	mu       sync.Mutex
	channels map[uint64]*running
	// mode is the exit mode the pool was last configured with. Changing it
	// restarts every channel, because it changes how the exit terminates
	// traffic.
	mode    string
	enabled bool
}

type running struct {
	id       uint64
	uuid     string
	instance *fluxnode.Instance
	// fingerprint is what decides whether a channel has to be restarted: it
	// covers everything that affects the running instance.
	fingerprint string
	startedAt   time.Time
	lastErr     string
}

// Status is one channel's state, for the heartbeat.
type Status struct {
	ChannelID uint64
	UUID      string
	// SessionActive is true when a client has completed the handshake. This
	// is what the panel means by a channel being in use, and what expires a
	// lease nobody is using.
	SessionActive bool
	Since         time.Time
	BytesSent     uint64
	BytesReceived uint64
	LastError     string
}

// New returns an empty pool.
func New(opts Options) *Pool {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	// The carriers keep their own log, with its own switch, and it is the
	// only place that says why a document would not open - a captcha, a
	// login redirect, a handshake that never came. Without this an operator
	// running the agent in debug sees "channel started" and nothing else.
	fluxutils.SetDebug(log.Enabled(context.Background(), slog.LevelDebug))
	return &Pool{
		opts:     opts,
		log:      log.With("core", "flux"),
		channels: map[uint64]*running{},
	}
}

// Apply reconciles the pool with the state's OpenFlux block.
//
// It returns the channels it started and stopped, so the agent can report them
// to the panel's journal. An error from one channel does not stop the others:
// a single bad document must not take the node's other channels down with it.
func (p *Pool) Apply(ctx context.Context, cfg *nodepb.OpenFluxConfig) (started, stopped []uint64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Absent or disabled means "stop everything".
	if cfg == nil || !cfg.GetEnabled() {
		stopped = p.stopAllLocked()
		p.enabled = false
		return nil, stopped, nil
	}

	mode := cfg.GetMode()
	if mode == "" {
		mode = "l4"
	}
	modeChanged := p.enabled && p.mode != mode
	p.mode, p.enabled = mode, true

	wanted := map[uint64]*nodepb.OpenFluxChannel{}
	for _, channel := range cfg.GetChannels() {
		if !channel.GetEnabled() {
			continue
		}
		wanted[channel.GetId()] = channel
	}

	// Stop what is gone or disabled.
	for id, current := range p.channels {
		if _, keep := wanted[id]; keep {
			continue
		}
		p.stopLocked(current)
		stopped = append(stopped, id)
	}

	// Start or restart the rest. Sorted so logs and events are in a stable
	// order, which makes two runs comparable.
	ids := make([]uint64, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var errs []error
	for _, id := range ids {
		channel := wanted[id]
		want := fingerprint(mode, channel)

		if current, ok := p.channels[id]; ok {
			if current.fingerprint == want && !modeChanged {
				continue // unchanged; leave the session alone
			}
			p.stopLocked(current)
			stopped = append(stopped, id)
		}

		instance, startErr := p.startChannel(mode, channel)
		if startErr != nil {
			errs = append(errs, startErr)
			// Record the failure so the panel can show which channel is
			// broken instead of only that something is.
			p.channels[id] = &running{
				id: id, uuid: channel.GetUuid(),
				fingerprint: want, lastErr: startErr.Error(),
			}
			continue
		}
		p.channels[id] = &running{
			id: id, uuid: channel.GetUuid(), instance: instance,
			fingerprint: want, startedAt: time.Now(),
		}
		started = append(started, id)
	}
	return started, stopped, errors.Join(errs...)
}

// startChannel builds and starts one exit instance.
func (p *Pool) startChannel(mode string, channel *nodepb.OpenFluxChannel) (*fluxnode.Instance, error) {
	carriers, err := carriersFor(channel)
	if err != nil {
		return nil, err
	}

	cfg := fluxnode.DefaultConfig()
	cfg.Exit = true
	cfg.Mode = mode
	cfg.Carriers = carriers
	cfg.Secret = channel.GetEncryptionKey()
	cfg.Context = channel.GetSessionContext()
	// More than one carrier needs a session, and a session needs a secret.
	// Asking for one explicitly whenever a secret exists also means a single
	// carrier gets the authenticated handshake rather than the classic path.
	cfg.Negotiate = cfg.Secret != "" && len(carriers) > 1
	cfg.Log = p.log.With("channel", channel.GetId())
	if p.opts.CookieDir != "" {
		cfg.CookieStorePath = filepath.Join(p.opts.CookieDir,
			fmt.Sprintf("flux-%d.json", channel.GetId()))
	}

	instance, err := fluxnode.Start(cfg)
	if err != nil {
		return nil, fmt.Errorf("fluxpool: channel %d (%s): %w", channel.GetId(), channel.GetTransport(), err)
	}
	p.log.Info("channel started",
		"channel", channel.GetId(), "transport", channel.GetTransport(), "mode", mode)
	return instance, nil
}

// carriersFor turns a channel into flux carriers.
//
// A channel names one transport and may carry extra ones through
// params["carriers"], which is "type:url@priority" separated by commas. The
// panel writes that form so one channel can have a fast direct carrier and a
// document as a fallback without the schema needing a nested list.
func carriersFor(channel *nodepb.OpenFluxChannel) ([]fluxnode.Carrier, error) {
	params := map[string]string{}
	for k, v := range channel.GetParams() {
		params[k] = v
	}

	primaryType := channel.GetTransport()
	if primaryType == "" {
		return nil, fmt.Errorf("fluxpool: channel %d has no transport", channel.GetId())
	}
	if !fluxnode.ValidCarrier(primaryType) {
		return nil, fmt.Errorf("fluxpool: channel %d: unknown transport %q", channel.GetId(), primaryType)
	}

	extra := params["carriers"]
	delete(params, "carriers")

	primary := fluxnode.Carrier{
		Type:     primaryType,
		URL:      channel.GetUrl(),
		Priority: 50,
		Params:   params,
	}
	if v := params["priority"]; v != "" {
		primary.Priority = atoiOr(v, 50)
	}
	carriers := []fluxnode.Carrier{primary}

	for _, spec := range splitList(extra) {
		carrier, err := parseCarrierSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("fluxpool: channel %d: %w", channel.GetId(), err)
		}
		carriers = append(carriers, carrier)
	}

	// Two carriers of the same type need distinct names; the primary keeps
	// the bare type so a single-carrier channel reads naturally.
	seen := map[string]int{}
	for i := range carriers {
		name := carriers[i].Name
		if name == "" {
			name = carriers[i].Type
		}
		if count := seen[name]; count > 0 {
			name = fmt.Sprintf("%s-%d", name, count+1)
		}
		seen[name]++
		carriers[i].Name = name
	}
	return carriers, nil
}

// parseCarrierSpec reads "type:url@priority". The url may contain colons, so
// the type is cut at the first one and the priority at the last @.
func parseCarrierSpec(spec string) (fluxnode.Carrier, error) {
	carrierType, rest, found := strings.Cut(spec, ":")
	if !found {
		// A bare type is valid for direct, which has no url.
		carrierType, rest = spec, ""
	}
	carrierType = strings.TrimSpace(carrierType)
	if !fluxnode.ValidCarrier(carrierType) {
		return fluxnode.Carrier{}, fmt.Errorf("unknown carrier type %q in %q", carrierType, spec)
	}

	priority := 50
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		if n, err := parseInt(rest[at+1:]); err == nil {
			priority = n
			rest = rest[:at]
		}
	}

	carrier := fluxnode.Carrier{Type: carrierType, Priority: priority, Params: map[string]string{}}
	switch carrierType {
	case fluxnode.CarrierDirect:
		// For an exit, direct takes a listen address rather than a url.
		carrier.Params["listen"] = strings.TrimSpace(rest)
	default:
		carrier.URL = strings.TrimSpace(rest)
	}
	return carrier, nil
}

// fingerprint covers everything that would make a running channel wrong.
// Changing anything in it restarts the channel; changing nothing leaves the
// session alone.
func fingerprint(mode string, channel *nodepb.OpenFluxChannel) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}
	write(mode, channel.GetTransport(), channel.GetUrl(),
		channel.GetEncryptionKey(), channel.GetSessionContext())

	keys := make([]string, 0, len(channel.GetParams()))
	for k := range channel.GetParams() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		write(k, channel.GetParams()[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Status reports every channel the pool knows about.
func (p *Pool) Status() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]Status, 0, len(p.channels))
	for _, current := range p.channels {
		status := Status{
			ChannelID: current.id,
			UUID:      current.uuid,
			Since:     current.startedAt,
			LastError: current.lastErr,
		}
		if current.instance != nil {
			status.SessionActive = current.instance.SessionActive()
			stats := current.instance.Stats()
			status.BytesSent = stats.BytesSent
			status.BytesReceived = stats.BytesReceived
		}
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChannelID < out[j].ChannelID })
	return out
}

// ActiveSessions counts the channels currently carrying a client. It is the
// node's flux user count for the heartbeat.
func (p *Pool) ActiveSessions() int {
	var n int
	for _, status := range p.Status() {
		if status.SessionActive {
			n++
		}
	}
	return n
}

// Running reports whether any channel is up, which is what the agent reports
// as the flux core being up.
func (p *Pool) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, current := range p.channels {
		if current.instance != nil {
			return true
		}
	}
	return false
}

// RestartChannel restarts one channel, which is how the panel revokes a lease
// the hard way.
func (p *Pool) RestartChannel(ctx context.Context, id uint64) error {
	p.mu.Lock()
	current, ok := p.channels[id]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("fluxpool: channel %d is not running here", id)
	}
	if current.instance == nil {
		return fmt.Errorf("fluxpool: channel %d is not running: %s", id, current.lastErr)
	}
	// The pool has no copy of the channel's configuration beyond its
	// fingerprint, so a restart means stopping it and letting the next Apply
	// bring it back. The agent re-applies its state right after.
	p.mu.Lock()
	p.stopLocked(current)
	p.mu.Unlock()
	return nil
}

// Stop shuts every channel down.
func (p *Pool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopAllLocked()
	p.enabled = false
}

func (p *Pool) stopAllLocked() []uint64 {
	stopped := make([]uint64, 0, len(p.channels))
	for id, current := range p.channels {
		p.stopLocked(current)
		stopped = append(stopped, id)
	}
	sort.Slice(stopped, func(i, j int) bool { return stopped[i] < stopped[j] })
	return stopped
}

// stopLocked stops one channel and forgets it. The caller holds the mutex.
func (p *Pool) stopLocked(current *running) {
	if current.instance != nil {
		if err := current.instance.Stop(); err != nil {
			p.log.Warn("channel did not stop cleanly", "channel", current.id, "error", err)
		}
		p.log.Info("channel stopped", "channel", current.id)
	}
	delete(p.channels, current.id)
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseInt(v string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}

func atoiOr(v string, fallback int) int {
	n, err := parseInt(v)
	if err != nil {
		return fallback
	}
	return n
}
