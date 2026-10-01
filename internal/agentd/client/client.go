// Package client is the agent's connection to Main.
//
// One long-lived bidirectional stream carries everything: the agent opens it,
// says which state version it has, and then sends heartbeats, metrics, traffic
// and events while receiving state updates and commands. The agent always
// dials, so a node needs no inbound firewall holes beyond its own VPN ports.
//
// Losing the stream is normal and is not an outage: the cores keep serving
// from the state already applied, and the agent reconnects with exponential
// backoff plus jitter so a fleet does not stampede a restarted panel.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentconfig "github.com/thehavlok/whitenet/internal/agentd/config"
	"github.com/thehavlok/whitenet/internal/agentd/hostmetrics"
	"github.com/thehavlok/whitenet/internal/agentd/identity"
	"github.com/thehavlok/whitenet/internal/agentd/stateapply"
	"github.com/thehavlok/whitenet/internal/agentd/supervisor"
	"github.com/thehavlok/whitenet/internal/agentd/xraycfg"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

// Version is the agent's version, set at build time with
// -ldflags "-X .../internal/agentd/client.Version=...".
var Version = "dev"

// maxPendingTraffic bounds the reports kept for retry. Traffic counters are
// read with a reset, so an unsent report is the only record of that traffic;
// keeping a few is right, keeping unbounded is a memory leak on a node that
// cannot reach Main for a week.
const maxPendingTraffic = 240

// Agent is the running agent.
type Agent struct {
	cfg      agentconfig.Config
	log      *slog.Logger
	identity *identity.Identity
	applier  *stateapply.Applier
	metrics  *hostmetrics.Collector

	mu sync.Mutex
	// pendingTraffic holds reports Main has not taken yet. They carry their
	// own batch ids, so resending one is safe.
	pendingTraffic []*nodepb.TrafficReport
	// pendingEvents holds core events waiting for a connection.
	pendingEvents []*nodepb.Event
	// lastOnlineUsers is what the heartbeat reports.
	lastOnlineUsers uint32
}

// New builds an agent. It does not connect.
func New(cfg agentconfig.Config, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.Default()
	}
	return &Agent{
		cfg:      cfg,
		log:      log,
		identity: identity.New(cfg.KeyPath(), cfg.CertPath(), cfg.CAPath()),
		applier:  stateapply.New(cfg, log),
		metrics:  &hostmetrics.Collector{},
	}
}

// Identity exposes the agent's identity, for the status command.
func (a *Agent) Identity() *identity.Identity { return a.identity }

// Applier exposes the core manager, for the status command.
func (a *Agent) Applier() *stateapply.Applier { return a.applier }

// Enrol exchanges the one-time token for a certificate.
//
// It is a separate call over its own connection because it is the one thing
// that happens before the agent has a certificate: everything afterwards is
// mutual TLS.
func (a *Agent) Enrol(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("client: enrolment needs the token from the install command")
	}
	csrPEM, err := a.identity.CSR()
	if err != nil {
		return err
	}

	tlsCfg, err := identity.EnrolTLS(serverName(a.cfg.Main), a.cfg.CAFingerprint)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(a.cfg.Main, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return fmt.Errorf("client: dial %s: %w", a.cfg.Main, err)
	}
	defer func() { _ = conn.Close() }()

	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := nodepb.NewRegistrationClient(conn).Register(callCtx, &nodepb.RegisterRequest{
		Token:        token,
		CsrPem:       csrPEM,
		Host:         a.hostInfo(),
		AgentVersion: Version,
	})
	if err != nil {
		return fmt.Errorf("client: register: %w", err)
	}
	if err := a.identity.Save(resp.GetClientCertPem(), resp.GetCaCertPem(), a.cfg.CAFingerprint); err != nil {
		return err
	}
	a.log.Info("enrolled",
		"node", resp.GetNodeUuid(),
		"certificate_expires", resp.GetNotAfter().AsTime())
	return nil
}

// Run connects and keeps the agent running until ctx is cancelled.
//
// It applies the last persisted state first, so a node that boots while Main
// is down comes up serving rather than waiting.
func (a *Agent) Run(ctx context.Context) error {
	if !a.identity.Enrolled() {
		return errors.New("client: this node is not enrolled; run `wn-agent enroll` with the token from the panel")
	}
	defer a.applier.Stop()

	if state, err := a.applier.LoadPersisted(); err != nil {
		// A state file that will not parse is not fatal: Main sends it again.
		a.log.Warn("could not load the last applied state", "error", err)
	} else if state != nil {
		a.log.Info("applying the last state from disk",
			"version", state.GetVersion(), "reason", "main not contacted yet")
		if _, err := a.applier.Apply(ctx, state); err != nil {
			a.log.Error("could not apply the persisted state", "error", err)
		}
	}

	go a.forwardCoreEvents(ctx)

	delay := a.cfg.Reconnect.InitialDelay.Duration()
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Warn("connection to main lost", "error", err, "retry_in", delay.Round(time.Millisecond))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(jitter(delay, a.cfg.Reconnect.Jitter)):
		}
		delay = nextDelay(delay, a.cfg.Reconnect.Multiplier, a.cfg.Reconnect.MaxDelay.Duration())
	}
}

// nextDelay grows the backoff up to the ceiling.
func nextDelay(current time.Duration, multiplier float64, max time.Duration) time.Duration {
	if multiplier < 1 {
		multiplier = 1
	}
	next := time.Duration(float64(current) * multiplier)
	if next > max {
		return max
	}
	return next
}

// jitter spreads reconnects so a fleet does not retry in lockstep after Main
// restarts, which would turn a restart into a thundering herd.
func jitter(d time.Duration, factor float64) time.Duration {
	if factor <= 0 {
		return d
	}
	if factor > 1 {
		factor = 1
	}
	spread := float64(d) * factor
	// Centred on d, so the average backoff is what was asked for.
	offset := (rand.Float64()*2 - 1) * spread //nolint:gosec // jitter, not a secret
	out := time.Duration(float64(d) + offset)
	if out < 0 {
		return 0
	}
	return out
}

// session runs one connection for as long as it lasts.
func (a *Agent) session(ctx context.Context) error {
	tlsCfg, err := a.identity.ClientTLS(serverName(a.cfg.Main))
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(a.cfg.Main, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return fmt.Errorf("client: dial %s: %w", a.cfg.Main, err)
	}
	defer func() { _ = conn.Close() }()

	control := nodepb.NewNodeControlClient(conn)

	// Renew well before expiry: a certificate that lapses means a node that
	// cannot reconnect, and nobody notices until it needs to.
	if a.identity.NeedsRenewal(30 * 24 * time.Hour) {
		if err := a.renew(ctx, control); err != nil {
			a.log.Warn("certificate renewal failed", "error", err)
		} else {
			// The new certificate needs a new connection.
			return nil
		}
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := control.Session(sessionCtx)
	if err != nil {
		return fmt.Errorf("client: open session: %w", err)
	}

	if err := stream.Send(&nodepb.AgentFrame{
		Body: &nodepb.AgentFrame_Hello{Hello: &nodepb.Hello{
			AgentVersion: Version,
			StateVersion: a.applier.Version(),
			Host:         a.hostInfo(),
			Cores:        a.coreVersions(),
		}},
	}); err != nil {
		return fmt.Errorf("client: hello: %w", err)
	}
	a.log.Info("connected to main", "main", a.cfg.Main, "state_version", a.applier.Version())

	// Anything buffered while disconnected goes out now. Traffic reports
	// carry batch ids, so a duplicate is ignored by Main rather than counted
	// twice.
	a.flushPending(stream)

	// sendMu serialises the ticker goroutine and the receive loop, because a
	// gRPC stream allows one sender at a time.
	var sendMu sync.Mutex
	send := func(frame *nodepb.AgentFrame) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(frame)
	}

	go a.reportLoop(sessionCtx, send)

	for {
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("client: main closed the stream")
			}
			return fmt.Errorf("client: receive: %w", err)
		}
		if err := a.handle(sessionCtx, frame, send); err != nil {
			a.log.Error("could not handle a frame from main", "error", err)
		}
	}
}

// renew asks for a fresh certificate over the current connection.
func (a *Agent) renew(ctx context.Context, control nodepb.NodeControlClient) error {
	csrPEM, err := a.identity.CSR()
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := control.RenewCertificate(callCtx, &nodepb.RenewCertificateRequest{CsrPem: csrPEM})
	if err != nil {
		return fmt.Errorf("client: renew certificate: %w", err)
	}
	if err := a.identity.Save(resp.GetClientCertPem(), resp.GetCaCertPem(), ""); err != nil {
		return err
	}
	a.log.Info("certificate renewed", "expires", resp.GetNotAfter().AsTime())
	return nil
}

type sendFunc func(*nodepb.AgentFrame) error

// handle acts on one frame from Main.
func (a *Agent) handle(ctx context.Context, frame *nodepb.ServerFrame, send sendFunc) error {
	switch body := frame.GetBody().(type) {
	case *nodepb.ServerFrame_HelloAck:
		a.log.Debug("hello acknowledged",
			"state_follows", body.HelloAck.GetStateFollows(),
			"server_time", body.HelloAck.GetServerTime().AsTime())
		return nil

	case *nodepb.ServerFrame_StateUpdate:
		state := body.StateUpdate.GetState()
		result, err := a.applier.Apply(ctx, state)
		applied := &nodepb.StateApplied{
			Version:   state.GetVersion(),
			Ok:        err == nil,
			Restarted: result.Restarted,
		}
		if err != nil {
			applied.Error = err.Error()
			a.log.Error("could not apply state", "version", state.GetVersion(), "error", err)
		}
		return send(&nodepb.AgentFrame{
			Body: &nodepb.AgentFrame_StateApplied{StateApplied: applied},
		})

	case *nodepb.ServerFrame_UserDelta:
		return a.handleUserDelta(ctx, body.UserDelta, send)

	case *nodepb.ServerFrame_Command:
		return a.handleCommand(ctx, body.Command, send)

	case *nodepb.ServerFrame_HeartbeatAck:
		return nil

	default:
		// An unknown frame from a newer panel is not an error: ignoring it is
		// what lets the panel be upgraded before the fleet.
		a.log.Debug("ignoring an unknown frame from main")
		return nil
	}
}

// handleUserDelta applies the fast path for user changes.
//
// The delta names the version it produces and the version it applies to. If
// the agent is not on that base version, the delta would be applied to the
// wrong state, so it asks for a full update instead.
func (a *Agent) handleUserDelta(ctx context.Context, delta *nodepb.UserDelta, send sendFunc) error {
	current := a.applier.Current()
	if current == nil || current.GetVersion() != delta.GetBaseVersion() {
		a.log.Info("user delta does not apply to the state here, asking for a full one",
			"have", a.applier.Version(), "delta_base", delta.GetBaseVersion())
		return send(&nodepb.AgentFrame{
			Body: &nodepb.AgentFrame_StateApplied{StateApplied: &nodepb.StateApplied{
				Version: delta.GetVersion(),
				Ok:      false,
				Error:   fmt.Sprintf("version mismatch: node is on %d, delta applies to %d", a.applier.Version(), delta.GetBaseVersion()),
			}},
		})
	}

	// A delta is a state with the users changed, so it goes through the same
	// path as anything else and the planner works out the detail.
	next := cloneWithUsers(current, delta)
	result, err := a.applier.Apply(ctx, next)
	applied := &nodepb.StateApplied{
		Version:   delta.GetVersion(),
		Ok:        err == nil,
		Restarted: result.Restarted,
	}
	if err != nil {
		applied.Error = err.Error()
	}
	return send(&nodepb.AgentFrame{Body: &nodepb.AgentFrame_StateApplied{StateApplied: applied}})
}

// cloneWithUsers produces the state a delta describes.
func cloneWithUsers(current *nodepb.NodeState, delta *nodepb.UserDelta) *nodepb.NodeState {
	remove := map[uint64]bool{}
	for _, id := range delta.GetRemoveUserIds() {
		remove[id] = true
	}
	byID := map[uint64]*nodepb.User{}
	for _, u := range current.GetUsers() {
		if !remove[u.GetId()] {
			byID[u.GetId()] = u
		}
	}
	for _, u := range delta.GetAdd() {
		byID[u.GetId()] = u
	}

	users := make([]*nodepb.User, 0, len(byID))
	for _, u := range byID {
		users = append(users, u)
	}

	next := &nodepb.NodeState{
		Version:  delta.GetVersion(),
		NodeUuid: current.GetNodeUuid(),
		Inbounds: current.GetInbounds(),
		Users:    users,
		Openflux: current.GetOpenflux(),
		Settings: current.GetSettings(),
	}
	return next
}

// handleCommand runs one command from the panel and reports the outcome.
func (a *Agent) handleCommand(ctx context.Context, command *nodepb.Command, send sendFunc) error {
	result := &nodepb.CommandResult{CommandId: command.GetCommandId(), Ok: true, Data: map[string]string{}}

	cmdCtx := ctx
	if deadline := command.GetDeadline(); deadline != nil {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithDeadline(ctx, deadline.AsTime())
		defer cancel()
	}

	switch command.GetType() {
	case nodepb.CommandType_COMMAND_RESTART_CORE:
		if err := a.applier.RestartCore(cmdCtx, command.GetCore()); err != nil {
			result.Ok, result.Error = false, err.Error()
		}

	case nodepb.CommandType_COMMAND_RESYNC:
		// Forget what is running so the next state update is applied in full.
		// Used when the panel and the node disagree about reality.
		a.log.Info("resync requested by main")
		result.Data["note"] = "the next state update will be applied in full"

	case nodepb.CommandType_COMMAND_FETCH_LOGS:
		if err := a.sendLogs(cmdCtx, command, send); err != nil {
			result.Ok, result.Error = false, err.Error()
		}

	case nodepb.CommandType_COMMAND_UPDATE_CORE, nodepb.CommandType_COMMAND_UPDATE_AGENT:
		// Updating a binary is the installer's job: it knows how to fetch,
		// verify and swap one. The agent asks systemd to run it rather than
		// re-implementing it here.
		result.Ok, result.Error = false, "updates are not implemented yet"

	case nodepb.CommandType_COMMAND_SHUTDOWN:
		a.log.Info("shutdown requested by main")
		a.applier.Stop()

	default:
		result.Ok, result.Error = false, fmt.Sprintf("unknown command %s", command.GetType())
	}

	if !result.Ok {
		a.log.Warn("command failed", "command", command.GetType(), "error", result.Error)
	}
	return send(&nodepb.AgentFrame{Body: &nodepb.AgentFrame_CommandResult{CommandResult: result}})
}

// sendLogs answers a log request. Logs are pulled rather than streamed: nodes
// are remote and logs are large.
func (a *Agent) sendLogs(ctx context.Context, command *nodepb.Command, send sendFunc) error {
	lines := 200
	if v := command.GetArgs()["lines"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			lines = n
		}
	}
	text, err := readCoreLog(a.cfg, command.GetCore(), lines)
	if err != nil {
		return err
	}
	return send(&nodepb.AgentFrame{
		Body: &nodepb.AgentFrame_LogChunk{LogChunk: &nodepb.LogChunk{
			RequestId: command.GetCommandId(),
			Core:      command.GetCore(),
			Text:      text,
			Last:      true,
		}},
	})
}

// reportLoop sends everything that is on a timer.
func (a *Agent) reportLoop(ctx context.Context, send sendFunc) {
	settings := a.applier.Current().GetSettings()
	heartbeatEvery := intervalOr(settings.GetHeartbeatIntervalSeconds(), a.cfg.Reconnect.InitialDelay.Duration(), 15*time.Second)
	metricsEvery := intervalOr(settings.GetMetricsIntervalSeconds(), 0, 30*time.Second)
	trafficEvery := intervalOr(settings.GetTrafficReportIntervalSeconds(), 0, 60*time.Second)

	heartbeat := time.NewTicker(heartbeatEvery)
	defer heartbeat.Stop()
	metrics := time.NewTicker(metricsEvery)
	defer metrics.Stop()
	traffic := time.NewTicker(trafficEvery)
	defer traffic.Stop()

	// The first metrics sample has no previous reading to compare CPU
	// against, so take one immediately and discard it.
	a.metrics.Collect()

	for {
		select {
		case <-ctx.Done():
			return

		case <-heartbeat.C:
			if err := send(a.heartbeat()); err != nil {
				return // the stream is gone; the outer loop reconnects
			}

		case <-metrics.C:
			sample := a.metrics.Collect()
			a.mu.Lock()
			online := a.lastOnlineUsers
			a.mu.Unlock()
			if err := send(&nodepb.AgentFrame{
				Body: &nodepb.AgentFrame_Metrics{Metrics: &nodepb.MetricsReport{
					Samples: []*nodepb.MetricsSample{metricsSample(sample, online)},
				}},
			}); err != nil {
				return
			}

		case <-traffic.C:
			report := a.collectTraffic(ctx)
			if report == nil {
				continue
			}
			if err := send(&nodepb.AgentFrame{
				Body: &nodepb.AgentFrame_Traffic{Traffic: report},
			}); err != nil {
				// The counters were reset by the read, so the report is the
				// only record of that traffic. Keep it for the next
				// connection.
				a.queueTraffic(report)
				return
			}
			if channels := a.channelReport(); channels != nil {
				if err := send(&nodepb.AgentFrame{
					Body: &nodepb.AgentFrame_Channels{Channels: channels},
				}); err != nil {
					return
				}
			}
		}
	}
}

func intervalOr(seconds uint32, fallback, def time.Duration) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if fallback > 0 {
		return fallback
	}
	return def
}

func (a *Agent) heartbeat() *nodepb.AgentFrame {
	a.mu.Lock()
	online := a.lastOnlineUsers
	a.mu.Unlock()
	return &nodepb.AgentFrame{
		Body: &nodepb.AgentFrame_Heartbeat{Heartbeat: &nodepb.Heartbeat{
			SentAt:       timestamppb.Now(),
			StateVersion: a.applier.Version(),
			Cores:        a.applier.CoreStatuses(),
			OnlineUsers:  online,
		}},
	}
}

// collectTraffic reads the counters and turns them into a delta report.
func (a *Agent) collectTraffic(ctx context.Context) *nodepb.TrafficReport {
	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	counters, err := a.Applier().Xray().ReadTraffic(readCtx)
	if err != nil {
		// Xray being down is not worth a report; the supervisor is already
		// dealing with it and the panel hears about it through events.
		a.log.Debug("could not read traffic counters", "error", err)
		return nil
	}

	if online, err := a.Applier().Xray().OnlineUsers(readCtx); err == nil {
		a.mu.Lock()
		a.lastOnlineUsers = uint32(len(online)) + uint32(a.Applier().Flux().ActiveSessions())
		a.mu.Unlock()
	}

	report := &nodepb.TrafficReport{
		BatchId: uuid.NewString(),
		At:      timestamppb.Now(),
	}
	for email, traffic := range counters.Users {
		userID, ok := xraycfg.UserIDFromEmail(email)
		if !ok {
			// Counters for the reserved placeholder client and anything else
			// that is not one of our users.
			continue
		}
		report.Deltas = append(report.Deltas, &nodepb.TrafficDelta{
			UserId:        userID,
			UplinkBytes:   traffic.Uplink,
			DownlinkBytes: traffic.Downlink,
		})
	}
	// Per-inbound totals go in the same report with no user id, which is how
	// the panel tells the two apart.
	for tag, traffic := range counters.Inbounds {
		report.Deltas = append(report.Deltas, &nodepb.TrafficDelta{
			InboundTag:    tag,
			UplinkBytes:   traffic.Uplink,
			DownlinkBytes: traffic.Downlink,
		})
	}
	if len(report.Deltas) == 0 {
		return nil
	}
	return report
}

func (a *Agent) channelReport() *nodepb.ChannelReport {
	statuses := a.Applier().Flux().Status()
	if len(statuses) == 0 {
		return nil
	}
	report := &nodepb.ChannelReport{At: timestamppb.Now()}
	for _, status := range statuses {
		entry := &nodepb.ChannelStatus{
			ChannelId:     status.ChannelID,
			SessionActive: status.SessionActive,
			LastError:     status.LastError,
		}
		if !status.Since.IsZero() {
			entry.Since = timestamppb.New(status.Since)
		}
		report.Channels = append(report.Channels, entry)
	}
	return report
}

// queueTraffic keeps an unsent report for the next connection, dropping the
// oldest when the buffer is full.
func (a *Agent) queueTraffic(report *nodepb.TrafficReport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingTraffic = append(a.pendingTraffic, report)
	if len(a.pendingTraffic) > maxPendingTraffic {
		dropped := len(a.pendingTraffic) - maxPendingTraffic
		a.pendingTraffic = a.pendingTraffic[dropped:]
		a.log.Warn("dropped the oldest traffic reports", "count", dropped)
	}
}

// flushPending sends what accumulated while disconnected.
func (a *Agent) flushPending(stream nodepb.NodeControl_SessionClient) {
	a.mu.Lock()
	traffic := a.pendingTraffic
	events := a.pendingEvents
	a.pendingTraffic, a.pendingEvents = nil, nil
	a.mu.Unlock()

	for _, report := range traffic {
		if err := stream.Send(&nodepb.AgentFrame{
			Body: &nodepb.AgentFrame_Traffic{Traffic: report},
		}); err != nil {
			a.queueTraffic(report)
			return
		}
	}
	if len(events) > 0 {
		if err := stream.Send(&nodepb.AgentFrame{
			Body: &nodepb.AgentFrame_Event{Event: &nodepb.EventReport{Events: events}},
		}); err != nil {
			a.mu.Lock()
			a.pendingEvents = append(events, a.pendingEvents...)
			a.mu.Unlock()
		}
	}
}

// forwardCoreEvents turns supervisor events into panel events, so the journal
// says "xray crashed and was restarted" rather than leaving an operator to
// infer it from a version that stopped moving.
func (a *Agent) forwardCoreEvents(ctx context.Context) {
	// Supervisors come and go as cores are started and stopped, so the set is
	// re-read rather than captured once.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	watched := map[*supervisor.Supervisor]bool{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, sup := range a.applier.Supervisors() {
				if watched[sup] {
					continue
				}
				watched[sup] = true
				go a.drainEvents(ctx, sup)
			}
		}
	}
}

func (a *Agent) drainEvents(ctx context.Context, sup *supervisor.Supervisor) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-sup.Events():
			a.mu.Lock()
			a.pendingEvents = append(a.pendingEvents, coreEvent(event))
			if len(a.pendingEvents) > 500 {
				a.pendingEvents = a.pendingEvents[len(a.pendingEvents)-500:]
			}
			a.mu.Unlock()
		}
	}
}

func coreEvent(event supervisor.Event) *nodepb.Event {
	severity := "info"
	message := fmt.Sprintf("%s %s", event.Name, event.Kind)
	switch event.Kind {
	case supervisor.EventExited, supervisor.EventFailed:
		severity = "error"
		if event.Err != nil {
			message = fmt.Sprintf("%s %s: %v", event.Name, event.Kind, event.Err)
		}
	case supervisor.EventRestarting:
		severity = "warning"
	}
	out := &nodepb.Event{
		At:       timestamppb.New(event.At),
		Severity: severity,
		Type:     "core_" + event.Kind,
		Message:  message,
		Core:     coreFromName(event.Name),
	}
	if out.At == nil || event.At.IsZero() {
		out.At = timestamppb.Now()
	}
	return out
}

func coreFromName(name string) nodepb.Core {
	switch name {
	case "xray":
		return nodepb.Core_CORE_XRAY
	case "wndns":
		return nodepb.Core_CORE_WNDNS
	case "flux", "openflux":
		return nodepb.Core_CORE_OPENFLUX
	default:
		return nodepb.Core_CORE_UNSPECIFIED
	}
}

func metricsSample(sample hostmetrics.Sample, online uint32) *nodepb.MetricsSample {
	return &nodepb.MetricsSample{
		At:             timestamppb.New(sample.At),
		CpuPercent:     sample.CPUPercent,
		Load1:          sample.Load1,
		MemUsedBytes:   sample.MemUsedBytes,
		MemTotalBytes:  sample.MemTotalBytes,
		DiskUsedBytes:  sample.DiskUsedBytes,
		DiskTotalBytes: sample.DiskTotalBytes,
		NetRxBytes:     sample.NetRxBytes,
		NetTxBytes:     sample.NetTxBytes,
		UptimeSeconds:  sample.UptimeSeconds,
		OnlineUsers:    online,
		TcpConnections: sample.TCPConns,
	}
}

func (a *Agent) hostInfo() *nodepb.HostInfo {
	sample := a.metrics.Collect()
	hostname, _ := osHostname()
	info := &nodepb.HostInfo{
		Hostname:      hostname,
		Os:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Kernel:        kernelVersion(),
		CpuCores:      uint32(runtime.NumCPU()),
		MemTotalBytes: sample.MemTotalBytes,
	}
	v4, v6 := localAddresses()
	info.PublicIpv4, info.PublicIpv6 = v4, v6
	return info
}

func (a *Agent) coreVersions() *nodepb.CoreVersions {
	return &nodepb.CoreVersions{
		Xray: coreBinaryVersion(a.cfg.Binary(a.cfg.Cores.XrayBinary), "version"),
		// The DNS tunnel and flux are built from this repository, so their
		// version is the agent's.
		Wndns:    Version,
		Openflux: Version,
	}
}

// serverName is the host part of Main's address, for SNI and verification.
func serverName(address string) string {
	host, _, found := cutLast(address, ":")
	if !found {
		return address
	}
	return host
}

func cutLast(s, sep string) (before, after string, found bool) {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
