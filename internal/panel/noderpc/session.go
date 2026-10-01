package noderpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thehavlok/whitenet/internal/nodepb"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// keepaliveParams make the server notice a node that disappeared without
// closing its stream, which is how most of them go: a VPS reboot, a dropped
// route, a NAT entry that timed out.
func keepaliveParams() keepalive.ServerParameters {
	return keepalive.ServerParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}
}

// keepalivePolicy allows the agent's own keepalives. Without this the server
// would close connections from an agent that pings more often than the
// default minimum.
func keepalivePolicy() keepalive.EnforcementPolicy {
	return keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second,
		PermitWithoutStream: true,
	}
}

// Session is the one long-lived call. The agent opens it and keeps it open;
// losing it is what "offline" means.
func (s *Server) Session(stream nodepb.NodeControl_SessionServer) error {
	ctx := stream.Context()
	node, err := s.authenticate(ctx)
	if err != nil {
		return err
	}

	conn := s.hub.register(node.ID, node.UUID)
	defer func() {
		s.hub.unregister(conn)
		// A disconnect is recorded immediately rather than waiting for the
		// heartbeat timeout, so the panel reflects reality as soon as it
		// knows.
		disconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.store.NodeDisconnected(disconnectCtx, node.ID, "stream closed"); err != nil {
			s.log.Warn("could not record a disconnect", "node", node.UUID, "error", err)
		}
		_ = s.store.RecordEvent(disconnectCtx, store.NewEvent{
			Severity: "warning",
			Type:     "node_disconnected",
			NodeID:   &node.ID,
			Message:  fmt.Sprintf("node %s disconnected", node.Name),
		})
		s.log.Info("node disconnected", "node", node.UUID, "name", node.Name)
	}()

	// The writer is a separate goroutine so a push from an admin's request
	// never waits on the agent reading, and the reader is never blocked by a
	// slow write.
	writeErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				writeErr <- nil
				return
			case <-conn.closed:
				// Either the node was displaced by a newer connection or the
				// panel kicked it.
				writeErr <- status.Error(codes.Aborted, "this connection was replaced or closed by the panel")
				return
			case frame := <-conn.out:
				if err := stream.Send(frame); err != nil {
					writeErr <- err
					return
				}
			}
		}
	}()

	for {
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := s.handleAgentFrame(ctx, node, conn, frame); err != nil {
			s.log.Error("could not handle an agent frame",
				"node", node.UUID, "error", err)
		}

		// A write failure means the stream is gone; stop reading.
		select {
		case err := <-writeErr:
			return err
		default:
		}
	}
}

// handleAgentFrame acts on one frame from an agent.
func (s *Server) handleAgentFrame(ctx context.Context, node *store.Node, conn *connection, frame *nodepb.AgentFrame) error {
	switch body := frame.GetBody().(type) {
	case *nodepb.AgentFrame_Hello:
		return s.handleHello(ctx, node, body.Hello)

	case *nodepb.AgentFrame_Heartbeat:
		return s.handleHeartbeat(ctx, node, body.Heartbeat)

	case *nodepb.AgentFrame_StateApplied:
		return s.handleStateApplied(ctx, node, body.StateApplied)

	case *nodepb.AgentFrame_Metrics:
		return s.handleMetrics(ctx, node, body.Metrics)

	case *nodepb.AgentFrame_Traffic:
		return s.handleTraffic(ctx, node, body.Traffic)

	case *nodepb.AgentFrame_Channels:
		return s.handleChannels(ctx, node, body.Channels)

	case *nodepb.AgentFrame_Event:
		return s.handleEvents(ctx, node, body.Event)

	case *nodepb.AgentFrame_CommandResult:
		return s.handleCommandResult(ctx, node, body.CommandResult)

	case *nodepb.AgentFrame_LogChunk:
		s.collectLog(body.LogChunk)
		return nil

	default:
		// A frame from a newer agent is not an error: ignoring it is what
		// lets the fleet be upgraded before the panel.
		s.log.Debug("ignoring an unknown frame from an agent", "node", node.UUID)
		return nil
	}
}

// handleHello records the agent's arrival and sends state when it is stale.
//
// The version the agent reports is what makes a reconnect cheap: a node that
// is already current gets an acknowledgement and nothing else.
func (s *Server) handleHello(ctx context.Context, node *store.Node, hello *nodepb.Hello) error {
	if err := s.store.NodeConnected(ctx, node.ID,
		hello.GetAgentVersion(),
		hello.GetCores().GetXray(),
		hello.GetCores().GetWndns(),
		hello.GetCores().GetOpenflux(),
		hostInfo(hello.GetHost())); err != nil {
		return err
	}
	_ = s.store.RecordEvent(ctx, store.NewEvent{
		Severity: "info",
		Type:     "node_connected",
		NodeID:   &node.ID,
		Message:  fmt.Sprintf("node %s connected", node.Name),
		Details: map[string]any{
			"agent_version": hello.GetAgentVersion(),
			"state_version": hello.GetStateVersion(),
		},
	})

	// Re-read the node: the version may have moved while the agent was away.
	current, err := s.store.NodeByID(ctx, node.ID)
	if err != nil {
		return err
	}
	stale := hello.GetStateVersion() != current.ConfigVersion

	if err := s.hub.Send(node.ID, &nodepb.ServerFrame{
		Body: &nodepb.ServerFrame_HelloAck{HelloAck: &nodepb.HelloAck{
			ServerTime:   timestamppb.Now(),
			StateFollows: stale,
		}},
	}); err != nil {
		return err
	}

	s.log.Info("node connected",
		"node", node.UUID, "name", node.Name,
		"agent_version", hello.GetAgentVersion(),
		"agent_state", hello.GetStateVersion(),
		"panel_state", current.ConfigVersion)

	if !stale {
		// The agent reports what it applied, so record it rather than
		// leaving applied_version behind after a panel restart.
		return s.store.SetNodeApplied(ctx, node.ID, hello.GetStateVersion(), "")
	}
	return s.PushState(ctx, node.ID)
}

// PushState renders and sends a node's desired state.
//
// It is exported because the API calls it after any change: the version is
// bumped in the database and the node is told, rather than the node polling.
func (s *Server) PushState(ctx context.Context, nodeID uint64) error {
	state, err := s.renderer.Render(ctx, nodeID)
	if err != nil {
		return err
	}
	// Snapshot it, encrypted: it carries every user secret and Reality
	// private key for that node, and it makes "what did we send" answerable.
	if raw, err := marshalState(state); err == nil {
		if sealed, err := s.box.Seal(raw); err == nil {
			if err := s.store.SaveDesiredState(ctx, nodeID, state.GetVersion(), sealed); err != nil {
				s.log.Warn("could not store the desired state", "node", nodeID, "error", err)
			}
		}
	}
	return s.hub.SendState(nodeID, state)
}

func (s *Server) handleHeartbeat(ctx context.Context, node *store.Node, beat *nodepb.Heartbeat) error {
	// A core that is not running, or one that keeps restarting, makes the
	// node degraded rather than offline: it is reachable but not well.
	var degraded string
	for _, core := range beat.GetCores() {
		if !core.GetRunning() {
			degraded = fmt.Sprintf("%s is not running", coreName(core.GetCore()))
			break
		}
		if core.GetLastError() != "" {
			degraded = fmt.Sprintf("%s: %s", coreName(core.GetCore()), core.GetLastError())
		}
	}
	if err := s.store.NodeHeartbeat(ctx, node.ID, beat.GetOnlineUsers(), degraded); err != nil {
		return err
	}

	// A version that drifted means the node missed a push; send it again.
	// This is the safety net behind "the panel tells the node", so a lost
	// frame does not leave a node stale forever.
	current, err := s.store.NodeByID(ctx, node.ID)
	if err != nil {
		return err
	}
	if beat.GetStateVersion() != current.ConfigVersion {
		s.log.Info("node is behind, resending state",
			"node", node.UUID, "node_version", beat.GetStateVersion(), "panel_version", current.ConfigVersion)
		return s.PushState(ctx, node.ID)
	}
	return nil
}

func (s *Server) handleStateApplied(ctx context.Context, node *store.Node, applied *nodepb.StateApplied) error {
	errText := ""
	if !applied.GetOk() {
		errText = applied.GetError()
	}
	if err := s.store.SetNodeApplied(ctx, node.ID, applied.GetVersion(), errText); err != nil {
		return err
	}

	severity, message := "info", fmt.Sprintf("node %s applied state %d", node.Name, applied.GetVersion())
	if !applied.GetOk() {
		severity = "error"
		message = fmt.Sprintf("node %s could not apply state %d: %s", node.Name, applied.GetVersion(), applied.GetError())
		s.log.Error("node could not apply state",
			"node", node.UUID, "version", applied.GetVersion(), "error", applied.GetError())
	}
	restarted := make([]string, 0, len(applied.GetRestarted()))
	for _, core := range applied.GetRestarted() {
		restarted = append(restarted, coreName(core))
	}
	return s.store.RecordEvent(ctx, store.NewEvent{
		Severity: severity,
		Type:     "state_applied",
		NodeID:   &node.ID,
		Message:  message,
		Details:  map[string]any{"version": applied.GetVersion(), "restarted": restarted},
	})
}

func (s *Server) handleMetrics(ctx context.Context, node *store.Node, report *nodepb.MetricsReport) error {
	samples := make([]store.MetricSample, 0, len(report.GetSamples()))
	for _, sample := range report.GetSamples() {
		samples = append(samples, store.MetricSample{
			At:             sample.GetAt().AsTime(),
			CPUPercent:     nullFloat(sample.GetCpuPercent()),
			Load1:          nullFloat(sample.GetLoad1()),
			MemUsedBytes:   nullInt(int64(sample.GetMemUsedBytes())),
			MemTotalBytes:  nullInt(int64(sample.GetMemTotalBytes())),
			DiskUsedBytes:  nullInt(int64(sample.GetDiskUsedBytes())),
			DiskTotalBytes: nullInt(int64(sample.GetDiskTotalBytes())),
			NetRxBytes:     nullInt(int64(sample.GetNetRxBytes())),
			NetTxBytes:     nullInt(int64(sample.GetNetTxBytes())),
			UptimeSeconds:  nullInt(int64(sample.GetUptimeSeconds())),
			OnlineUsers:    nullInt(int64(sample.GetOnlineUsers())),
			TCPConnections: nullInt(int64(sample.GetTcpConnections())),
		})
	}
	return s.store.InsertMetrics(ctx, node.ID, samples)
}

// handleTraffic records a report and enforces the limits it just tripped.
func (s *Server) handleTraffic(ctx context.Context, node *store.Node, report *nodepb.TrafficReport) error {
	deltas := make([]store.TrafficDelta, 0, len(report.GetDeltas()))
	for _, delta := range report.GetDeltas() {
		deltas = append(deltas, store.TrafficDelta{
			UserID:        delta.GetUserId(),
			InboundTag:    delta.GetInboundTag(),
			UplinkBytes:   delta.GetUplinkBytes(),
			DownlinkBytes: delta.GetDownlinkBytes(),
		})
	}
	at := report.GetAt().AsTime()
	if at.IsZero() {
		at = time.Now().UTC()
	}

	overLimit, err := s.store.ApplyTrafficReport(ctx, node.ID, at, report.GetBatchId(), deltas)
	if err != nil {
		return err
	}
	if len(overLimit) == 0 {
		return nil
	}

	// Someone just ran out. Enforcing it here rather than waiting for the
	// periodic job is what makes a limit a limit.
	expired, limited, err := s.store.EnforceLimits(ctx)
	if err != nil {
		return err
	}
	for _, userID := range append(append([]uint64{}, expired...), limited...) {
		// A flux channel is held by a lease, and a user who is out of
		// traffic must not keep holding one.
		if err := s.store.RevokeUserLeases(ctx, userID); err != nil {
			s.log.Warn("could not release a user's leases", "user", userID, "error", err)
		}
		id := userID
		_ = s.store.RecordEvent(ctx, store.NewEvent{
			Severity: "warning",
			Type:     "user_limit_reached",
			UserID:   &id,
			Message:  fmt.Sprintf("user %d was disabled: out of traffic or expired", userID),
		})
	}
	// The nodes were bumped by EnforceLimits; push to the ones connected.
	s.PushToConnected(ctx)
	return nil
}

// PushToConnected sends the current state to every connected node whose
// version has moved. The API calls it after a change that affects many nodes.
func (s *Server) PushToConnected(ctx context.Context) {
	for _, nodeID := range s.hub.ConnectedNodes() {
		node, err := s.store.NodeByID(ctx, nodeID)
		if err != nil {
			continue
		}
		if node.InSync() {
			continue
		}
		if err := s.PushState(ctx, nodeID); err != nil {
			s.log.Warn("could not push state", "node", node.UUID, "error", err)
		}
	}
}

func (s *Server) handleChannels(ctx context.Context, node *store.Node, report *nodepb.ChannelReport) error {
	for _, channel := range report.GetChannels() {
		if err := s.store.SetChannelStatus(ctx, channel.GetChannelId(),
			channel.GetSessionActive(), channel.GetLastError()); err != nil {
			s.log.Warn("could not record a channel's status",
				"node", node.UUID, "channel", channel.GetChannelId(), "error", err)
		}
	}
	// A channel with no session frees its lease sooner than the expiry would,
	// which keeps a small pool usable.
	if _, err := s.store.ExpireLeases(ctx); err != nil {
		s.log.Warn("could not expire leases", "error", err)
	}
	return nil
}

func (s *Server) handleEvents(ctx context.Context, node *store.Node, report *nodepb.EventReport) error {
	for _, event := range report.GetEvents() {
		nodeID := node.ID
		if err := s.store.RecordEvent(ctx, store.NewEvent{
			At:       event.GetAt().AsTime(),
			Severity: event.GetSeverity(),
			Type:     event.GetType(),
			Core:     coreName(event.GetCore()),
			NodeID:   &nodeID,
			Message:  event.GetMessage(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleCommandResult(ctx context.Context, node *store.Node, result *nodepb.CommandResult) error {
	severity := "info"
	message := fmt.Sprintf("command %s on node %s succeeded", result.GetCommandId(), node.Name)
	if !result.GetOk() {
		severity = "error"
		message = fmt.Sprintf("command %s on node %s failed: %s",
			result.GetCommandId(), node.Name, result.GetError())
	}
	nodeID := node.ID
	return s.store.RecordEvent(ctx, store.NewEvent{
		Severity: severity,
		Type:     "command_result",
		NodeID:   &nodeID,
		Message:  message,
		Details:  map[string]any{"command_id": result.GetCommandId(), "data": result.GetData()},
	})
}

// ---------------------------------------------------------------------------
// Node logs
// ---------------------------------------------------------------------------

// FetchLog asks a node for its core log and waits for the answer.
//
// Logs are pulled on demand rather than streamed: nodes are remote and logs
// are large, and an operator only wants them when something is wrong.
func (s *Server) FetchLog(ctx context.Context, nodeID uint64, core nodepb.Core, lines int, timeout time.Duration) (string, error) {
	commandID := fmt.Sprintf("log-%d-%d", nodeID, time.Now().UnixNano())
	result := &logResult{done: make(chan struct{}), core: core}

	s.logsMu.Lock()
	s.logs[commandID] = result
	s.logsMu.Unlock()
	defer func() {
		s.logsMu.Lock()
		delete(s.logs, commandID)
		s.logsMu.Unlock()
	}()

	if err := s.hub.SendCommand(nodeID, &nodepb.Command{
		CommandId: commandID,
		Type:      nodepb.CommandType_COMMAND_FETCH_LOGS,
		Core:      core,
		Args:      map[string]string{"lines": fmt.Sprint(lines)},
		Deadline:  timestamppb.New(time.Now().Add(timeout)),
	}); err != nil {
		return "", err
	}

	select {
	case <-result.done:
		return result.text.String(), nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(timeout):
		return "", errors.New("noderpc: the node did not answer with its log in time")
	}
}

// collectLog accumulates a log answer.
func (s *Server) collectLog(chunk *nodepb.LogChunk) {
	s.logsMu.Lock()
	result, ok := s.logs[chunk.GetRequestId()]
	s.logsMu.Unlock()
	if !ok {
		// Nobody is waiting any more; the request timed out.
		return
	}
	if result.text.Len() < s.opts.LogBuffer {
		result.text.WriteString(chunk.GetText())
	}
	if chunk.GetLast() {
		close(result.done)
	}
}

// Hub exposes the connection registry, so the API can ask whether a node is
// reachable and push commands.
func (s *Server) Hub() *Hub { return s.hub }

func coreName(core nodepb.Core) string {
	switch core {
	case nodepb.Core_CORE_XRAY:
		return "xray"
	case nodepb.Core_CORE_WNDNS:
		return "wndns"
	case nodepb.Core_CORE_OPENFLUX:
		return "openflux"
	default:
		return ""
	}
}
