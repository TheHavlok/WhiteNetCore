package noderpc

import (
	"errors"
	"sync"
	"time"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

// ErrNotConnected is returned when the panel tries to reach a node whose agent
// is not currently connected.
var ErrNotConnected = errors.New("noderpc: the node's agent is not connected")

// ErrQueueFull is returned when a node's outbound queue is full, which means
// its agent is not reading - a stuck connection rather than a busy one.
var ErrQueueFull = errors.New("noderpc: the node's outbound queue is full")

// Hub tracks the connected agents so the rest of the panel can push state and
// commands without knowing anything about gRPC.
//
// One connection per node: a second one for the same node replaces the first,
// because the usual cause is a network partition where the old stream is dead
// but nobody has noticed yet.
type Hub struct {
	mu    sync.RWMutex
	nodes map[uint64]*connection
}

type connection struct {
	nodeID      uint64
	nodeUUID    string
	connectedAt time.Time
	// out is the queue the stream's writer drains. Buffered, so a push does
	// not block on the network.
	out chan *nodepb.ServerFrame
	// closed is closed when the connection ends, so a push can tell a dead
	// connection from a slow one.
	closed chan struct{}
	once   sync.Once
}

func (c *connection) close() {
	c.once.Do(func() { close(c.closed) })
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{nodes: map[uint64]*connection{}}
}

// register adds a connection, displacing any previous one for the same node.
func (h *Hub) register(nodeID uint64, nodeUUID string) *connection {
	conn := &connection{
		nodeID:      nodeID,
		nodeUUID:    nodeUUID,
		connectedAt: time.Now().UTC(),
		out:         make(chan *nodepb.ServerFrame, 64),
		closed:      make(chan struct{}),
	}

	h.mu.Lock()
	if previous, ok := h.nodes[nodeID]; ok {
		// The old stream is almost certainly dead; ending it keeps one
		// connection per node and stops two writers fighting over state.
		previous.close()
	}
	h.nodes[nodeID] = conn
	h.mu.Unlock()
	return conn
}

// unregister removes a connection, but only if it is still the current one: a
// replaced connection must not unregister its successor on the way out.
func (h *Hub) unregister(conn *connection) {
	h.mu.Lock()
	if current, ok := h.nodes[conn.nodeID]; ok && current == conn {
		delete(h.nodes, conn.nodeID)
	}
	h.mu.Unlock()
	conn.close()
}

// Connected reports whether a node's agent is connected.
func (h *Hub) Connected(nodeID uint64) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.nodes[nodeID]
	return ok
}

// ConnectedNodes lists the node ids with a live connection.
func (h *Hub) ConnectedNodes() []uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]uint64, 0, len(h.nodes))
	for id := range h.nodes {
		out = append(out, id)
	}
	return out
}

// ConnectedSince reports when a node's agent connected.
func (h *Hub) ConnectedSince(nodeID uint64) (time.Time, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	conn, ok := h.nodes[nodeID]
	if !ok {
		return time.Time{}, false
	}
	return conn.connectedAt, true
}

// Send queues a frame for a node.
//
// It never blocks: a node whose queue is full is one whose agent has stopped
// reading, and waiting on it would stall whatever is pushing - usually an
// admin's HTTP request.
func (h *Hub) Send(nodeID uint64, frame *nodepb.ServerFrame) error {
	h.mu.RLock()
	conn, ok := h.nodes[nodeID]
	h.mu.RUnlock()
	if !ok {
		return ErrNotConnected
	}

	select {
	case <-conn.closed:
		return ErrNotConnected
	case conn.out <- frame:
		return nil
	default:
		return ErrQueueFull
	}
}

// SendState pushes a desired state.
func (h *Hub) SendState(nodeID uint64, state *nodepb.NodeState) error {
	return h.Send(nodeID, &nodepb.ServerFrame{
		Body: &nodepb.ServerFrame_StateUpdate{
			StateUpdate: &nodepb.StateUpdate{State: state},
		},
	})
}

// SendCommand pushes a command.
func (h *Hub) SendCommand(nodeID uint64, command *nodepb.Command) error {
	return h.Send(nodeID, &nodepb.ServerFrame{
		Body: &nodepb.ServerFrame_Command{Command: command},
	})
}

// Disconnect ends a node's connection, which is how the panel kicks an agent
// whose node was deleted or whose certificate was revoked.
func (h *Hub) Disconnect(nodeID uint64) {
	h.mu.Lock()
	conn, ok := h.nodes[nodeID]
	if ok {
		delete(h.nodes, nodeID)
	}
	h.mu.Unlock()
	if ok {
		conn.close()
	}
}
