// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"encoding/binary"
	"sync"
	"time"

	Enums "github.com/thehavlok/whitenet/masterdnsvpn/enums"
)

// downloadPollTimeout is how long a poll may go unanswered before it is
// counted as lost and stops holding a slot in the window. Long enough for a
// slow recursive resolver, short enough that a lost poll is replaced while
// the transfer it was feeding is still running.
const downloadPollTimeout = 3 * time.Second

// downloadPoller keeps a window of empty queries (PINGs) in flight while the
// server has data for this client.
//
// A DNS server cannot send anything on its own: every byte downstream rides
// the answer to a query. Without polling, the only queries are the client's
// own data, its ACKs and the ping manager's keep-alives, so each answer that
// carries data buys back at most one query, and every query lost on the way
// removes one for good. Download speed then settles wherever the start of the
// transfer and its losses leave the number of queries in flight, and a larger
// download MTU makes it worse, because fewer, larger answers mean fewer
// queries. Measured on the loopback bench (masterdnsvpn/benchtest) that was a
// few Mbit/s regardless of the MTU.
//
// The poller tops the window up each time an answer brings data, and lets it
// drain when answers come back empty (PONG), so it costs nothing while the
// link is idle. It needs nothing from the server: a PING is answered with
// queued data whenever there is any, by every server version.
type downloadPoller struct {
	window  int
	timeout time.Duration

	mu sync.Mutex
	// inflight maps the DNS id of every poll sent to when it was sent.
	inflight map[uint16]time.Time
	// queued holds when each poll was handed to the dispatcher and not yet
	// written, oldest first. A poll can be dropped on the way (a congested
	// queue, no usable resolver), so entries also expire.
	queued []time.Time
}

func newDownloadPoller(window int) *downloadPoller {
	if window <= 0 {
		return nil
	}
	return &downloadPoller{
		window:   window,
		timeout:  downloadPollTimeout,
		inflight: make(map[uint16]time.Time, window*2),
	}
}

// expireLocked forgets polls that were lost or dropped.
func (p *downloadPoller) expireLocked(now time.Time) {
	for id, sentAt := range p.inflight {
		if now.Sub(sentAt) > p.timeout {
			delete(p.inflight, id)
		}
	}
	drop := 0
	for drop < len(p.queued) && now.Sub(p.queued[drop]) > p.timeout {
		drop++
	}
	if drop > 0 {
		p.queued = p.queued[drop:]
	}
}

// reserve claims up to the free slots in the window for new polls and
// returns how many were claimed.
func (p *downloadPoller) reserve(now time.Time) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	free := p.window - len(p.inflight) - len(p.queued)
	for i := 0; i < free; i++ {
		p.queued = append(p.queued, now)
	}
	return max(free, 0)
}

// release gives back a slot claimed by reserve whose poll never got queued.
func (p *downloadPoller) release() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if len(p.queued) > 0 {
		p.queued = p.queued[1:]
	}
	p.mu.Unlock()
}

// noteSent records the DNS packets a poll went out as. One poll may be
// several packets when it is duplicated across resolvers; an answer to any of
// them settles it, and the others expire.
func (p *downloadPoller) noteSent(frames []encodedOutboundDatagram, now time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if len(p.queued) > 0 {
		p.queued = p.queued[1:]
	}
	for _, frame := range frames {
		if len(frame.packet) >= 2 {
			p.inflight[binary.BigEndian.Uint16(frame.packet[:2])] = now
		}
	}
	p.mu.Unlock()
}

// noteAnswer settles the poll a DNS answer belongs to, if it was one.
func (p *downloadPoller) noteAnswer(dnsPacket []byte) {
	if p == nil || len(dnsPacket) < 2 {
		return
	}
	id := binary.BigEndian.Uint16(dnsPacket[:2])
	p.mu.Lock()
	delete(p.inflight, id)
	p.mu.Unlock()
}

// carriesDownstreamData reports whether an answer brought stream data, which
// is the sign that the server has more queued behind it.
func carriesDownstreamData(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return true
	default:
		return false
	}
}

// topUpDownloadPolls queues polls until the window is full again.
func (c *Client) topUpDownloadPolls() {
	if c == nil || c.downloadPoller == nil || !c.SessionReady() {
		return
	}
	n := c.downloadPoller.reserve(time.Now())
	if n == 0 {
		return
	}

	c.streamsMu.RLock()
	s0 := c.active_streams[0]
	c.streamsMu.RUnlock()
	if s0 == nil {
		for i := 0; i < n; i++ {
			c.downloadPoller.release()
		}
		return
	}

	for i := 0; i < n; i++ {
		payload, err := buildClientPingPayload()
		if err != nil || !s0.PushTXPacket(
			Enums.DefaultPacketPriority(Enums.PACKET_PING),
			Enums.PACKET_PING,
			c.pingManager.nextPingSequence(),
			0, 0, 0, 0,
			payload,
		) {
			c.downloadPoller.release()
		}
	}
}
