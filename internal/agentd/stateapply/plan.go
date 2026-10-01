// Package stateapply turns a desired state into the actions a node must take.
//
// The planning half is a pure function over two states, because this is the
// logic that decides whether anyone's connection gets dropped. A change to a
// user's subscription must cost nothing; a change to an inbound costs a
// restart. Getting that backwards means either dropping every session whenever
// someone is added, or serving a stale configuration forever - so it is worth
// having as something that can be tested without a node.
package stateapply

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/thehavlok/whitenet/internal/agentd/xrayctl"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

// Plan is what has to happen to go from one state to another.
type Plan struct {
	// RestartXray is set when the inbounds themselves changed. Users alone
	// never require it: that is what the Xray API is for.
	RestartXray bool
	// RestartWNDNS is set when the DNS tunnel's own configuration changed.
	// The tunnel has no runtime API, so any change is a restart.
	RestartWNDNS bool
	// StopWNDNS is set when the node no longer has a tunnel.
	StopWNDNS bool

	// AddUsers and RemoveUsers are per inbound tag, for the inbounds that
	// support runtime changes. They are empty when RestartXray is set,
	// because the restart applies the users anyway.
	AddUsers    map[string][]*nodepb.User
	RemoveUsers map[string][]string

	// ApplyFlux is set when the flux channels changed; the pool works out the
	// per-channel detail itself.
	ApplyFlux bool

	// Reason explains the plan in one line, for the node's log and the
	// panel's journal. "why did my node restart" is a question that has to be
	// answerable.
	Reason string
}

// Empty reports whether the plan asks for nothing.
func (p Plan) Empty() bool {
	return !p.RestartXray && !p.RestartWNDNS && !p.StopWNDNS && !p.ApplyFlux &&
		len(p.AddUsers) == 0 && len(p.RemoveUsers) == 0
}

// PlanFor compares the state a node is running with the state it should run.
//
// current may be nil, which is a node that has just started: everything is a
// change, and Xray starts rather than restarts.
func PlanFor(current, next *nodepb.NodeState) Plan {
	plan := Plan{
		AddUsers:    map[string][]*nodepb.User{},
		RemoveUsers: map[string][]string{},
	}

	currentXray := xrayInbounds(current)
	nextXray := xrayInbounds(next)

	switch {
	case current == nil:
		plan.RestartXray = len(nextXray) > 0
		plan.Reason = "first state after start"
	case inboundsFingerprint(currentXray) != inboundsFingerprint(nextXray):
		plan.RestartXray = true
		plan.Reason = "xray inbounds changed"
	}

	// Users are a delta unless a restart is already happening.
	if !plan.RestartXray {
		currentUsers := usersByID(current)
		nextUsers := usersByID(next)

		added, removed := diffUsers(currentUsers, nextUsers)
		if len(added) > 0 || len(removed) > 0 {
			for _, inbound := range nextXray {
				if !xrayctl.SupportsUsers(inbound.GetProtocol()) {
					continue
				}
				tag := inbound.GetTag()
				if len(added) > 0 {
					plan.AddUsers[tag] = added
				}
				if len(removed) > 0 {
					plan.RemoveUsers[tag] = removed
				}
			}
			if plan.Reason == "" {
				plan.Reason = userReason(len(added), len(removed))
			}
		}
	}

	// The DNS tunnel has no runtime API, so any change to it is a restart.
	currentDNS := dnsFingerprint(current)
	nextDNS := dnsFingerprint(next)
	switch {
	case currentDNS == nextDNS:
		// nothing to do
	case nextDNS == "":
		plan.StopWNDNS = true
		if plan.Reason == "" {
			plan.Reason = "dns tunnel removed"
		}
	default:
		plan.RestartWNDNS = true
		if plan.Reason == "" {
			plan.Reason = "dns tunnel configuration changed"
		}
	}

	// A tunnel that forwards into an Xray inbound depends on that inbound's
	// port. A restart of Xray can change it, so the tunnel has to follow.
	if plan.RestartXray && nextDNS != "" {
		plan.RestartWNDNS = true
	}

	if fluxFingerprint(current) != fluxFingerprint(next) {
		plan.ApplyFlux = true
		if plan.Reason == "" {
			plan.Reason = "flux channels changed"
		}
	}

	if plan.Reason == "" {
		plan.Reason = "no change"
	}
	return plan
}

func userReason(added, removed int) string {
	switch {
	case added > 0 && removed > 0:
		return "users added and removed"
	case added > 0:
		return "users added"
	default:
		return "users removed"
	}
}

// xrayInbounds returns the enabled inbounds xray-core serves, sorted by tag.
func xrayInbounds(state *nodepb.NodeState) []*nodepb.Inbound {
	var out []*nodepb.Inbound
	for _, in := range state.GetInbounds() {
		if in.GetEnabled() && in.GetCore() == nodepb.Core_CORE_XRAY {
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetTag() < out[j].GetTag() })
	return out
}

// inboundsFingerprint covers everything about an inbound that Xray reads at
// startup. Users are deliberately not in it: they are the one thing that can
// change without a restart.
func inboundsFingerprint(inbounds []*nodepb.Inbound) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}
	for _, in := range inbounds {
		write(in.GetTag(), in.GetProtocol().String(), in.GetListenAddress(),
			itoa(int(in.GetListenPort())), in.GetForwardToTag())
		writeSortedMap(write, in.GetParams())
		writeSortedMap(write, in.GetSecrets())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// dnsFingerprint covers the tunnel's configuration, including the port of the
// inbound it forwards into: if that moves, the tunnel is pointing at nothing.
func dnsFingerprint(state *nodepb.NodeState) string {
	var tunnel *nodepb.Inbound
	for _, in := range state.GetInbounds() {
		if in.GetEnabled() && in.GetProtocol() == nodepb.Protocol_PROTOCOL_WNDNS {
			tunnel = in
			break
		}
	}
	if tunnel == nil {
		return ""
	}
	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}
	write(tunnel.GetTag(), tunnel.GetListenAddress(), itoa(int(tunnel.GetListenPort())),
		tunnel.GetForwardToTag())
	writeSortedMap(write, tunnel.GetParams())
	writeSortedMap(write, tunnel.GetSecrets())

	// The forward target's port is part of the tunnel's configuration.
	for _, in := range state.GetInbounds() {
		if in.GetTag() == tunnel.GetForwardToTag() {
			write("target", itoa(int(in.GetListenPort())), in.GetListenAddress())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fluxFingerprint covers the flux block. The pool works out which individual
// channels moved; this only has to answer "did anything".
func fluxFingerprint(state *nodepb.NodeState) string {
	cfg := state.GetOpenflux()
	if cfg == nil || !cfg.GetEnabled() {
		return ""
	}
	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}
	write("enabled", cfg.GetMode())

	channels := append([]*nodepb.OpenFluxChannel(nil), cfg.GetChannels()...)
	sort.Slice(channels, func(i, j int) bool { return channels[i].GetId() < channels[j].GetId() })
	for _, channel := range channels {
		write(itoa(int(channel.GetId())), boolString(channel.GetEnabled()),
			channel.GetTransport(), channel.GetUrl(),
			channel.GetEncryptionKey(), channel.GetSessionContext())
		writeSortedMap(write, channel.GetParams())
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeSortedMap(write func(...string), m map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		write(k, m[k])
	}
}

func usersByID(state *nodepb.NodeState) map[uint64]*nodepb.User {
	out := map[uint64]*nodepb.User{}
	for _, u := range state.GetUsers() {
		out[u.GetId()] = u
	}
	return out
}

// diffUsers returns the users to add and the emails to remove.
//
// A user whose credentials changed appears in both: the Xray API has no update
// operation, so a changed UUID is a remove followed by an add. The old email is
// what identifies the account to remove, which is why it is taken from the
// current state rather than the new one.
func diffUsers(current, next map[uint64]*nodepb.User) (added []*nodepb.User, removedEmails []string) {
	for id, user := range next {
		existing, ok := current[id]
		if !ok {
			added = append(added, user)
			continue
		}
		if credentialsChanged(existing, user) {
			removedEmails = append(removedEmails, existing.GetEmail())
			added = append(added, user)
		}
	}
	for id, user := range current {
		if _, ok := next[id]; !ok {
			removedEmails = append(removedEmails, user.GetEmail())
		}
	}

	sort.Slice(added, func(i, j int) bool { return added[i].GetId() < added[j].GetId() })
	sort.Strings(removedEmails)
	return added, removedEmails
}

// credentialsChanged reports whether anything a node uses to authenticate the
// user differs. The name and the limits are not here: a node never sees them.
func credentialsChanged(a, b *nodepb.User) bool {
	return a.GetEmail() != b.GetEmail() ||
		a.GetVlessUuid() != b.GetVlessUuid() ||
		a.GetPassword() != b.GetPassword() ||
		a.GetSsPassword() != b.GetSsPassword() ||
		a.GetFlow() != b.GetFlow()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
