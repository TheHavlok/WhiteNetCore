package subhttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	"github.com/thehavlok/whitenet/internal/panel/store"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// handleAcquireLease hands a free flux channel to a client.
//
// This is the only part of the subscription that changes state, and it is why
// flux appears as a lease endpoint rather than as credentials: a channel
// carries one client at a time, so the pool has to be handed out rather than
// published.
func (s *Server) handleAcquireLease(w http.ResponseWriter, r *http.Request) {
	user, ok := s.leaseUser(w, r)
	if !ok {
		return
	}

	nodeUUID := r.URL.Query().Get("node")
	if nodeUUID == "" {
		s.writeJSON(w, http.StatusBadRequest, leaseError("bad_request", "no node given"))
		return
	}
	node, err := s.store.NodeByUUID(r.Context(), nodeUUID)
	if err != nil {
		s.writeJSON(w, http.StatusNotFound, leaseError("not_found", "unknown node"))
		return
	}

	// A user may only lease on a node their groups reach, which is checked
	// here rather than trusted from the request.
	allowed, err := s.store.NodesForUser(r.Context(), user.ID, false)
	if err != nil {
		s.log.Error("could not read the user's nodes", "user", user.ID, "error", err)
		s.writeJSON(w, http.StatusServiceUnavailable, leaseError("unavailable", "try again"))
		return
	}
	var permitted bool
	for _, candidate := range allowed {
		if candidate.ID == node.ID {
			permitted = true
			break
		}
	}
	if !permitted {
		s.writeJSON(w, http.StatusForbidden, leaseError("forbidden", "this account cannot use that node"))
		return
	}

	var deviceID *uint64
	if hwid := r.Header.Get(HeaderHWID); hwid != "" {
		device, err := s.store.SeenDevice(r.Context(), user.ID, hwid,
			r.Header.Get(HeaderModel), r.Header.Get(HeaderPlatform),
			r.Header.Get(HeaderAppVersion), s.clientIP(r))
		if errors.Is(err, store.ErrDeviceLimit) {
			s.writeJSON(w, http.StatusForbidden,
				leaseError("device_limit", fmt.Sprintf("this account allows %d devices", user.DevicesLimit)))
			return
		}
		if err == nil {
			deviceID = &device.ID
		}
	}

	ttl := s.cfg.Node.OpenFluxLeaseTTL.Duration()
	lease, channel, err := s.store.AcquireChannel(r.Context(), user.ID, node.ID, deviceID, ttl)
	if err != nil {
		if errors.Is(err, store.ErrNoChannel) {
			// Not a failure: every channel on this node is in use. The app
			// should try another node.
			s.writeJSON(w, http.StatusConflict,
				leaseError("no_channel", "every channel on this node is in use"))
			return
		}
		s.log.Error("could not lease a channel", "user", user.ID, "node", node.UUID, "error", err)
		s.writeJSON(w, http.StatusServiceUnavailable, leaseError("unavailable", "try again"))
		return
	}

	built, err := s.leaseResponse(r, user, lease, channel)
	if err != nil {
		s.log.Error("could not build a lease response", "user", user.ID, "error", err)
		s.writeJSON(w, http.StatusServiceUnavailable, leaseError("unavailable", "try again"))
		return
	}
	s.writeJSON(w, http.StatusOK, built)
}

// handleRenewLease extends a lease the client is still using.
func (s *Server) handleRenewLease(w http.ResponseWriter, r *http.Request) {
	user, ok := s.leaseUser(w, r)
	if !ok {
		return
	}
	leaseID, ok := s.leaseID(w, r)
	if !ok {
		return
	}
	lease, err := s.store.RenewLease(r.Context(), leaseID, user.ID, s.cfg.Node.OpenFluxLeaseTTL.Duration())
	if err != nil {
		// Either it is not theirs or it already lapsed; both mean "ask for a
		// new one", which is what the app does with this answer.
		s.writeJSON(w, http.StatusConflict, leaseError("lease_gone", "ask for a new channel"))
		return
	}
	channel, err := s.store.ChannelByID(r.Context(), lease.ChannelID)
	if err != nil {
		s.writeJSON(w, http.StatusConflict, leaseError("lease_gone", "ask for a new channel"))
		return
	}
	built, err := s.leaseResponse(r, user, lease, channel)
	if err != nil {
		s.writeJSON(w, http.StatusServiceUnavailable, leaseError("unavailable", "try again"))
		return
	}
	s.writeJSON(w, http.StatusOK, built)
}

// handleReleaseLease hands a channel back, so it does not sit idle until its
// lease expires. An app that disconnects cleanly calls this.
func (s *Server) handleReleaseLease(w http.ResponseWriter, r *http.Request) {
	user, ok := s.leaseUser(w, r)
	if !ok {
		return
	}
	leaseID, ok := s.leaseID(w, r)
	if !ok {
		return
	}
	if err := s.store.ReleaseLease(r.Context(), leaseID, user.ID, "released"); err != nil {
		// Releasing something already gone is not worth an error.
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// leaseUser resolves and checks the caller.
func (s *Server) leaseUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	ip := s.clientIP(r)
	settings, err := s.store.SubscriptionSettings(r.Context())
	if err == nil && !s.limiter.allow("lease:"+ip, settings.RateLimitPerMinute) {
		w.Header().Set("Retry-After", "60")
		s.writeJSON(w, http.StatusTooManyRequests, leaseError("rate_limited", "slow down"))
		return nil, false
	}

	user, err := s.store.UserBySubToken(r.Context(), r.PathValue("token"))
	if err != nil {
		s.writeJSON(w, http.StatusNotFound, leaseError("not_found", "unknown subscription"))
		return nil, false
	}
	if !user.Usable() {
		s.writeJSON(w, http.StatusForbidden, leaseError("not_active", "this account is "+user.Status))
		return nil, false
	}
	return user, true
}

func (s *Server) leaseID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("leaseID"), 10, 64)
	if err != nil || id == 0 {
		s.writeJSON(w, http.StatusBadRequest, leaseError("bad_request", "bad lease id"))
		return 0, false
	}
	return id, true
}

// leaseResponse describes a leased channel in the subscription format.
func (s *Server) leaseResponse(r *http.Request, user *store.User, lease *store.OpenFluxLease, channel *store.OpenFluxChannel) (*subscription.LeaseResponse, error) {
	secretValue, err := s.box.OpenString(channel.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt the channel secret: %w", err)
	}

	// The node is needed for the direct carrier: the exit listens on a
	// wildcard, and a client cannot dial that.
	node, err := s.store.NodeByID(r.Context(), channel.NodeID)
	if err != nil {
		return nil, err
	}
	carriers, err := s.carriers(channel, node)
	if err != nil {
		return nil, err
	}

	base, err := s.subscriptionURL(r, "")
	if err != nil {
		return nil, err
	}
	base = strings.TrimSuffix(strings.TrimRight(base, "/"), "/sub")
	leaseBase := fmt.Sprintf("%s/lease/%s/%d", base, user.SubToken, lease.ID)

	return &subscription.LeaseResponse{
		Channel: subscription.Channel{
			ID:       channel.UUID,
			Secret:   secretValue,
			Context:  channel.SessionContext.String,
			Carriers: carriers,
		},
		ExpiresAt:  lease.ExpiresAt.UTC(),
		RenewURL:   leaseBase + "/renew",
		ReleaseURL: leaseBase + "/release",
	}, nil
}

// carriers turns a channel's configuration into what the client runs.
//
// The MAX carrier is left out: its token belongs to the exit's own account, so
// handing it to a client would hand over that account.
func (s *Server) carriers(channel *store.OpenFluxChannel, node *store.Node) ([]subscription.Carrier, error) {
	params := map[string]string{}
	for k, v := range channel.Params {
		params[k] = v
	}
	extra := params["carriers"]
	delete(params, "carriers")

	var out []subscription.Carrier
	add := func(carrierType, url string, priority int, carrierParams map[string]string) {
		if carrierType == fluxnode.CarrierOneMe {
			return
		}
		carrier := subscription.Carrier{
			Type:     carrierType,
			URL:      url,
			Priority: priority,
			Params:   map[string]string{},
		}
		// A client dials `direct`, so the exit's listen address becomes a
		// dial address. The listen side is usually a wildcard, which is not
		// something a client can connect to, so the node's own address is
		// substituted for the host.
		if carrierType == fluxnode.CarrierDirect {
			if dial := dialAddress(carrierParams["listen"], node.Address); dial != "" {
				carrier.Params["dial"] = dial
			}
		}
		// The client needs nothing else from the server's parameters, and
		// sending cookies or tokens would leak the exit's own credentials.
		out = append(out, carrier)
	}

	add(channel.Transport, channel.URL, 50, params)
	for _, spec := range splitCSV(extra) {
		carrierType, rest, _ := strings.Cut(spec, ":")
		carrierType = strings.TrimSpace(carrierType)
		priority := 50
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			if n, err := strconv.Atoi(strings.TrimSpace(rest[at+1:])); err == nil {
				priority = n
				rest = rest[:at]
			}
		}
		rest = strings.TrimSpace(rest)
		if carrierType == fluxnode.CarrierDirect {
			add(carrierType, "", priority, map[string]string{"listen": rest})
			continue
		}
		add(carrierType, rest, priority, nil)
	}

	if len(out) == 0 {
		return nil, errors.New("this channel has no carrier a client can use")
	}
	// Distinct names, because a session registers carriers by name.
	seen := map[string]int{}
	for i := range out {
		name := out[i].Type
		if count := seen[name]; count > 0 {
			name = fmt.Sprintf("%s-%d", name, count+1)
		}
		seen[out[i].Type]++
		out[i].Name = name
	}
	return out, nil
}

func leaseError(code, message string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": message}}
}

// unused keeps the time import honest if the lease TTL moves elsewhere.
var _ = time.Minute

// dialAddress turns an exit's listen address into one a client can dial.
//
// An exit listens on 0.0.0.0 or :: so it accepts on every interface; handing
// that to a client would have it connect to itself. The port is kept and the
// host becomes the node's configured address - the same one every other
// protocol on that node is dialled at.
func dialAddress(listen, nodeAddress string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Not host:port at all; pass it through rather than guessing.
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]", "*":
		if nodeAddress == "" {
			return ""
		}
		return net.JoinHostPort(nodeAddress, port)
	default:
		return listen
	}
}
