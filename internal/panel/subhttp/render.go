package subhttp

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/staterender"
	"github.com/thehavlok/whitenet/internal/panel/store"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// render builds the document for one user.
//
// Only nodes the user may reach and that are actually up go in: handing a
// client a dead server is worse than handing it one fewer. A user who is
// disabled, expired or out of traffic still gets a document - with no servers
// - so the app can say why rather than showing a network error.
// Render renders what a user would be served, for a caller that is not that
// user: the admin API, which lists the same servers and offers a share link
// for each one.
//
// No device is passed, so looking at a user in the panel never consumes one of
// their device slots - an administrator opening a page is not a device.
func (s *Server) Render(r *http.Request, user *store.User) (*subscription.Response, error) {
	return s.render(r, user, nil)
}

func (s *Server) render(r *http.Request, user *store.User, deviceID *uint64) (*subscription.Response, error) {
	settings, err := s.store.SubscriptionSettings(r.Context())
	if err != nil {
		return nil, err
	}
	branding, err := s.store.Branding(r.Context())
	if err != nil {
		return nil, err
	}
	devices, err := s.store.UserDevices(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}

	doc := &subscription.Response{
		Version:             subscription.Version,
		IssuedAt:            time.Now().UTC(),
		UpdateIntervalHours: settings.UpdateIntervalHours,
		User: subscription.User{
			UUID:         user.UUID,
			Name:         user.Name,
			TrafficUsed:  user.TrafficUsed,
			TrafficLimit: user.TrafficLimit,
			DevicesLimit: int(user.DevicesLimit),
			DevicesUsed:  len(devices),
			Status:       user.Status,
		},
		Servers:  []subscription.Server{},
		Branding: brandingResponse(branding),
	}
	if user.ExpiresAt.Valid {
		when := user.ExpiresAt.Time.UTC()
		doc.User.ExpiresAt = &when
	}

	if !user.Usable() {
		return doc, nil
	}

	nodes, err := s.store.NodesForUser(r.Context(), user.ID, !settings.IncludeOfflineNodes)
	if err != nil {
		return nil, err
	}

	for i := range nodes {
		node := nodes[i]
		servers, err := s.serversForNode(r, user, &node, deviceID)
		if err != nil {
			// One misconfigured node must not empty everyone's subscription.
			s.log.Warn("could not render a node for a subscription",
				"node", node.UUID, "user", user.ID, "error", err)
			continue
		}
		doc.Servers = append(doc.Servers, servers...)
	}

	sort.SliceStable(doc.Servers, func(a, b int) bool {
		if doc.Servers[a].Sort != doc.Servers[b].Sort {
			return doc.Servers[a].Sort < doc.Servers[b].Sort
		}
		return doc.Servers[a].Name < doc.Servers[b].Name
	})

	if err := doc.Validate(); err != nil {
		// A document that fails its own validation is a panel bug, and
		// serving it would make the app behave oddly rather than report it.
		return nil, fmt.Errorf("subhttp: rendered an invalid subscription: %w", err)
	}
	return doc, nil
}

// serversForNode turns one node into the entries a client can connect with.
func (s *Server) serversForNode(r *http.Request, user *store.User, node *store.Node, deviceID *uint64) ([]subscription.Server, error) {
	inbounds, err := s.store.NodeInbounds(r.Context(), node.ID)
	if err != nil {
		return nil, err
	}
	groups, err := s.store.NodeGroupNames(r.Context(), node.ID)
	if err != nil {
		return nil, err
	}
	groupName := ""
	if len(groups) > 0 {
		groupName = groups[0]
	}

	// The address clients dial is what the admin configured. Falling back to
	// the hostname the agent reported would hand out an internal name.
	address := node.Address
	if address == "" {
		return nil, fmt.Errorf("node %s has no address configured", node.UUID)
	}

	byTag := map[string]store.NodeInbound{}
	for _, inbound := range inbounds {
		byTag[inbound.Tag] = inbound
	}

	password, err := s.box.OpenString(user.Password)
	if err != nil {
		return nil, fmt.Errorf("decrypt the user's password: %w", err)
	}
	ssPassword, err := s.box.OpenString(user.SSPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt the user's shadowsocks key: %w", err)
	}

	var out []subscription.Server
	for _, inbound := range inbounds {
		if !inbound.Enabled || !inbound.Published {
			continue
		}
		server, ok, err := s.serverFromInbound(node, inbound, byTag, user, password, ssPassword, groupName, address)
		if err != nil {
			s.log.Warn("could not render an inbound",
				"node", node.UUID, "inbound", inbound.Tag, "error", err)
			continue
		}
		if ok {
			out = append(out, server)
		}
	}

	// Flux is not an inbound: it has no port and no per-user credentials, so
	// it is rendered from the node's channel pool.
	if flux, ok, err := s.fluxServer(r, node, groupName); err != nil {
		s.log.Warn("could not render the flux pool", "node", node.UUID, "error", err)
	} else if ok {
		out = append(out, flux)
	}
	return out, nil
}

// serverFromInbound builds one entry.
func (s *Server) serverFromInbound(
	node *store.Node,
	inbound store.NodeInbound,
	byTag map[string]store.NodeInbound,
	user *store.User,
	password, ssPassword, groupName, address string,
) (subscription.Server, bool, error) {
	secrets, err := staterender.OpenSecrets(s.box, inbound.Secrets)
	if err != nil {
		return subscription.Server{}, false, err
	}

	server := subscription.Server{
		ID:      node.UUID + ":" + inbound.Tag,
		Name:    serverName(node, inbound),
		Country: node.Country(),
		Group:   groupName,
		Address: address,
		Port:    int(inbound.ListenPort),
		Sort:    inbound.SortOrder,
		Params:  map[string]string{},
	}

	switch inbound.Protocol {
	case store.ProtoVLESS:
		server.Protocol = subscription.ProtocolVLESS
		server.Params["uuid"] = user.VLESSUUID
		if flow := inbound.Params.Get("flow"); flow != "" {
			server.Params["flow"] = flow
		}

	case store.ProtoVMess:
		server.Protocol = subscription.ProtocolVMess
		server.Params["uuid"] = user.VLESSUUID
		server.Params["security"] = orDefault(inbound.Params.Get("security_vmess"), "auto")

	case store.ProtoTrojan:
		server.Protocol = subscription.ProtocolTrojan
		server.Params["password"] = password

	case store.ProtoShadowsocks:
		server.Protocol = subscription.ProtocolShadowsocks
		server.Params["method"] = inbound.Params.Get("method")
		server.Params["password"] = ssPassword

	case store.ProtoShadowsocks2022:
		server.Protocol = subscription.ProtocolShadowsocks2022
		server.Params["method"] = inbound.Params.Get("method")
		// A 2022 client key is "serverKey:userKey": the server key
		// authenticates the server and the user key the user.
		server.Params["password"] = secrets["password"] + ":" + ssPassword

	case store.ProtoHysteria2:
		server.Protocol = subscription.ProtocolHysteria2
		server.Params["auth"] = password

	case store.ProtoWNDNS:
		server.Protocol = subscription.ProtocolWNDNS
		server.Transport = "dns"
		server.Params["domains"] = inbound.Params.Get("domains")
		server.Params["encryption_method"] = orDefault(inbound.Params.Get("encryption_method"), "2")
		server.Params["encryption_key"] = secrets["encryption_key"]
		// Where the app sends the tunnel's queries. Optional: the app has a
		// built-in list, and this is how an operator replaces it when the
		// resolvers that get through change, without an app release.
		if resolvers := inbound.Params.Get("resolvers"); resolvers != "" {
			server.Params["resolvers"] = resolvers
		}

		// The tunnel has no accounts of its own: it forwards into an Xray
		// inbound, and that inbound is what authenticates the user. The app
		// needs both halves, so the inner one travels in `chain`.
		target, ok := byTag[inbound.ForwardToTag.String]
		if !ok {
			return subscription.Server{}, false, fmt.Errorf(
				"the tunnel forwards to %q, which is not on this node", inbound.ForwardToTag.String)
		}
		chain, err := s.chainFromInbound(target, user, password, ssPassword)
		if err != nil {
			return subscription.Server{}, false, err
		}
		server.Chain = chain

	default:
		// A protocol the panel knows but this format does not: skip it rather
		// than serve something the app cannot use.
		return subscription.Server{}, false, nil
	}

	if inbound.Protocol != store.ProtoWNDNS {
		server.Transport = clientTransport(inbound)
		applyTransportParams(server.Params, inbound, secrets)
	}

	return server, true, nil
}

// chainFromInbound describes the inner hop of a tunnel. It deliberately has no
// address: the app dials whatever local endpoint the tunnel exposes.
func (s *Server) chainFromInbound(inbound store.NodeInbound, user *store.User, password, ssPassword string) (*subscription.Chain, error) {
	secrets, err := staterender.OpenSecrets(s.box, inbound.Secrets)
	if err != nil {
		return nil, err
	}
	chain := &subscription.Chain{
		Transport: clientTransport(inbound),
		Params:    map[string]string{},
	}
	switch inbound.Protocol {
	case store.ProtoVLESS:
		chain.Protocol = subscription.ProtocolVLESS
		chain.Params["uuid"] = user.VLESSUUID
		if flow := inbound.Params.Get("flow"); flow != "" {
			chain.Params["flow"] = flow
		}
	case store.ProtoVMess:
		chain.Protocol = subscription.ProtocolVMess
		chain.Params["uuid"] = user.VLESSUUID
	case store.ProtoTrojan:
		chain.Protocol = subscription.ProtocolTrojan
		chain.Params["password"] = password
	case store.ProtoShadowsocks:
		chain.Protocol = subscription.ProtocolShadowsocks
		chain.Params["method"] = inbound.Params.Get("method")
		chain.Params["password"] = ssPassword
	case store.ProtoShadowsocks2022:
		chain.Protocol = subscription.ProtocolShadowsocks2022
		chain.Params["method"] = inbound.Params.Get("method")
		chain.Params["password"] = secrets["password"] + ":" + ssPassword
	default:
		return nil, fmt.Errorf("a tunnel cannot forward into %s", inbound.Protocol)
	}
	applyTransportParams(chain.Params, inbound, secrets)
	return chain, nil
}

// fluxServer renders the node's flux pool as one entry with a lease endpoint.
//
// A channel carries one client at a time, so the subscription hands out the
// endpoint rather than a channel: the app asks for a free one when it connects
// and renews while it uses it.
func (s *Server) fluxServer(r *http.Request, node *store.Node, groupName string) (subscription.Server, bool, error) {
	cfg, err := s.store.NodeOpenFluxConfig(r.Context(), node.ID)
	if err != nil {
		return subscription.Server{}, false, err
	}
	if cfg == nil || !cfg.Enabled {
		return subscription.Server{}, false, nil
	}
	channels, err := s.store.NodeChannels(r.Context(), node.ID)
	if err != nil {
		return subscription.Server{}, false, err
	}
	// An enabled exit with no channels has no capacity, so there is nothing
	// to offer.
	var enabled int
	transports := map[string]bool{}
	for _, channel := range channels {
		if channel.Enabled {
			enabled++
			transports[channel.Transport] = true
		}
	}
	if enabled == 0 {
		return subscription.Server{}, false, nil
	}

	base, err := s.subscriptionURL(r, "")
	if err != nil {
		return subscription.Server{}, false, err
	}
	base = strings.TrimSuffix(strings.TrimRight(base, "/"), "/sub")

	// The transport shown is the one the pool mostly offers, so the app can
	// label the entry sensibly without listing every channel.
	transport := ""
	for name := range transports {
		if transport == "" || name < transport {
			transport = name
		}
	}

	token := r.PathValue("token")
	return subscription.Server{
		ID:        node.UUID + ":flux",
		Name:      fluxName(node, transport),
		Country:   node.Country(),
		Group:     groupName,
		Protocol:  subscription.ProtocolFlux,
		Transport: transport,
		Sort:      1000, // after the direct protocols, which are faster
		Flux: &subscription.Flux{
			Mode:  cfg.Mode,
			Lease: fmt.Sprintf("%s/lease/%s?node=%s", base, token, node.UUID),
		},
	}, true, nil
}

// clientTransport is the transport name the app uses, which is the panel's
// spelling rather than xray-core's internal one.
func clientTransport(inbound store.NodeInbound) string {
	security := inbound.Security
	network := inbound.Network
	if network == "" {
		network = inbound.Params.Get("network")
	}
	if network == "" {
		network = "raw"
	}
	// REALITY is the thing a client has to know about; the network underneath
	// is almost always raw.
	if security == "reality" {
		return "reality"
	}
	switch network {
	case "raw", "tcp":
		if security == "tls" {
			return "tls"
		}
		return "raw"
	case "ws", "websocket":
		return "ws"
	case "kcp", "mkcp":
		return "kcp"
	default:
		return network
	}
}

// applyTransportParams copies the keys a client needs for the transport.
//
// Only what the client actually uses is copied: server-side knobs such as the
// Reality private key or a certificate path must never leave the panel.
func applyTransportParams(params map[string]string, inbound store.NodeInbound, secrets map[string]string) {
	copyIfSet := func(keys ...string) {
		for _, key := range keys {
			if value := inbound.Params.Get(key); value != "" {
				params[key] = value
			}
		}
	}

	switch inbound.Security {
	case "reality":
		// The client needs the public half, which is derived from the private
		// key the panel keeps.
		if public, err := realityPublicKey(secrets["private_key"]); err == nil {
			params["pbk"] = public
		}
		// Any one of the inbound's short ids works; the first is as good as
		// another, and sending them all would tell a client more than it
		// needs.
		if ids := splitCSV(inbound.Params.Get("short_ids")); len(ids) > 0 {
			params["sid"] = ids[0]
		}
		if names := splitCSV(inbound.Params.Get("server_names")); len(names) > 0 {
			params["sni"] = names[0]
		} else {
			copyIfSet("sni")
		}
		copyIfSet("fp", "spx")

	case "tls":
		copyIfSet("sni", "fp", "alpn", "allow_insecure")
	}

	network := inbound.Network
	if network == "" {
		network = inbound.Params.Get("network")
	}
	switch network {
	case "xhttp", "splithttp":
		copyIfSet("path", "host", "mode")
	case "ws", "websocket", "httpupgrade":
		copyIfSet("path", "host")
	case "grpc":
		copyIfSet("service_name", "multi_mode")
	case "kcp", "mkcp":
		copyIfSet("header")
		if seed := secrets["seed"]; seed != "" {
			params["seed"] = seed
		}
	}

	if inbound.Protocol == store.ProtoHysteria2 {
		copyIfSet("up_mbps", "down_mbps", "congestion")
		// Salamander is configured as a finalmask on the server; the client
		// needs to know it is there and with what password.
		for _, mask := range splitCSV(inbound.Params.Get("finalmask_udp")) {
			if mask == "salamander" {
				params["obfs"] = "salamander"
				if password := firstNonEmpty(secrets["salamander_password"], secrets["obfs_password"]); password != "" {
					params["obfs_password"] = password
				}
			}
		}
	}
}

func serverName(node *store.Node, inbound store.NodeInbound) string {
	label := node.Label()
	// A node with one inbound reads better without a suffix; with several,
	// the protocol is what distinguishes them in the app's list.
	suffix := protocolLabel(inbound.Protocol)
	if suffix == "" {
		return label
	}
	return label + " · " + suffix
}

func fluxName(node *store.Node, transport string) string {
	label := node.Label()
	if transport == "" {
		return label + " · Flux"
	}
	return label + " · " + transport
}

func protocolLabel(protocol string) string {
	switch protocol {
	case store.ProtoVLESS:
		return "VLESS"
	case store.ProtoVMess:
		return "VMess"
	case store.ProtoTrojan:
		return "Trojan"
	case store.ProtoShadowsocks, store.ProtoShadowsocks2022:
		return "SS"
	case store.ProtoHysteria2:
		return "HY2"
	case store.ProtoWNDNS:
		return "DNS"
	default:
		return ""
	}
}

func brandingResponse(branding store.Branding) *subscription.Branding {
	if branding.AppName == "" && branding.SupportURL == "" && branding.Message == "" {
		return nil
	}
	return &subscription.Branding{
		AppName:     branding.AppName,
		LogoURL:     branding.LogoURL,
		SupportURL:  branding.SupportURL,
		Message:     branding.Message,
		AccentColor: branding.AccentColor,
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
