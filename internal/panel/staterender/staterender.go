// Package staterender turns the database into a node's desired state.
//
// This is the one place that decides what a node runs and who it serves. The
// agent never computes anything: it applies what this produces. Keeping that
// boundary sharp is what makes a node that was offline for a week converge by
// applying one message.
package staterender

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/thehavlok/whitenet/internal/agentd/xraycfg"
	"github.com/thehavlok/whitenet/internal/nodepb"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// Renderer builds node states.
type Renderer struct {
	store *store.Store
	box   *secret.Box
	// Settings pushed to every agent.
	settings Settings
}

// Settings are the intervals and versions Main dictates to the fleet, so they
// can be retuned centrally rather than per node.
type Settings struct {
	HeartbeatSeconds     uint32
	MetricsSeconds       uint32
	TrafficReportSeconds uint32
	XrayLogLevel         string
}

// New returns a renderer.
func New(st *store.Store, box *secret.Box, settings Settings) *Renderer {
	if settings.XrayLogLevel == "" {
		settings.XrayLogLevel = "warning"
	}
	return &Renderer{store: st, box: box, settings: settings}
}

// Render builds the state for one node at its current configuration version.
//
// Everything the node needs is resolved here: template parameters are already
// merged, secrets are decrypted, and the user list is already filtered by
// group, status, expiry and traffic. A node is never handed a user who should
// not be able to connect.
func (r *Renderer) Render(ctx context.Context, nodeID uint64) (*nodepb.NodeState, error) {
	node, err := r.store.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, err
	}

	state := &nodepb.NodeState{
		Version:  node.ConfigVersion,
		NodeUuid: node.UUID,
		Settings: &nodepb.NodeSettings{
			HeartbeatIntervalSeconds:     r.settings.HeartbeatSeconds,
			MetricsIntervalSeconds:       r.settings.MetricsSeconds,
			TrafficReportIntervalSeconds: r.settings.TrafficReportSeconds,
			XrayLogLevel:                 r.settings.XrayLogLevel,
		},
	}

	// A node an admin disabled serves nobody, but it still gets a state: the
	// empty one is what makes it stop, rather than leaving it running the
	// last configuration it had.
	if !node.Enabled {
		return state, nil
	}

	inbounds, err := r.store.NodeInbounds(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		built, err := r.inbound(inbound)
		if err != nil {
			return nil, fmt.Errorf("staterender: node %s inbound %s: %w", node.UUID, inbound.Tag, err)
		}
		state.Inbounds = append(state.Inbounds, built)
	}

	users, err := r.store.UsersForNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		built, err := r.user(user)
		if err != nil {
			return nil, fmt.Errorf("staterender: node %s user %d: %w", node.UUID, user.ID, err)
		}
		state.Users = append(state.Users, built)
	}

	flux, err := r.flux(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	state.Openflux = flux

	return state, nil
}

// inbound converts one row.
func (r *Renderer) inbound(in store.NodeInbound) (*nodepb.Inbound, error) {
	protocol, err := protocolFromString(in.Protocol)
	if err != nil {
		return nil, err
	}

	params := map[string]string{}
	for k, v := range in.Params {
		params[k] = v
	}
	// The network and security columns are the authoritative values; they are
	// also mirrored into params because that is where the generator reads
	// them, and a template could have left a stale copy there.
	if in.Network != "" {
		params["network"] = in.Network
	}
	if in.Security != "" {
		params["security"] = in.Security
	}

	secrets, err := r.openSecrets(in.Secrets)
	if err != nil {
		return nil, err
	}

	core := nodepb.Core_CORE_XRAY
	if protocol == nodepb.Protocol_PROTOCOL_WNDNS {
		core = nodepb.Core_CORE_WNDNS
	}

	return &nodepb.Inbound{
		Id:            in.ID,
		Tag:           in.Tag,
		Protocol:      protocol,
		Core:          core,
		Enabled:       in.Enabled,
		ListenAddress: in.ListenAddress,
		ListenPort:    in.ListenPort,
		Params:        params,
		Secrets:       secrets,
		ForwardToTag:  in.ForwardToTag.String,
	}, nil
}

// user converts one row, decrypting the credentials.
func (r *Renderer) user(u store.User) (*nodepb.User, error) {
	password, err := r.box.OpenString(u.Password)
	if err != nil {
		return nil, fmt.Errorf("decrypt password: %w", err)
	}
	ssPassword, err := r.box.OpenString(u.SSPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt shadowsocks password: %w", err)
	}
	return &nodepb.User{
		Id:   u.ID,
		Uuid: u.UUID,
		// The email is how Xray keys this user's traffic counters, so it is
		// derived rather than stored: it must be the same string everywhere.
		Email:      xraycfg.UserEmail(u.ID, u.UUID),
		VlessUuid:  u.VLESSUUID,
		Password:   password,
		SsPassword: ssPassword,
	}, nil
}

// flux builds the OpenFlux block.
func (r *Renderer) flux(ctx context.Context, nodeID uint64) (*nodepb.OpenFluxConfig, error) {
	cfg, err := r.store.NodeOpenFluxConfig(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	// No row at all means the node has no flux, and the agent keeps the core
	// down. That is the normal case.
	if cfg == nil {
		return nil, nil
	}

	out := &nodepb.OpenFluxConfig{
		Enabled: cfg.Enabled,
		Mode:    cfg.Mode,
	}
	if !cfg.Enabled {
		return out, nil
	}

	channels, err := r.store.NodeChannels(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	for _, channel := range channels {
		built, err := r.channel(channel)
		if err != nil {
			return nil, fmt.Errorf("staterender: channel %d: %w", channel.ID, err)
		}
		out.Channels = append(out.Channels, built)
	}
	sort.Slice(out.Channels, func(i, j int) bool { return out.Channels[i].GetId() < out.Channels[j].GetId() })
	return out, nil
}

// channel converts one channel row, decrypting its key and credentials.
func (r *Renderer) channel(c store.OpenFluxChannel) (*nodepb.OpenFluxChannel, error) {
	key, err := r.box.OpenString(c.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt channel key: %w", err)
	}

	params := map[string]string{}
	for k, v := range c.Params {
		params[k] = v
	}
	// Carrier credentials (a Yandex cookie jar, a MAX token) are stored
	// encrypted in their own column and merged into params here, because that
	// is where the carrier reads them.
	if len(c.Credentials) > 0 {
		raw, err := r.box.Open(c.Credentials)
		if err != nil {
			return nil, fmt.Errorf("decrypt channel credentials: %w", err)
		}
		var creds map[string]string
		if err := json.Unmarshal(raw, &creds); err != nil {
			return nil, fmt.Errorf("parse channel credentials: %w", err)
		}
		for k, v := range creds {
			params[k] = v
		}
	}

	return &nodepb.OpenFluxChannel{
		Id:             c.ID,
		Uuid:           c.UUID,
		Enabled:        c.Enabled,
		Transport:      c.Transport,
		Url:            c.URL,
		Params:         params,
		EncryptionKey:  key,
		SessionContext: c.SessionContext.String,
	}, nil
}

// openSecrets decrypts an inbound's secrets column into a flat map.
func (r *Renderer) openSecrets(encrypted []byte) (map[string]string, error) {
	if len(encrypted) == 0 {
		return map[string]string{}, nil
	}
	raw, err := r.box.Open(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse secrets: %w", err)
	}
	return out, nil
}

// SealSecrets encrypts a secrets map for storage. It lives here so the API and
// the renderer agree on the encoding.
func SealSecrets(box *secret.Box, secrets map[string]string) ([]byte, error) {
	if len(secrets) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("staterender: marshal secrets: %w", err)
	}
	return box.Seal(raw)
}

// OpenSecrets decrypts a secrets map, for the API's edit forms.
func OpenSecrets(box *secret.Box, encrypted []byte) (map[string]string, error) {
	r := &Renderer{box: box}
	return r.openSecrets(encrypted)
}

// protocolFromString maps the database enum to the protocol enum. The two use
// the same spellings on purpose, so this is a lookup rather than a
// translation, and an unknown value is an error rather than a silent zero.
func protocolFromString(name string) (nodepb.Protocol, error) {
	switch strings.ToLower(name) {
	case store.ProtoVLESS:
		return nodepb.Protocol_PROTOCOL_VLESS, nil
	case store.ProtoVMess:
		return nodepb.Protocol_PROTOCOL_VMESS, nil
	case store.ProtoTrojan:
		return nodepb.Protocol_PROTOCOL_TROJAN, nil
	case store.ProtoShadowsocks:
		return nodepb.Protocol_PROTOCOL_SHADOWSOCKS, nil
	case store.ProtoShadowsocks2022:
		return nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022, nil
	case store.ProtoHysteria2:
		return nodepb.Protocol_PROTOCOL_HYSTERIA2, nil
	case store.ProtoWNDNS:
		return nodepb.Protocol_PROTOCOL_WNDNS, nil
	default:
		return nodepb.Protocol_PROTOCOL_UNSPECIFIED, fmt.Errorf("unknown protocol %q", name)
	}
}

// ProtocolString is the reverse, for the API.
func ProtocolString(p nodepb.Protocol) string {
	switch p {
	case nodepb.Protocol_PROTOCOL_VLESS:
		return store.ProtoVLESS
	case nodepb.Protocol_PROTOCOL_VMESS:
		return store.ProtoVMess
	case nodepb.Protocol_PROTOCOL_TROJAN:
		return store.ProtoTrojan
	case nodepb.Protocol_PROTOCOL_SHADOWSOCKS:
		return store.ProtoShadowsocks
	case nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022:
		return store.ProtoShadowsocks2022
	case nodepb.Protocol_PROTOCOL_HYSTERIA2:
		return store.ProtoHysteria2
	case nodepb.Protocol_PROTOCOL_WNDNS:
		return store.ProtoWNDNS
	default:
		return ""
	}
}
