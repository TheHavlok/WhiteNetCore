// Package subscription defines WhiteNetVPN's own subscription format: the
// JSON the app fetches, and the server objects that the whitenet:// share
// links carry.
//
// One set of types serves both, so a server described in a link and the same
// server in a subscription are byte-for-byte the same object. No v2ray links,
// no Clash: the app is ours and this format says exactly what it needs.
//
// Compatibility rules, so old apps keep working:
//   - Version is bumped only for a change that an old client cannot ignore.
//   - New fields are added as omitempty and must be optional in meaning too.
//   - A client must skip a server whose protocol it does not recognise rather
//     than failing the whole subscription.
package subscription

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Version is the format version. A client that sees a higher number should
// tell the user to update rather than guess.
const Version = 1

// Protocol values. These are the wire names; they are also what the panel
// stores, so there is one spelling of each throughout the system.
const (
	ProtocolVLESS           = "vless"
	ProtocolVMess           = "vmess"
	ProtocolTrojan          = "trojan"
	ProtocolShadowsocks     = "shadowsocks"
	ProtocolShadowsocks2022 = "shadowsocks2022"
	ProtocolHysteria2       = "hysteria2"
	// ProtocolWNDNS is the WhiteNet DNS tunnel. Its Chain field carries the
	// inner protocol the tunnel forwards to.
	ProtocolWNDNS = "wndns"
	// ProtocolFlux is the ported OpenFlux stack: traffic rides a carrier such
	// as a Yandex document or a MAX room.
	ProtocolFlux = "flux"
)

// User status values.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusExpired  = "expired"
	StatusLimited  = "limited"
)

// Response is the whole subscription document.
type Response struct {
	Version int `json:"version"`
	// IssuedAt lets the app show how fresh its copy is, and lets it ignore
	// an out-of-order reply from a cache.
	IssuedAt time.Time `json:"issued_at"`
	// UpdateIntervalHours is how often the app should refetch. The panel
	// decides, so the refresh rate can be changed without an app update.
	UpdateIntervalHours int `json:"update_interval_hours"`

	User     User      `json:"user"`
	Servers  []Server  `json:"servers"`
	Branding *Branding `json:"branding,omitempty"`
}

// User is the account as the app displays it.
type User struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	// ExpiresAt is nil for an account that never expires.
	ExpiresAt *time.Time `json:"expires_at"`
	// TrafficUsed and TrafficLimit are bytes; a limit of 0 means unlimited.
	TrafficUsed  uint64 `json:"traffic_used"`
	TrafficLimit uint64 `json:"traffic_limit"`
	// DevicesLimit of 0 means unlimited.
	DevicesLimit int `json:"devices_limit"`
	DevicesUsed  int `json:"devices_used"`
	// Status is one of the Status* constants. A subscription is still served
	// for a disabled or expired user - with an empty server list - so the app
	// can say why nothing works instead of showing a network error.
	Status string `json:"status"`
}

// Server is one connectable endpoint.
type Server struct {
	// ID is "<node-uuid>:<inbound-tag>", stable across subscription fetches,
	// so the app can remember a preferred server and keep per-server stats.
	ID string `json:"id"`
	// Name is what the user sees, e.g. "🇩🇪 Germany 1".
	Name string `json:"name"`
	// Country is an ISO 3166-1 alpha-2 code, for the flag.
	Country string `json:"country,omitempty"`
	// Group is the node group's name, for grouping in the UI.
	Group string `json:"group,omitempty"`

	Protocol string `json:"protocol"`
	// Transport is the protocol's carrier: reality, xhttp, ws, grpc,
	// httpupgrade, kcp, raw, tls for Xray; "dns" for wndns; the carrier name
	// for flux. Empty where the protocol has only one.
	Transport string `json:"transport,omitempty"`

	// Address and Port are where the app connects. Empty for flux, which
	// reaches its exit through a carrier instead of an address.
	Address string `json:"address,omitempty"`
	Port    int    `json:"port,omitempty"`

	// Sort orders the list; lower comes first. Equal values fall back to Name.
	Sort int `json:"sort,omitempty"`

	// Params are protocol-specific. Strings throughout, because that is what
	// every consumer of them wants and it keeps the format stable when a new
	// knob appears.
	Params map[string]string `json:"params,omitempty"`

	// Chain is the inner hop for a protocol that tunnels another one. For
	// wndns it is the Xray inbound the tunnel forwards to: the app brings up
	// the DNS tunnel, then speaks Chain's protocol through it.
	Chain *Chain `json:"chain,omitempty"`

	// Flux carries the flux carriers for ProtocolFlux.
	Flux *Flux `json:"flux,omitempty"`
}

// Chain is an inner protocol reached through the outer one. It deliberately
// has no address: the app dials whatever local endpoint the outer tunnel
// exposes.
type Chain struct {
	Protocol  string            `json:"protocol"`
	Transport string            `json:"transport,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
}

// Flux describes a flux server.
//
// A flux channel carries one client at a time, so a subscription normally
// hands the app a Lease endpoint rather than a channel: the app asks for a
// free channel when it connects and renews while it uses it. Channels is
// filled in only when a channel is dedicated to this user.
type Flux struct {
	// Mode is the exit backend: l3 or l4. The app does not run the exit, but
	// it affects what the session negotiates.
	Mode string `json:"mode,omitempty"`
	// Lease is where to ask for a channel: a URL that answers with a
	// LeaseResponse.
	Lease string `json:"lease,omitempty"`
	// Channels is a dedicated channel, or several to choose from, when the
	// panel assigned them rather than pooling them.
	Channels []Channel `json:"channels,omitempty"`
}

// Channel is one flux rendezvous: the carriers and the key for them.
type Channel struct {
	ID string `json:"id"`
	// Secret is the AES-256-GCM shared secret, hex. Whoever holds it can use
	// the channel, so a subscription carrying one is a bearer credential.
	Secret string `json:"secret"`
	// Context is the KDF context; it must match the exit's exactly.
	Context  string    `json:"context,omitempty"`
	Carriers []Carrier `json:"carriers"`
}

// Carrier is one way into a channel.
type Carrier struct {
	// Type is a flux carrier name: yandex, vyandex, boards, mailru,
	// cupsonline, oneme, direct.
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
	// URL is the document, room or board. Unused by direct.
	URL string `json:"url,omitempty"`
	// Priority orders carriers inside a session; higher is tried first.
	Priority int `json:"priority,omitempty"`
	// Params are carrier-specific, e.g. dial for direct.
	Params map[string]string `json:"params,omitempty"`
}

// LeaseResponse is what a flux Lease endpoint answers.
type LeaseResponse struct {
	Channel Channel `json:"channel"`
	// ExpiresAt is when the lease lapses unless renewed. The app should renew
	// at about half of the remaining time.
	ExpiresAt time.Time `json:"expires_at"`
	// RenewURL renews this lease; ReleaseURL hands the channel back when the
	// user disconnects, so it does not sit idle until it expires.
	RenewURL   string `json:"renew_url,omitempty"`
	ReleaseURL string `json:"release_url,omitempty"`
}

// Branding is what the panel's settings let an operator change without a new
// app build.
type Branding struct {
	AppName    string `json:"app_name,omitempty"`
	LogoURL    string `json:"logo_url,omitempty"`
	SupportURL string `json:"support_url,omitempty"`
	// Message is shown in the app, e.g. a maintenance notice.
	Message string `json:"message,omitempty"`
	// AccentColor is a hex colour such as "#3b82f6".
	AccentColor string `json:"accent_color,omitempty"`
}

// Validate checks a document for the mistakes that would leave the app with
// nothing to connect to. The panel runs it before serving, so a bad
// configuration is a log line on the server rather than a silent failure on
// a phone.
func (r Response) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("subscription: version %d, want %d", r.Version, Version)
	}
	if r.User.UUID == "" {
		return fmt.Errorf("subscription: user uuid is empty")
	}
	switch r.User.Status {
	case StatusActive, StatusDisabled, StatusExpired, StatusLimited:
	default:
		return fmt.Errorf("subscription: unknown user status %q", r.User.Status)
	}
	seen := map[string]bool{}
	for i, server := range r.Servers {
		if err := server.Validate(); err != nil {
			return fmt.Errorf("subscription: server %d: %w", i, err)
		}
		if seen[server.ID] {
			return fmt.Errorf("subscription: duplicate server id %q", server.ID)
		}
		seen[server.ID] = true
	}
	return nil
}

// Validate checks one server.
func (s Server) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("id is empty")
	}
	if s.Name == "" {
		return fmt.Errorf("name is empty")
	}
	switch s.Protocol {
	case ProtocolVLESS, ProtocolVMess, ProtocolTrojan,
		ProtocolShadowsocks, ProtocolShadowsocks2022, ProtocolHysteria2:
		if s.Address == "" {
			return fmt.Errorf("%s needs an address", s.Protocol)
		}
		if s.Port <= 0 || s.Port > 65535 {
			return fmt.Errorf("%s has port %d", s.Protocol, s.Port)
		}

	case ProtocolWNDNS:
		if s.Address == "" {
			return fmt.Errorf("wndns needs an address")
		}
		if len(s.Params["domains"]) == 0 {
			return fmt.Errorf("wndns needs params.domains")
		}
		// Without the inner hop the tunnel carries traffic that nothing
		// authenticates, which is exactly what the chain exists to prevent.
		if s.Chain == nil {
			return fmt.Errorf("wndns needs a chain")
		}
		if s.Chain.Protocol == "" {
			return fmt.Errorf("wndns chain has no protocol")
		}

	case ProtocolFlux:
		if s.Flux == nil {
			return fmt.Errorf("flux needs a flux block")
		}
		if s.Flux.Lease == "" && len(s.Flux.Channels) == 0 {
			return fmt.Errorf("flux needs either a lease url or at least one channel")
		}
		for i, channel := range s.Flux.Channels {
			if err := channel.Validate(); err != nil {
				return fmt.Errorf("flux channel %d: %w", i, err)
			}
		}

	case "":
		return fmt.Errorf("protocol is empty")
	default:
		return fmt.Errorf("unknown protocol %q", s.Protocol)
	}
	return nil
}

// Validate checks one flux channel.
func (c Channel) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("id is empty")
	}
	if c.Secret == "" {
		return fmt.Errorf("secret is empty")
	}
	if len(c.Carriers) == 0 {
		return fmt.Errorf("no carriers")
	}
	// More than one carrier means the session multiplexes them, and the
	// session is authenticated, so names have to be distinct.
	names := map[string]bool{}
	for i, carrier := range c.Carriers {
		if carrier.Type == "" {
			return fmt.Errorf("carrier %d has no type", i)
		}
		name := carrier.Name
		if name == "" {
			name = carrier.Type
		}
		if names[name] {
			return fmt.Errorf("two carriers share the name %q", name)
		}
		names[name] = true
	}
	return nil
}

// DomainList splits a wndns server's params.domains, which is a
// comma-separated list because Params is flat strings.
func (s Server) DomainList() []string {
	raw := s.Params["domains"]
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// MarshalJSON is defined on Response only to guarantee the version field is
// right even if a caller builds the struct by hand and forgets it.
func (r Response) MarshalJSON() ([]byte, error) {
	type raw Response
	copied := raw(r)
	if copied.Version == 0 {
		copied.Version = Version
	}
	if copied.Servers == nil {
		// An empty list and a null mean different things to a client; always
		// send a list.
		copied.Servers = []Server{}
	}
	return json.Marshal(copied)
}
