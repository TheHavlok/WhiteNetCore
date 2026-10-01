// Package node runs the flux stack as an exit node or as a client, driven by
// a configuration struct instead of command-line flags.
//
// Upstream OpenFlux wires this up inside its main(), which is convenient for
// a CLI and useless for anything else. The panel needs to start, stop and
// reconfigure a carrier from a desired state, and the client app needs the
// same code paths, so the wiring lives here as a library and the binaries are
// thin.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/thehavlok/whitenet/internal/flux/socks5"
	"github.com/thehavlok/whitenet/internal/flux/transport"
	"github.com/thehavlok/whitenet/internal/flux/transport/control"
	"github.com/thehavlok/whitenet/internal/flux/transport/cupsonline"
	"github.com/thehavlok/whitenet/internal/flux/transport/mailru"
	"github.com/thehavlok/whitenet/internal/flux/transport/manager"
	"github.com/thehavlok/whitenet/internal/flux/transport/oneme"
	"github.com/thehavlok/whitenet/internal/flux/transport/yandex"
	"github.com/thehavlok/whitenet/internal/flux/tunnel"
)

// Carrier types, as they appear in a desired state, a share link and the
// panel. These are upstream's names: changing them would break
// interoperability with upstream clients for no gain.
const (
	CarrierDirect       = "direct"
	CarrierYandexDocs   = "yandex"
	CarrierYandexVolga  = "vyandex"
	CarrierYandexBoards = "boards"
	CarrierMailruDocs   = "mailru"
	CarrierOneMe        = "oneme"
	CarrierCupsOnline   = "cupsonline"
)

// Carriers lists every carrier this build can run, for validation and for the
// panel's dropdowns.
func Carriers() []string {
	return []string{
		CarrierDirect, CarrierYandexDocs, CarrierYandexVolga, CarrierYandexBoards,
		CarrierMailruDocs, CarrierOneMe, CarrierCupsOnline,
	}
}

// ValidCarrier reports whether name is a carrier this build knows.
func ValidCarrier(name string) bool {
	for _, c := range Carriers() {
		if c == name {
			return true
		}
	}
	return false
}

// Carrier is one rendezvous the session may ride.
type Carrier struct {
	// Name identifies the carrier inside a session; it defaults to Type.
	// Two carriers of the same type in one session need distinct names.
	Name string
	Type string
	// URL is the document, room or board. For `direct` it is unused; use
	// Params["listen"] on the exit and Params["dial"] on the client.
	URL string
	// Priority orders carriers within a session, higher first.
	Priority int
	// Params are carrier-specific: listen/dial for direct, token/uid for
	// oneme, cookies_file for vyandex.
	Params map[string]string
}

// Config is what either role needs.
type Config struct {
	// Exit selects the role. An exit terminates traffic to the internet; a
	// client hands it packets.
	Exit bool

	// Mode is the exit backend: l3 (Linux, raw sockets, needs root) or l4
	// (gVisor, portable). Ignored by a client.
	Mode string
	// LocalIP is the egress address for l3 SNAT. Empty means autodetect.
	LocalIP string

	Carriers []Carrier

	// Secret is the AES-256-GCM shared secret, hex. Required for a session,
	// which is required whenever there is more than one carrier.
	Secret string
	// Context is the KDF context; both peers must use the same string.
	// Empty falls back to the highest-priority carrier's URL, which is what
	// upstream does.
	Context string
	// Negotiate forces an authenticated session even for a single carrier.
	Negotiate bool

	// MaxPacketSize bounds one IPv4 packet in a session, 1280..65000.
	MaxPacketSize int

	// CookieStorePath persists the carriers' cookie jars across restarts, so
	// a restart does not look like a fresh browser to Yandex.
	CookieStorePath string

	// Client-only: where the local proxy listens.
	SocksAddr     string
	HTTPProxyAddr string
	// Inbound is "socks5" or "tun". A tun inbound needs root.
	Inbound string

	Log *slog.Logger
}

// DefaultConfig returns a configuration with the knobs upstream defaults to.
func DefaultConfig() Config {
	return Config{
		Mode:          "l4",
		MaxPacketSize: transport.MaxNegotiatedPacket,
		SocksAddr:     "127.0.0.1:1080",
		Inbound:       "socks5",
	}
}

// Validate rejects a configuration that cannot work, with the reason, rather
// than failing deep inside a carrier.
func (c Config) Validate() error {
	if len(c.Carriers) == 0 {
		return errors.New("flux: no carriers configured")
	}
	seen := map[string]bool{}
	for i, carrier := range c.Carriers {
		if !ValidCarrier(carrier.Type) {
			return fmt.Errorf("flux: carrier %d: unknown type %q", i, carrier.Type)
		}
		name := carrier.name()
		if seen[name] {
			return fmt.Errorf("flux: two carriers share the name %q", name)
		}
		seen[name] = true

		switch carrier.Type {
		case CarrierDirect:
			if c.Exit && carrier.Params["listen"] == "" {
				return fmt.Errorf("flux: carrier %q: direct on an exit needs params.listen", name)
			}
			if !c.Exit && carrier.Params["dial"] == "" {
				return fmt.Errorf("flux: carrier %q: direct on a client needs params.dial", name)
			}
		case CarrierOneMe:
			if carrier.Params["token"] == "" || carrier.Params["uid"] == "" {
				return fmt.Errorf("flux: carrier %q: oneme needs params.token and params.uid", name)
			}
		default:
			if carrier.URL == "" {
				return fmt.Errorf("flux: carrier %q: %s needs a URL", name, carrier.Type)
			}
		}
	}

	// More than one carrier means a session, and a session means a secret:
	// the handshake is authenticated, so there is nothing to negotiate with
	// otherwise.
	if c.sessionWanted() && c.Secret == "" {
		return errors.New("flux: a session needs a secret (several carriers, or negotiate set)")
	}
	if c.MaxPacketSize != 0 && (c.MaxPacketSize < 1280 || c.MaxPacketSize > transport.MaxNegotiatedPacket) {
		return fmt.Errorf("flux: max packet size %d is outside 1280..%d", c.MaxPacketSize, transport.MaxNegotiatedPacket)
	}
	if c.Exit {
		if _, err := tunnel.ParseExitMode(c.Mode); err != nil {
			return fmt.Errorf("flux: %w", err)
		}
	} else if c.Inbound != "socks5" && c.Inbound != "tun" {
		return fmt.Errorf("flux: inbound must be socks5 or tun, got %q", c.Inbound)
	}
	return nil
}

func (c Config) sessionWanted() bool {
	return c.Negotiate || len(c.Carriers) > 1
}

func (c Carrier) name() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Type
}

// context returns the KDF context: the configured one, else the
// highest-priority carrier's URL, matching upstream's default.
func (c Config) context() string {
	if c.Context != "" {
		return c.Context
	}
	best := -1
	ctx := ""
	for _, carrier := range c.Carriers {
		if carrier.URL != "" && carrier.Priority > best {
			best = carrier.Priority
			ctx = carrier.URL
		}
	}
	if ctx == "" {
		// Upstream's placeholder, so two peers that both fall through here
		// still derive the same key.
		return "http://#"
	}
	return ctx
}

// Factory builds raw carriers. It is the one place that knows every carrier
// package, and the session manager calls it again whenever the peer asks for
// an additional carrier at runtime.
func Factory(base transport.TransportConfig, isExit bool) manager.Factory {
	return func(cfg *control.TransportConfig) (transport.Transport, error) {
		if cfg == nil {
			return nil, errors.New("flux: nil carrier config")
		}
		param := func(key string) string {
			if cfg.Params == nil {
				return ""
			}
			v, _ := cfg.Params[key].(string)
			return v
		}
		boolParam := func(key string) bool {
			if cfg.Params == nil {
				return false
			}
			v, _ := cfg.Params[key].(bool)
			return v
		}

		switch cfg.Type {
		case CarrierYandexDocs:
			return yandex.NewYandexDocsTransport(cfg.URL, base), nil
		case CarrierYandexVolga:
			t := yandex.NewYandexVolgaTransport(cfg.URL, base)
			if file := param("cookies_file"); file != "" {
				if err := t.LoadCookieFile(file); err != nil {
					return nil, fmt.Errorf("flux: vyandex cookies: %w", err)
				}
			}
			return t, nil
		case CarrierYandexBoards:
			return yandex.NewBoardsTransport(cfg.URL, base), nil
		case CarrierMailruDocs:
			return mailru.NewMailruDocsTransport(cfg.URL, base), nil
		case CarrierCupsOnline:
			// Only an exit may create rooms: a client that creates its own
			// waits in a room the exit never joins.
			return cupsonline.NewCupsonlineTransport(cfg.URL, base, !isExit), nil
		case CarrierOneMe:
			uid, err := strconv.ParseInt(param("uid"), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("flux: oneme uid %q: %w", param("uid"), err)
			}
			return oneme.NewOneMeTransport(boolParam("exit"), param("token"), uid, base), nil
		case CarrierDirect:
			dcfg := transport.DefaultDirectConfig()
			if v := param("listen"); v != "" {
				dcfg.ListenAddr = v
			}
			if v := param("dial"); v != "" {
				dcfg.DialAddr = v
			}
			dcfg.IsExit = boolParam("is_exit")
			return transport.NewDirectTransport(base, dcfg), nil
		default:
			return nil, fmt.Errorf("flux: unknown carrier type %q", cfg.Type)
		}
	}
}

// controlConfig turns a Carrier into what the factory consumes, filling in
// the role-dependent parameters the caller should not have to repeat.
func (c Config) controlConfig(carrier Carrier) *control.TransportConfig {
	params := map[string]any{}
	for k, v := range carrier.Params {
		params[k] = v
	}
	if carrier.Type == CarrierDirect {
		params["is_exit"] = c.Exit
	}
	if carrier.Type == CarrierOneMe {
		params["exit"] = c.Exit
	}
	return &control.TransportConfig{
		Name:   carrier.name(),
		Type:   carrier.Type,
		URL:    carrier.URL,
		Params: params,
	}
}

// Instance is a running exit node or client.
type Instance struct {
	cfg Config
	log *slog.Logger

	mu        sync.Mutex
	exit      tunnel.ExitNode
	session   *transport.Session
	mgr       *manager.Manager
	raw       map[string]transport.Transport
	tun       *tunnel.TCPTunnel
	socks     *socks5.SOCKS5Server
	httpProxy net.Listener
	stopped   bool
}

// Stats is what the agent reports to the panel for one running instance.
type Stats struct {
	Connected     bool
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Reconnects    uint64
	Uptime        time.Duration
	// Carriers is the per-carrier breakdown, keyed by carrier name.
	Carriers map[string]transport.TransportStats
}

// Start brings up the configured role and returns once it is running. The
// caller stops it with Stop, or by cancelling the context passed to Run.
func Start(cfg Config) (*Instance, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}

	inst := &Instance{cfg: cfg, log: log, raw: map[string]transport.Transport{}}

	base := transport.DefaultConfig()
	carrier, err := inst.buildCarrier(base)
	if err != nil {
		return nil, err
	}

	// Starting the carrier is what begins the handshake. The exit node and
	// the client only read and write through it, so it has to be up first.
	if err := carrier.Start(); err != nil {
		return nil, fmt.Errorf("flux: carrier start: %w", err)
	}

	start := inst.startClient
	if cfg.Exit {
		start = inst.startExit
	}
	if err := start(carrier); err != nil {
		// The carrier is already running, so unwind it rather than leaving a
		// connected document behind with nothing reading from it.
		_ = inst.Stop()
		return nil, err
	}
	return inst, nil
}

// buildCarrier produces the transport the tunnel rides: either a Session
// multiplexing several carriers, or a single raw carrier when no session is
// wanted and no secret was given.
func (inst *Instance) buildCarrier(base transport.TransportConfig) (transport.Transport, error) {
	cfg := inst.cfg
	factory := Factory(base, cfg.Exit)

	// The plain path: one carrier, no secret, no session. Upstream calls
	// this "classic".
	if !cfg.sessionWanted() && cfg.Secret == "" {
		raw, err := factory(cfg.controlConfig(cfg.Carriers[0]))
		if err != nil {
			return nil, err
		}
		inst.raw[cfg.Carriers[0].name()] = raw
		return raw, nil
	}

	caps := transport.CapabilityIPv4 | transport.CapabilityTCP | transport.CapabilityUDP
	// An l3 exit can produce real ICMP errors, and a client always wants
	// them; an l4 exit cannot, so it does not claim the capability.
	if !cfg.Exit || cfg.Mode == "l3" {
		caps |= transport.CapabilityICMPErrors
	}
	maxPacket := cfg.MaxPacketSize
	if maxPacket == 0 {
		maxPacket = transport.MaxNegotiatedPacket
	}

	session, err := transport.NewSession(transport.PeerParameters{
		Capabilities:  caps,
		MaxPacketSize: maxPacket,
	}, cfg.Exit)
	if err != nil {
		return nil, fmt.Errorf("flux: session: %w", err)
	}
	// A single carrier without an explicit Negotiate still answers classic
	// clients, which is what lets an upstream client connect to our exit.
	if !cfg.Negotiate && len(cfg.Carriers) == 1 {
		session.SetClassic("batched")
	}

	kdfContext := cfg.context()
	mgr := manager.New(session, factory, cfg.Secret, kdfContext)

	var store *transport.CookieStore
	if cfg.CookieStorePath != "" {
		store, err = transport.NewCookieStore(cfg.CookieStorePath)
		if err != nil {
			inst.log.Warn("flux: cookie store unavailable, carriers will start cold",
				"path", cfg.CookieStorePath, "error", err)
			store = nil
		}
	}

	for _, carrier := range cfg.Carriers {
		name := carrier.name()
		raw, err := factory(cfg.controlConfig(carrier))
		if err != nil {
			return nil, err
		}
		inst.raw[name] = raw

		var provider manager.CookieProvider
		if p, ok := raw.(manager.CookieProvider); ok {
			provider = p
		}
		if err := session.AddTransport(name, raw, cfg.Secret, kdfContext, carrier.Priority); err != nil {
			return nil, fmt.Errorf("flux: session add %s: %w", name, err)
		}
		if err := mgr.Add(name, carrier.Type, raw, carrier.Priority, provider); err != nil {
			return nil, fmt.Errorf("flux: manager add %s: %w", name, err)
		}
		if carrier.URL != "" && carrier.URL != transport.ContextPlaceholder {
			mgr.SetURL(name, carrier.URL)
		}
		if store != nil && provider != nil {
			// Replaying a saved jar is best-effort: a carrier that cannot
			// restore one simply logs in again.
			if err := mgr.UseCookieStore(store, name, cookieKey(carrier)); err != nil {
				inst.log.Debug("flux: cookie replay failed", "carrier", name, "error", err)
			}
		}
	}

	// Without this the manager never sees the peer's control messages, so
	// runtime carrier changes, cookie handoff and captcha notifications all
	// go nowhere.
	session.SetControlHandler(mgr.DispatchControl)

	inst.session = session
	inst.mgr = mgr
	return session, nil
}

// cookieKey namespaces a carrier's jar so two channels on one node, or a
// carrier pointed at a different document, do not share cookies.
func cookieKey(carrier Carrier) string {
	key := carrier.Type + "|" + carrier.URL
	if uid := carrier.Params["uid"]; uid != "" {
		key += "|" + uid
	}
	return key
}

func (inst *Instance) startExit(carrier transport.Transport) error {
	mode, err := tunnel.ParseExitMode(inst.cfg.Mode)
	if err != nil {
		return fmt.Errorf("flux: %w", err)
	}
	if mode == tunnel.ExitModeL3 {
		if err := tunnel.SetLocalIP(inst.cfg.LocalIP); err != nil {
			return fmt.Errorf("flux: local ip: %w", err)
		}
	}
	exit, err := tunnel.NewExitNode(carrier, mode.String())
	if err != nil {
		return fmt.Errorf("flux: exit node: %w", err)
	}
	if err := exit.Start(); err != nil {
		return fmt.Errorf("flux: exit start: %w", err)
	}
	inst.mu.Lock()
	inst.exit = exit
	inst.mu.Unlock()

	inst.log.Info("flux exit running",
		"mode", exit.Mode(),
		"carriers", len(inst.cfg.Carriers),
		"session", inst.session != nil)

	// L3 SNAT makes the kernel see return packets for connections it never
	// opened, so it answers with RST and tears the tunnel's flows down. The
	// rule has to be installed outside this process.
	if mode == tunnel.ExitModeL3 {
		if inst.cfg.LocalIP != "" {
			inst.log.Warn("l3 exit needs an outbound RST filter",
				"rule", fmt.Sprintf("iptables -A OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP", inst.cfg.LocalIP))
		} else {
			inst.log.Warn("l3 exit needs an outbound RST filter, and no local_ip is set to scope it to; " +
				"assign a dedicated alias IP and set local_ip, or every outbound RST on the host has to be dropped")
		}
	}
	return nil
}

func (inst *Instance) startClient(carrier transport.Transport) error {
	// TUN belongs to the platform layers that already own it in this
	// repository (mobile/, internal/runtime), so this package offers the
	// SOCKS5 inbound only and lets those layers dial through DialTCP.
	if inst.cfg.Inbound == "tun" {
		return errors.New("flux: the tun inbound is wired by the platform layer, not by this package; use inbound socks5 and dial through Instance.DialTCP")
	}
	mode, err := tunnel.ParseExitMode(inst.cfg.Mode)
	if err != nil {
		return fmt.Errorf("flux: %w", err)
	}
	tun := tunnel.NewTCPTunnelMode(carrier, false, mode)

	socksServer := socks5.NewSOCKS5Server(inst.cfg.SocksAddr, tun)
	// Bind before Start so a port already in use is an error from Start
	// rather than a goroutine that dies unnoticed.
	if err := socksServer.Bind(); err != nil {
		tun.Close()
		return fmt.Errorf("flux: socks5 %s: %w", inst.cfg.SocksAddr, err)
	}

	var httpLn net.Listener
	if inst.cfg.HTTPProxyAddr != "" {
		httpLn, err = net.Listen("tcp", inst.cfg.HTTPProxyAddr)
		if err != nil {
			_ = socksServer.Close()
			tun.Close()
			return fmt.Errorf("flux: http proxy %s: %w", inst.cfg.HTTPProxyAddr, err)
		}
	}

	inst.mu.Lock()
	inst.tun, inst.socks, inst.httpProxy = tun, socksServer, httpLn
	inst.mu.Unlock()

	go func() {
		if err := socksServer.Start(); err != nil {
			inst.log.Debug("flux: socks5 server stopped", "error", err)
		}
	}()
	if httpLn != nil {
		go func() {
			if err := tunnel.ServeHTTPProxy(httpLn, tun.DialTCP); err != nil {
				inst.log.Debug("flux: http proxy stopped", "error", err)
			}
		}()
	}

	inst.log.Info("flux client running", "socks5", inst.cfg.SocksAddr, "http_proxy", inst.cfg.HTTPProxyAddr)
	return nil
}

// DialTCP opens a connection through the tunnel. The platform TUN layers use
// it instead of the SOCKS5 inbound.
func (inst *Instance) DialTCP(address string) (net.Conn, error) {
	inst.mu.Lock()
	tun := inst.tun
	inst.mu.Unlock()
	if tun == nil {
		return nil, errors.New("flux: no client tunnel running")
	}
	return tun.DialTCP(address)
}

// Run starts the instance and blocks until ctx is cancelled, then stops it.
func Run(ctx context.Context, cfg Config) error {
	inst, err := Start(cfg)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return inst.Stop()
}

// Stop shuts the instance down. It is safe to call more than once.
func (inst *Instance) Stop() error {
	inst.mu.Lock()
	if inst.stopped {
		inst.mu.Unlock()
		return nil
	}
	inst.stopped = true
	exit, session := inst.exit, inst.session
	tun, socksServer, httpLn := inst.tun, inst.socks, inst.httpProxy
	raw := inst.raw
	inst.mu.Unlock()

	var errs []error
	if exit != nil {
		if err := exit.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("exit stop: %w", err))
		}
	}
	if httpLn != nil {
		if err := httpLn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("http proxy stop: %w", err))
		}
	}
	if socksServer != nil {
		if err := socksServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("socks5 stop: %w", err))
		}
	}
	if tun != nil {
		tun.Close()
	}
	if session != nil {
		if err := session.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("session stop: %w", err))
		}
	} else {
		// Without a session the raw carrier was never owned by anything
		// else, so stop it here.
		for name, t := range raw {
			if err := t.Stop(); err != nil {
				errs = append(errs, fmt.Errorf("carrier %s stop: %w", name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Stats reports what the panel shows for this instance.
func (inst *Instance) Stats() Stats {
	inst.mu.Lock()
	session, raw := inst.session, inst.raw
	inst.mu.Unlock()

	out := Stats{Carriers: map[string]transport.TransportStats{}}
	for name, t := range raw {
		s := t.Stats()
		out.Carriers[name] = s
		out.BytesSent += s.BytesSent
		out.BytesReceived += s.BytesReceived
		out.PacketsSent += s.PacketsSent
		out.PacketsRecv += s.PacketsRecv
		out.Reconnects += s.Reconnects
		if s.Connected {
			out.Connected = true
		}
		if s.Uptime > out.Uptime {
			out.Uptime = s.Uptime
		}
	}
	if session != nil {
		// A session is only usable once the handshake finished, which is a
		// stronger statement than "a carrier is connected" and is what the
		// panel means by an active channel.
		if _, ok := session.PeerParameters(); !ok {
			out.Connected = false
		}
	}
	return out
}

// SessionActive reports whether a peer completed the handshake. For an exit
// this answers "is a client on this channel right now", which is what the
// panel needs to know whether a lease is really in use.
func (inst *Instance) SessionActive() bool {
	inst.mu.Lock()
	session := inst.session
	inst.mu.Unlock()
	if session == nil {
		// Without a session, a connected carrier is the best signal there is.
		return inst.Stats().Connected
	}
	_, ok := session.PeerParameters()
	return ok
}
