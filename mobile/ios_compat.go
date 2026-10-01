package mobile

// #cgo darwin LDFLAGS: -lresolv
// #cgo ios LDFLAGS: -lresolv
import "C"

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"

	"github.com/thehavlok/whitenet/internal/memprofile"
	masterdnsvpn_client "github.com/thehavlok/whitenet/masterdnsvpn/client"
	masterdnsvpn_config "github.com/thehavlok/whitenet/masterdnsvpn/config"
)

// Client represents a running VPN/Tunnel client instance.
type Client struct {
	socksPort int
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	Stop()
}

// yamlConfig duplicates the necessary fields from the desktop client's config
// to allow parsing the same config.yaml string on mobile.
type yamlConfig struct {
	Auth struct {
		Provider string `yaml:"provider"`
	} `yaml:"auth"`
	Room struct {
		ID      string `yaml:"id"`
		Channel string `yaml:"channel"`
	} `yaml:"room"`
	Crypto struct {
		Key string `yaml:"key"`
	} `yaml:"crypto"`
	Net struct {
		DNS       string `yaml:"dns"`
		Transport string `yaml:"transport"`
	} `yaml:"net"`
	MasterDns struct {
		Domains []string `yaml:"domains"`
		// Method is the tunnel's encryption method, which has to match the
		// server's: 0 none, 1 XOR, 2 ChaCha20, 3-5 AES-128/192/256-GCM. The
		// key length is fixed per method, so a mismatch fails at the
		// handshake rather than degrading.
		Method int `yaml:"method"`
	} `yaml:"masterdns"`
	Socks struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"socks"`
	Debug bool `yaml:"debug"`
}

const maxConcurrentTCP = 64 // limit simultaneous TCP connections to save memory

// iosSoftMemoryLimit keeps the Go heap comfortably under the NEPacketTunnelProvider
// jetsam ceiling so the extension is not killed mid-session.
const iosSoftMemoryLimit = 34 << 20

var (
	tunOnce      sync.Once
	activeClient *Client
	pipe         *swiftPipe
	tcpSem       chan struct{} // semaphore for TCP concurrency
)

// swiftPipe bridges Swift byte array boundaries into a standard io.ReadWriter
type swiftPipe struct {
	in  chan []byte
	out chan []byte
}

func newSwiftPipe() *swiftPipe {
	return &swiftPipe{
		in:  make(chan []byte, 256),
		out: make(chan []byte, 256),
	}
}

func (p *swiftPipe) Read(b []byte) (int, error) {
	data, ok := <-p.in
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	return n, nil
}

func (p *swiftPipe) Write(b []byte) (int, error) {
	clone := make([]byte, len(b))
	copy(clone, b)
	select {
	case p.out <- clone:
	default:
		log.Println("dropped outbound packet (channel full)")
	}
	return len(b), nil
}

// initTUN sets up the gvisor stack for tun2socks.
func initTUN() {
	tunOnce.Do(func() {
		// Семафор создаётся здесь, а не в StartVPN: StartVPN теперь может быть
		// вызван повторно (перезапуск клиента на месте при пробуждении или
		// смене профиля), а соединения предыдущей сессии ещё живы. Они вернут
		// свой токен через <-tcpSem уже в НОВЫЙ канал и либо исчерпают его,
		// либо заблокируются на пустом.
		tcpSem = make(chan struct{}, maxConcurrentTCP)

		pipe = newSwiftPipe()

		// Create gVisor link endpoint based on our swift pipe
		// MTU is standard 1500, no offset.
		ep, err := iobased.New(pipe, 1500, 0)
		if err != nil {
			log.Fatalf("failed to create iobased endpoint: %v", err)
		}

		handler := &tunHandler{}

		cfg := &core.Config{
			LinkEndpoint:     ep,
			TransportHandler: handler,
		}

		_, err = core.CreateStack(cfg)
		if err != nil {
			log.Fatalf("failed to create tun2socks stack: %v", err)
		}
	})
}

// InputPacket feeds an IP packet (read from iOS NEPacketTunnelProvider) into the TCP/IP stack.
func InputPacket(packet []byte) {
	initTUN()
	clone := make([]byte, len(packet))
	copy(clone, packet)
	select {
	case pipe.in <- clone:
	default:
		// drop if full
	}
}

// GetPacket blocks until an IP packet is ready to be written to iOS NEPacketTunnelProvider.
func GetPacket() []byte {
	initTUN()
	return <-pipe.out
}

// tunHandler implements adapter.TransportHandler
type tunHandler struct{}

func (h *tunHandler) HandleTCP(conn adapter.TCPConn) {
	if activeClient == nil {
		_ = conn.Close()
		return
	}

	// Limit concurrent TCP connections to prevent memory exhaustion
	select {
	case tcpSem <- struct{}{}:
	default:
		// Too many connections — reject this one
		_ = conn.Close()
		return
	}

	target := conn.LocalAddr().(*net.TCPAddr)
	host := target.IP.String()
	port := target.Port

	// Dial the local SOCKS5 proxy provided by whitenet
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", activeClient.socksPort), nil, proxy.Direct)
	if err != nil {
		log.Printf("failed to create socks proxy dialer: %v", err)
		_ = conn.Close()
		<-tcpSem
		return
	}

	remoteConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Printf("tunnel dial failed for %s:%d: %v", host, port, err)
		_ = conn.Close()
		<-tcpSem
		return
	}

	// Use small 4KB buffers instead of default 32KB to save memory on iOS
	buf1 := make([]byte, 4096)
	buf2 := make([]byte, 4096)

	// Bidirectional copy with a WaitGroup to release semaphore when both directions finish
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.CopyBuffer(remoteConn, conn, buf1) // Local -> Remote
	}()

	go func() {
		defer wg.Done()
		_, _ = io.CopyBuffer(conn, remoteConn, buf2) // Remote -> Local
	}()

	go func() {
		wg.Wait()
		_ = conn.Close()
		_ = remoteConn.Close()
		<-tcpSem // release slot
	}()
}

func (h *tunHandler) HandleUDP(conn adapter.UDPConn) {
	// Not implemented in WhiteNet originally either, just drop.
	conn.Close()
}

// StartVPN is the main entry point for the iOS TUN mode.
func StartVPN(config string) (*Client, error) {
	// См. StartVPNAndroid: тип профиля определяется по формату конфига.
	if IsXrayConfig(config) {
		return startXrayIOS(config)
	}

	yamlString := config

	// Aggressive GC: iOS Network Extensions run under a hard jetsam limit
	// (50 MB for a packet tunnel provider). Going over it kills the
	// extension, which the OS reports to the app as an unexpected
	// disconnect -- one of the main reasons the tunnel kept dropping.
	// A soft memory limit makes the Go GC work harder well before the
	// extension reaches the ceiling.
	debug.SetGCPercent(20)
	debug.SetMemoryLimit(iosSoftMemoryLimit)

	// Стек tun2socks и семафор соединений поднимаются один раз на процесс.
	// Вызывать initTUN здесь безопасно: внутри sync.Once.
	initTUN()

	// Переключает smux на мобильные размеры буферов: десктопные 16 МБ на
	// сессию и 1 МБ на поток в расширение с лимитом 50 МБ не помещаются.
	memprofile.SetMobile(true)

	// Scope every background loop started below to this run, so Stop()
	// (called from stopTunnel) actually stops them instead of letting the
	// supervisor immediately reconnect.
	supCtx := newSupervisorContext()

	var cfg yamlConfig
	if err := yaml.Unmarshal([]byte(yamlString), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	log.Printf("StartVPN: provider=%s room=%s transport=%s socks_port=%d",
		cfg.Auth.Provider, cfg.Room.ID, cfg.Net.Transport, cfg.Socks.Port)

	if cfg.Debug {
		SetDebug(true)
	}

	if cfg.Net.Transport != "" {
		SetTransport(cfg.Net.Transport)
	}

	if cfg.Net.DNS != "" {
		SetDNS(cfg.Net.DNS)
	}

	port := cfg.Socks.Port
	if port == 0 {
		port = 10808 // fallback port
	}

	// Предыдущее ядро могло ещё не отпустить порт: профили часто делят один
	// и тот же. Проверка готовности приняла бы его слушатель за наш.
	waitForPortFree(port, portFreeTimeout)

	clientID := cfg.Room.Channel
	if clientID == "" {
		clientID = fmt.Sprintf("ios-client-%d", time.Now().UnixNano())
	}

	log.Printf("StartVPN: starting whitenet with clientID=%s port=%d", clientID, port)

	if cfg.Auth.Provider == "dns" || cfg.Net.Transport == "dns" {
		// Launch MasterDnsVPN
		// Every domain, not just the first: a resolver that rate-limits one
		// of them still leaves the others, which is the reason the panel
		// lets an operator delegate several.
		domains := make([]string, 0, len(cfg.MasterDns.Domains))
		for _, domain := range cfg.MasterDns.Domains {
			if domain = strings.TrimSpace(domain); domain != "" {
				domains = append(domains, strconv.Quote(domain))
			}
		}
		if len(domains) == 0 && cfg.Room.ID != "" {
			// Older profiles put the single domain in room.id, so that is
			// still honoured rather than failing a config that used to work.
			domains = append(domains, strconv.Quote(cfg.Room.ID))
		}
		if len(domains) == 0 {
			return nil, fmt.Errorf("the DNS profile names no domain to tunnel through")
		}

		jsonStr := fmt.Sprintf(`{
			"PROTOCOL_TYPE": "SOCKS5",
			"DOMAINS": [%s],
			"DATA_ENCRYPTION_METHOD": %d,
			"ENCRYPTION_KEY": "%s",
			"LISTEN_IP": "127.0.0.1",
			"LISTEN_PORT": %d,
			"MAX_DOWNLOAD_MTU": 2500,
			"RX_TX_WORKERS": 12,
			"TUNNEL_PROCESS_WORKERS": 4,
			"ARQ_WINDOW_SIZE": 1500,
			"PACKET_DUPLICATION_COUNT": 1
		}`, strings.Join(domains, ", "), encryptionMethod(cfg.MasterDns.Method), cfg.Crypto.Key, port)

		b64 := base64.StdEncoding.EncodeToString([]byte(jsonStr))

		appCfg, err := masterdnsvpn_config.LoadClientConfigFromJSONBase64WithOverrides(b64, masterdnsvpn_config.ClientConfigOverrides{})
		if err != nil {
			return nil, fmt.Errorf("failed to load masterdnsvpn config: %w", err)
		}

		// Inject fallback resolvers if none exist
		if len(appCfg.Resolvers) == 0 {
			appCfg.Resolvers = []masterdnsvpn_config.ResolverAddress{
				{IP: "77.88.8.8", Port: 53},
				{IP: "77.88.8.1", Port: 53},
				{IP: "77.88.8.88", Port: 53},
				{IP: "77.88.8.2", Port: 53},
				{IP: "77.88.8.7", Port: 53},
				{IP: "77.88.8.3", Port: 53},
			}
			appCfg.ResolverMap = make(map[string]int)
			for i, r := range appCfg.Resolvers {
				appCfg.ResolverMap[r.IP] = i
			}
		}

		app, err := masterdnsvpn_client.BootstrapLoadedConfig(appCfg, "")
		if err != nil {
			return nil, fmt.Errorf("failed to start MasterDnsVPN: %w", err)
		}
		markDNSCoreRunning(true)

		go func() {
			// Пока этот цикл жив, активное ядро — MasterDNS. IsRunning должен
			// это видеть: иначе внешние проверки здоровья считают туннель мёртвым.
			defer markDNSCoreRunning(false)

			for {
				if supCtx.Err() != nil {
					log.Println("MasterDnsVPN supervisor stopped")
					return
				}

				err := app.Run(supCtx)

				if supCtx.Err() != nil {
					log.Println("MasterDnsVPN stopped by user")
					return
				}

				if err != nil {
					log.Printf("MasterDnsVPN Error: %v — will auto-reconnect in 3s", err)
				} else {
					log.Println("MasterDnsVPN exited cleanly — will auto-reconnect in 3s")
				}

				if !sleepOrDone(supCtx, 3*time.Second) {
					return
				}

				// Re-bootstrap a fresh client instance
				newApp, bootstrapErr := masterdnsvpn_client.BootstrapLoadedConfig(appCfg, "")
				if bootstrapErr != nil {
					log.Printf("MasterDnsVPN reconnect bootstrap failed: %v — retrying in 5s", bootstrapErr)
					if !sleepOrDone(supCtx, 5*time.Second) {
						return
					}
					continue
				}
				app = newApp
				log.Println("MasterDnsVPN reconnected successfully!")
			}
		}()
	} else {
		// Start the original whitenet client
		err := Start(
			cfg.Auth.Provider,
			cfg.Room.ID,
			clientID,
			cfg.Crypto.Key,
			port,
			cfg.Socks.User,
			cfg.Socks.Pass,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to start whitenet: %w", err)
		}

		// Wait for SOCKS5 server to come up (30s for WebRTC negotiation)
		log.Println("StartVPN: waiting for SOCKS5 proxy to become ready...")
		if err := WaitReady(30000); err != nil {
			log.Printf("StartVPN: WaitReady failed: %v", err)
			Stop() // clean up
			return nil, fmt.Errorf("whitenet not ready: %w", err)
		}

		// Auto-reconnect: monitor the session and restart if it dies.
		// internal/client reconnects the carrier on its own and keeps the SOCKS
		// listener up, so this loop only has to cover the case where the whole
		// run ends. It is scoped to supCtx so Stop() ends it: previously it ran
		// forever and resurrected the client seconds after the user (or the OS)
		// shut the tunnel down.
		go func() {
			for {
				if !sleepOrDone(supCtx, 3*time.Second) {
					log.Println("StartVPN: supervisor stopped")
					return
				}

				if IsRunning() {
					continue
				}

				log.Println("StartVPN: session died, attempting auto-reconnect...")

				if !sleepOrDone(supCtx, 2*time.Second) {
					return
				}

				reconnErr := Start(
					cfg.Auth.Provider,
					cfg.Room.ID,
					clientID,
					cfg.Crypto.Key,
					port,
					cfg.Socks.User,
					cfg.Socks.Pass,
				)
				if reconnErr != nil {
					log.Printf("StartVPN: reconnect Start failed: %v", reconnErr)
					continue
				}

				if waitErr := WaitReady(30000); waitErr != nil {
					log.Printf("StartVPN: reconnect WaitReady failed: %v", waitErr)
					stopClient()
					continue
				}

				log.Println("StartVPN: reconnected successfully!")
			}
		}()
	}

	log.Printf("StartVPN: SOCKS5 proxy ready on 127.0.0.1:%d", port)

	// Initialize the tun2socks stack
	initTUN()

	activeClient = &Client{socksPort: port}
	return activeClient, nil
}
