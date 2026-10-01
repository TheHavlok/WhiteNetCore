package mobile

import (
	"context"
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
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"

	"github.com/thehavlok/whitenet/internal/memprofile"
	"github.com/thehavlok/whitenet/internal/protect"
	masterdnsvpn_client "github.com/thehavlok/whitenet/masterdnsvpn/client"
	masterdnsvpn_config "github.com/thehavlok/whitenet/masterdnsvpn/config"
)

var (
	tunOnceAndroid      sync.Once
	activeClientAndroid *Client
	pipeAndroid         *androidPipeStruct
	tcpSemAndroid       *semaphore.Weighted
)

type androidPipeStruct struct {
	in  chan []byte
	out chan []byte
}

func newAndroidPipe() *androidPipeStruct {
	return &androidPipeStruct{
		in:  make(chan []byte, 256),
		out: make(chan []byte, 256),
	}
}

func (p *androidPipeStruct) Read(b []byte) (int, error) {
	data, ok := <-p.in
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	return n, nil
}

func (p *androidPipeStruct) Write(b []byte) (int, error) {
	clone := make([]byte, len(b))
	copy(clone, b)
	select {
	case p.out <- clone:
	default:
		log.Println("dropped outbound packet (channel full)")
	}
	return len(b), nil
}

func initTUNAndroid() {
	tunOnceAndroid.Do(func() {
		debug.SetGCPercent(20)
		tcpSemAndroid = semaphore.NewWeighted(64)
		pipeAndroid = newAndroidPipe()

		ep, err := iobased.New(pipeAndroid, 1500, 0)
		if err != nil {
			log.Fatalf("failed to create iobased endpoint: %v", err)
		}

		handler := &tunHandlerAndroid{}

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

// InputPacketAndroid feeds an IP packet into the TCP/IP stack.
func InputPacketAndroid(packet []byte) {
	initTUNAndroid()
	clone := make([]byte, len(packet))
	copy(clone, packet)
	select {
	case pipeAndroid.in <- clone:
	default:
	}
}

// GetPacketAndroid blocks until an IP packet is ready.
func GetPacketAndroid() []byte {
	initTUNAndroid()
	return <-pipeAndroid.out
}

type tunHandlerAndroid struct{}

func (h *tunHandlerAndroid) HandleTCP(conn adapter.TCPConn) {
	// Wait up to 15 seconds for SOCKS5 proxy to become ready
	for i := 0; i < 150; i++ {
		if activeClientAndroid != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if activeClientAndroid == nil {
		_ = conn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tcpSemAndroid.Acquire(ctx, 1); err != nil {
		log.Printf("tun2socks dropped TCP connection: too many concurrent connections")
		_ = conn.Close()
		return
	}
	defer tcpSemAndroid.Release(1)

	target := conn.LocalAddr().(*net.TCPAddr)
	host := target.IP.String()
	port := target.Port

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", activeClientAndroid.socksPort), nil, proxy.Direct)
	if err != nil {
		log.Printf("failed to create socks proxy dialer: %v", err)
		_ = conn.Close()
		return
	}

	remoteConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Printf("tunnel dial failed for %s:%d: %v", host, port, err)
		_ = conn.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer conn.Close()
		defer remoteConn.Close()
		buf := make([]byte, 4096)
		_, _ = io.CopyBuffer(remoteConn, conn, buf)
	}()

	go func() {
		defer wg.Done()
		defer conn.Close()
		defer remoteConn.Close()
		buf := make([]byte, 4096)
		_, _ = io.CopyBuffer(conn, remoteConn, buf)
	}()

	wg.Wait()
}

func (h *tunHandlerAndroid) HandleUDP(conn adapter.UDPConn) {
	target := conn.LocalAddr().(*net.UDPAddr)

	// Only proxy DNS (port 53) to the real network to resolve domains.
	if target.Port != 53 {
		conn.Close()
		return
	}

	go func() {
		defer conn.Close()

		dialer := protect.NewDialer()
		remoteConn, err := dialer.Dial("udp", target.String())
		if err != nil {
			return
		}
		defer remoteConn.Close()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				_, err = remoteConn.Write(buf[:n])
				if err != nil {
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				n, err := remoteConn.Read(buf)
				if err != nil {
					return
				}
				_, err = conn.Write(buf[:n])
				if err != nil {
					return
				}
			}
		}()

		wg.Wait()
	}()
}

// StartVPNAndroid is the dedicated entry point for Android.
func StartVPNAndroid(config string) (*Client, error) {
	// Профиль Xray приходит тем же полем, что и WhiteNet-овский, и отличается
	// только форматом: JSON против YAML. Разводим по содержимому, чтобы
	// платформенным слоям не пришлось таскать рядом отдельный флаг типа —
	// сохранение конфига, START_STICKY-восстановление и смена профиля по сети
	// продолжают работать без единой правки.
	if IsXrayConfig(config) {
		return startXrayAndroid(config)
	}

	yamlString := config

	var cfg yamlConfig
	if err := yaml.Unmarshal([]byte(yamlString), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	// Scope every background loop started below to this run. Stop() cancels
	// it, so a user-initiated disconnect (or a revoke by another VPN app) is
	// never undone by the supervisor.
	supCtx := newSupervisorContext()

	// Телефон — не десктоп: те же мобильные размеры буферов, что и на iOS.
	memprofile.SetMobile(true)

	if cfg.Debug {
		SetDebug(true)
	}

	if cfg.Net.Transport != "" {
		SetTransport(cfg.Net.Transport)
	}

	dnsServer := cfg.Net.DNS
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}

	// Prevent mobile.go from overwriting net.DefaultResolver with an unprotected dialer
	SetDNS("")

	// Override DNS resolver with our protected dialer explicitly for Android
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return protect.DialContext(ctx, network, dnsServer)
		},
	}

	port := cfg.Socks.Port
	if port == 0 {
		port = 10808
	}

	// Предыдущее ядро могло ещё не отпустить порт: профили часто делят один
	// и тот же. Проверка готовности приняла бы его слушатель за наш.
	waitForPortFree(port, portFreeTimeout)

	clientID := cfg.Room.Channel
	if clientID == "" {
		clientID = fmt.Sprintf("android-client-%d", time.Now().UnixNano())
	}

	log.Printf("StartVPNAndroid: starting whitenet with clientID=%s port=%d", clientID, port)

	if cfg.Auth.Provider == "dns" || cfg.Net.Transport == "dns" {
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
		go func() {
			for {
				if supCtx.Err() != nil {
					log.Println("WebRTC supervisor stopped")
					return
				}

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
					log.Printf("WebRTC Start VPN failed: %v", err)
				}

				err = WaitReady(120000)
				if err != nil {
					log.Printf("WebRTC WaitReady failed: %v", err)
					stopClient()
					if !sleepOrDone(supCtx, 3*time.Second) {
						return
					}
					continue
				}

				mu.Lock()
				d := done
				mu.Unlock()

				// internal/client already reconnects the carrier on its own and
				// keeps the SOCKS listener up, so reaching this point means the
				// whole run really ended (context cancelled or conference over).
				if d != nil {
					select {
					case <-d:
					case <-supCtx.Done():
						return
					}
				} else if !sleepOrDone(supCtx, 3*time.Second) {
					return
				}

				if supCtx.Err() != nil {
					log.Println("WebRTC VPN stopped by user")
					return
				}

				log.Printf("WebRTC VPN session died, restarting...")
			}
		}()
	}

	ready := false
	for i := 0; i < 1200; i++ {
		if supCtx.Err() != nil {
			log.Printf("StartVPNAndroid: cancelled while waiting for SOCKS proxy")
			return nil, fmt.Errorf("whitenet start cancelled")
		}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}

		if !sleepOrDone(supCtx, 100*time.Millisecond) {
			return nil, fmt.Errorf("whitenet start cancelled")
		}
	}

	if !ready {
		log.Printf("StartVPNAndroid: SOCKS proxy did not become ready")
		Stop()
		return nil, fmt.Errorf("whitenet socks proxy not ready")
	}

	log.Printf("StartVPNAndroid: SOCKS5 proxy ready on 127.0.0.1:%d", port)

	initTUNAndroid()

	activeClientAndroid = &Client{socksPort: port}
	return activeClientAndroid, nil
}
