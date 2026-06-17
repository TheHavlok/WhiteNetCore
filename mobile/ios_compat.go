package mobile

// #cgo darwin LDFLAGS: -lresolv
// #cgo ios LDFLAGS: -lresolv
import "C"

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"

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
	} `yaml:"masterdns"`
	Socks struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"socks"`
	Debug bool `yaml:"debug"`
}

var (
	tunOnce      sync.Once
	activeClient *Client
	pipe         *swiftPipe
)

// swiftPipe bridges Swift byte array boundaries into a standard io.ReadWriter
type swiftPipe struct {
	in  chan []byte
	out chan []byte
}

func newSwiftPipe() *swiftPipe {
	return &swiftPipe{
		in:  make(chan []byte, 1024),
		out: make(chan []byte, 1024),
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

	target := conn.LocalAddr().(*net.TCPAddr)
	host := target.IP.String()
	port := target.Port

	log.Printf("tun2socks intercepting TCP -> %s:%d", host, port)

	// Dial the local SOCKS5 proxy provided by whitenet
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", activeClient.socksPort), nil, proxy.Direct)
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

	// Bidirectional copy (two independent goroutines, non-blocking)
	go func() {
		defer conn.Close()
		defer remoteConn.Close()
		_, _ = io.Copy(remoteConn, conn) // Local -> Remote
	}()

	go func() {
		defer conn.Close()
		defer remoteConn.Close()
		_, _ = io.Copy(conn, remoteConn) // Remote -> Local
	}()
}

func (h *tunHandler) HandleUDP(conn adapter.UDPConn) {
	// Not implemented in WhiteNet originally either, just drop.
	conn.Close()
}

// StartVPN is the main entry point for the iOS TUN mode.
func StartVPN(yamlString string) (*Client, error) {
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

	clientID := cfg.Room.Channel
	if clientID == "" {
		clientID = fmt.Sprintf("ios-client-%d", time.Now().UnixNano())
	}

	log.Printf("StartVPN: starting whitenet with clientID=%s port=%d", clientID, port)

	if cfg.Auth.Provider == "dns" || cfg.Net.Transport == "dns" {
		// Launch MasterDnsVPN
		domain := ""
		if len(cfg.MasterDns.Domains) > 0 {
			domain = cfg.MasterDns.Domains[0]
		}
		
		jsonStr := fmt.Sprintf(`{
			"PROTOCOL_TYPE": "SOCKS5",
			"DOMAINS": ["%s"],
			"ENCRYPTION_KEY": "%s",
			"LISTEN_IP": "127.0.0.1",
			"LISTEN_PORT": %d
		}`, domain, cfg.Crypto.Key, port)

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
		go func() {
			err := app.Run(context.Background())
			if err != nil {
				log.Printf("MasterDnsVPN Error: %v", err)
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
	}

	log.Printf("StartVPN: SOCKS5 proxy ready on 127.0.0.1:%d", port)

	// Initialize the tun2socks stack
	initTUN()

	activeClient = &Client{socksPort: port}
	return activeClient, nil
}

