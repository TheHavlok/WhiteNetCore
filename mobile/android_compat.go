package mobile

import (
	"context"
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

	"github.com/thehavlok/whitenet/internal/protect"
)

var (
	tunOnceAndroid      sync.Once
	activeClientAndroid *Client
	pipeAndroid         *androidPipeStruct
)

type androidPipeStruct struct {
	in  chan []byte
	out chan []byte
}

func newAndroidPipe() *androidPipeStruct {
	return &androidPipeStruct{
		in:  make(chan []byte, 1024),
		out: make(chan []byte, 1024),
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

	target := conn.LocalAddr().(*net.TCPAddr)
	host := target.IP.String()
	port := target.Port

	log.Printf("tun2socks intercepting TCP -> %s:%d", host, port)

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

	go func() {
		defer conn.Close()
		defer remoteConn.Close()
		_, _ = io.Copy(remoteConn, conn)
	}()

	go func() {
		defer conn.Close()
		defer remoteConn.Close()
		_, _ = io.Copy(conn, remoteConn)
	}()
}

func (h *tunHandlerAndroid) HandleUDP(conn adapter.UDPConn) {
	target := conn.LocalAddr().(*net.UDPAddr)
	
	// Only proxy DNS (port 53) to the real network to resolve domains.
	// WhiteNet WebRTC tunnel does not support UDP relay.
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

		go func() {
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
}

// StartVPNAndroid is the dedicated entry point for Android.
func StartVPNAndroid(yamlString string) (*Client, error) {
	var cfg yamlConfig
	if err := yaml.Unmarshal([]byte(yamlString), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

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

	clientID := cfg.Room.Channel
	if clientID == "" {
		clientID = fmt.Sprintf("android-client-%d", time.Now().UnixNano())
	}

	log.Printf("StartVPNAndroid: starting whitenet with clientID=%s port=%d", clientID, port)

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
	
	// Wait up to 120s to ensure even very slow handshakes succeed on Android
	log.Println("StartVPNAndroid: waiting for SOCKS5 proxy to become ready...")
	if err := WaitReady(120000); err != nil {
		log.Printf("StartVPNAndroid: WaitReady failed: %v", err)
		Stop() // clean up
		return nil, fmt.Errorf("whitenet not ready: %w", err)
	}

	log.Printf("StartVPNAndroid: SOCKS5 proxy ready on 127.0.0.1:%d", port)

	initTUNAndroid()

	activeClientAndroid = &Client{socksPort: port}
	return activeClientAndroid, nil
}
