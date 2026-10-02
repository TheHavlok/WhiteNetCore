// Package benchtest measures the DNS tunnel's throughput end to end on one
// machine: a real server and a real client, with UDP proxies standing in for
// the recursive resolvers in between, adding latency and loss.
//
// It is opt-in, because it takes tens of seconds and measures rather than
// asserts:
//
//	WN_DNS_BENCH=1 go test ./masterdnsvpn/benchtest -run TestDNSTunnelThroughput -v
//
// Knobs (environment):
//
//	WN_DNS_BENCH_DELAY_MS   one-way resolver latency, default 40 (80 ms RTT)
//	WN_DNS_BENCH_LOSS       packet loss per direction in percent, default 1
//	WN_DNS_BENCH_RESOLVERS  how many resolvers, default 4
//	WN_DNS_BENCH_BYTES      bytes to download, default 1 MiB
//	WN_DNS_BENCH_CLIENT     extra client config as JSON, merged over the base
//
// The client runs in TCP mode, which is how WhiteNet chains the tunnel into a
// local Xray inbound: every stream the client accepts is forwarded by the
// server to one fixed address, here a local server that streams bytes.
package benchtest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientpkg "github.com/thehavlok/whitenet/masterdnsvpn/client"
	"github.com/thehavlok/whitenet/masterdnsvpn/config"
	"github.com/thehavlok/whitenet/masterdnsvpn/logger"
	"github.com/thehavlok/whitenet/masterdnsvpn/security"
	"github.com/thehavlok/whitenet/masterdnsvpn/udpserver"
)

const benchDomain = "t.bench.test"

func envInt(t *testing.T, key string, def int) int {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s=%q: %v", key, raw, err)
	}
	return v
}

func freePort(t *testing.T, network, host string) int {
	t.Helper()
	switch network {
	case "udp":
		c, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	default:
		l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
}

func encodeJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// resolverProxy is a stand-in recursive resolver: it relays each query to the
// server and each answer back, after a delay and subject to loss.
type resolverProxy struct {
	conn     *net.UDPConn
	upstream *net.UDPAddr
	delay    time.Duration
	loss     float64

	mu      sync.Mutex
	clients map[string]*net.UDPConn // client address -> its upstream socket

	queries atomic.Int64
	dropped atomic.Int64
}

func startResolverProxy(t *testing.T, ctx context.Context, ip string, upstream *net.UDPAddr, delay time.Duration, loss float64) *resolverProxy {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip), Port: 53535})
	if err != nil {
		t.Fatalf("resolver proxy on %s: %v", ip, err)
	}
	p := &resolverProxy{conn: conn, upstream: upstream, delay: delay, loss: loss, clients: map[string]*net.UDPConn{}}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
		p.mu.Lock()
		for _, c := range p.clients {
			_ = c.Close()
		}
		p.mu.Unlock()
	}()
	go p.serve()
	return p
}

func (p *resolverProxy) lose() bool {
	return p.loss > 0 && rand.Float64() < p.loss
}

func (p *resolverProxy) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.queries.Add(1)
		if p.lose() {
			p.dropped.Add(1)
			continue
		}
		up, err := p.upstreamFor(from)
		if err != nil {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		time.AfterFunc(p.delay, func() { _, _ = up.Write(packet) })
	}
}

// upstreamFor gives every client socket its own socket towards the server,
// so answers find their way back to the right one.
func (p *resolverProxy) upstreamFor(client *net.UDPAddr) (*net.UDPConn, error) {
	key := client.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if up, ok := p.clients[key]; ok {
		return up, nil
	}
	up, err := net.DialUDP("udp", nil, p.upstream)
	if err != nil {
		return nil, err
	}
	p.clients[key] = up
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			if p.lose() {
				p.dropped.Add(1)
				continue
			}
			answer := append([]byte(nil), buf[:n]...)
			time.AfterFunc(p.delay, func() { _, _ = p.conn.WriteToUDP(answer, client) })
		}
	}()
	return up, nil
}

// startBulkServer is the far end: it streams size bytes to whoever connects.
func startBulkServer(t *testing.T, ctx context.Context, size int) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	chunk := make([]byte, 32*1024)
	rand.New(rand.NewSource(1)).Read(chunk) // incompressible, like TLS
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				left := size
				for left > 0 {
					n := min(left, len(chunk))
					if _, err := c.Write(chunk[:n]); err != nil {
						return
					}
					left -= n
				}
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestDNSTunnelThroughput(t *testing.T) {
	if os.Getenv("WN_DNS_BENCH") == "" {
		t.Skip("set WN_DNS_BENCH=1 to run the DNS tunnel throughput bench")
	}

	delay := time.Duration(envInt(t, "WN_DNS_BENCH_DELAY_MS", 40)) * time.Millisecond
	loss := float64(envInt(t, "WN_DNS_BENCH_LOSS", 1)) / 100
	resolvers := envInt(t, "WN_DNS_BENCH_RESOLVERS", 4)
	size := envInt(t, "WN_DNS_BENCH_BYTES", 1<<20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bulkPort := startBulkServer(t, ctx, size)

	// The server.
	dir := t.TempDir()
	serverPort := freePort(t, "udp", "127.0.0.1")
	serverCfg, err := config.LoadServerConfigFromJSONBase64(encodeJSON(t, map[string]any{
		"PROTOCOL_TYPE":       "TCP",
		"UDP_HOST":            "127.0.0.1",
		"UDP_PORT":            serverPort,
		"DOMAIN":              []string{benchDomain},
		"FORWARD_IP":          "127.0.0.1",
		"FORWARD_PORT":        bulkPort,
		"ENCRYPTION_KEY_FILE": filepath.Join(dir, "key.txt"),
		"LOG_LEVEL":           "ERROR",
	}))
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	keyInfo, err := security.EnsureServerEncryptionKey(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewCodecFromConfig(serverCfg, keyInfo.Key)
	if err != nil {
		t.Fatal(err)
	}
	srv := udpserver.New(serverCfg, logger.New("bench-server", "ERROR"), codec)
	go func() { _ = srv.Run(ctx) }()

	// The resolvers between them.
	upstream := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort}
	proxies := make([]*resolverProxy, 0, resolvers)
	resolverAddrs := make([]config.ResolverAddress, 0, resolvers)
	for i := 0; i < resolvers; i++ {
		ip := fmt.Sprintf("127.0.0.%d", 10+i)
		proxies = append(proxies, startResolverProxy(t, ctx, ip, upstream, delay, loss))
		resolverAddrs = append(resolverAddrs, config.ResolverAddress{IP: ip, Port: 53535})
	}

	// The client.
	listenPort := freePort(t, "tcp", "127.0.0.1")
	clientJSON := map[string]any{
		"PROTOCOL_TYPE":          "TCP",
		"DOMAINS":                []string{benchDomain},
		"ENCRYPTION_KEY":         keyInfo.Key,
		"DATA_ENCRYPTION_METHOD": serverCfg.DataEncryptionMethod,
		"LISTEN_IP":              "127.0.0.1",
		"LISTEN_PORT":            listenPort,
		"LOG_LEVEL":              "ERROR",
	}
	if extra := os.Getenv("WN_DNS_BENCH_CLIENT"); extra != "" {
		if err := json.Unmarshal([]byte(extra), &clientJSON); err != nil {
			t.Fatalf("WN_DNS_BENCH_CLIENT: %v", err)
		}
	}
	clientCfg, err := config.LoadClientConfigFromJSONBase64WithOverrides(encodeJSON(t, clientJSON), config.ClientConfigOverrides{})
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	clientCfg.Resolvers = resolverAddrs
	clientCfg.ResolverMap = map[string]int{}
	for i, r := range resolverAddrs {
		clientCfg.ResolverMap[r.IP] = i
	}
	app, err := clientpkg.BootstrapLoadedConfig(clientCfg, "")
	if err != nil {
		t.Fatalf("client bootstrap: %v", err)
	}
	go func() { _ = app.Run(ctx) }()

	// Wait for the tunnel: the first connection that yields a byte.
	deadline := time.Now().Add(60 * time.Second)
	var conn net.Conn
	for {
		if time.Now().After(deadline) {
			t.Fatal("the tunnel did not come up within 60s")
		}
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), time.Second)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			one := make([]byte, 1)
			if _, err := io.ReadFull(c, one); err == nil {
				conn = c
				break
			}
			_ = c.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	// The first byte also paid for session setup and the stream handshake;
	// measure the transfer that follows.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
	got, err := io.Copy(io.Discard, conn)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("download after %d bytes: %v", got, err)
	}
	got++ // the first byte
	if got != int64(size) {
		t.Fatalf("downloaded %d bytes, want %d", got, size)
	}

	var queries, dropped int64
	for _, p := range proxies {
		queries += p.queries.Load()
		dropped += p.dropped.Load()
	}
	kbps := float64(got) * 8 / elapsed.Seconds() / 1000
	t.Logf("RESULT download %d KiB in %v = %.1f kbit/s (%.1f KiB/s); RTT %v, loss %.1f%%, %d resolvers; %d queries through resolvers (%d dropped)",
		got/1024, elapsed.Round(time.Millisecond), kbps, float64(got)/1024/elapsed.Seconds(),
		2*delay, loss*100, resolvers, queries, dropped)
}
