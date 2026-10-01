package node

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

const testSecret = "7b1f0c9d2e3a4b5c6d7e8f90a1b2c3d47b1f0c9d2e3a4b5c6d7e8f90a1b2c3d4"

// nonLoopbackIPv4 finds an address on this host that the exit's gVisor stack
// will route to. Without one there is nothing to proxy to, so the test has
// nothing to say.
func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	t.Skip("no routable IPv4 address on this host; the l4 exit cannot reach a loopback origin")
	return ""
}

// An exit and a client over the direct carrier must carry real TCP traffic
// end to end. This is the whole point of the port: the stack has to work as a
// library, not only behind upstream's main().
func TestExitAndClientCarryTraffic(t *testing.T) {
	// The l4 exit terminates traffic in a gVisor stack, which drops packets
	// addressed to loopback as martians - correctly, since a real exit must
	// not let a client reach its own 127.0.0.1. So the origin has to live on
	// a routable address on this host.
	hostIP := nonLoopbackIPv4(t)
	originLn, err := net.Listen("tcp", hostIP+":0")
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello through flux")
	}))
	origin.Listener = originLn
	origin.Start()
	defer origin.Close()

	carrierPort := freePort(t)
	socksPort := freePort(t)
	listen := fmt.Sprintf("127.0.0.1:%d", carrierPort)

	exitCfg := DefaultConfig()
	exitCfg.Exit = true
	exitCfg.Mode = "l4" // l3 needs root and Linux
	exitCfg.Secret = testSecret
	exitCfg.Context = "test-context"
	exitCfg.Carriers = []Carrier{{
		Type:   CarrierDirect,
		Params: map[string]string{"listen": listen},
	}}
	exit, err := Start(exitCfg)
	if err != nil {
		t.Fatalf("start exit: %v", err)
	}
	defer func() { _ = exit.Stop() }()

	clientCfg := DefaultConfig()
	clientCfg.Secret = testSecret
	clientCfg.Context = "test-context"
	clientCfg.SocksAddr = fmt.Sprintf("127.0.0.1:%d", socksPort)
	clientCfg.Carriers = []Carrier{{
		Type:   CarrierDirect,
		Params: map[string]string{"dial": listen},
	}}
	client, err := Start(clientCfg)
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer func() { _ = client.Stop() }()

	// The handshake needs a moment; poll rather than sleeping a fixed time.
	deadline := time.Now().Add(20 * time.Second)
	for !client.SessionActive() || !exit.SessionActive() {
		if time.Now().After(deadline) {
			t.Fatalf("session did not come up: client=%v exit=%v", client.SessionActive(), exit.SessionActive())
		}
		time.Sleep(100 * time.Millisecond)
	}

	proxyURL, parseErr := url.Parse("socks5://" + clientCfg.SocksAddr)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	httpClient := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	// The first request can race the tunnel's first packet; retry briefly.
	var body string
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(origin.URL)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		raw, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		body = string(raw)
		break
	}
	if body != "hello through flux" {
		t.Fatalf("body = %q (last error: %v)", body, lastErr)
	}

	stats := client.Stats()
	if stats.BytesSent == 0 || stats.BytesReceived == 0 {
		t.Errorf("client carried no bytes: %+v", stats)
	}
	if !stats.Connected {
		t.Error("client reports no connection after carrying traffic")
	}
}

func TestValidate(t *testing.T) {
	base := func() Config {
		cfg := DefaultConfig()
		cfg.Carriers = []Carrier{{Type: CarrierYandexDocs, URL: "https://docs.example/1"}}
		return cfg
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("a single carrier with a URL must validate: %v", err)
	}

	cases := map[string]func(*Config){
		"no carriers":         func(c *Config) { c.Carriers = nil },
		"unknown carrier":     func(c *Config) { c.Carriers[0].Type = "telepathy" },
		"carrier without url": func(c *Config) { c.Carriers[0].URL = "" },
		"duplicate names": func(c *Config) {
			c.Carriers = append(c.Carriers, Carrier{Type: CarrierYandexDocs, URL: "https://docs.example/2"})
			c.Secret = testSecret
		},
		"two carriers without a secret": func(c *Config) {
			c.Carriers = append(c.Carriers, Carrier{Name: "second", Type: CarrierMailruDocs, URL: "https://mail.example/1"})
		},
		"oneme without credentials": func(c *Config) {
			c.Carriers = []Carrier{{Type: CarrierOneMe}}
		},
		"direct client without dial": func(c *Config) {
			c.Carriers = []Carrier{{Type: CarrierDirect}}
		},
		"direct exit without listen": func(c *Config) {
			c.Exit = true
			c.Carriers = []Carrier{{Type: CarrierDirect}}
		},
		"bad exit mode": func(c *Config) {
			c.Exit = true
			c.Mode = "l9"
		},
		"bad inbound":      func(c *Config) { c.Inbound = "carrier pigeon" },
		"packet too big":   func(c *Config) { c.MaxPacketSize = 70000 },
		"packet too small": func(c *Config) { c.MaxPacketSize = 100 },
	}
	for name, mutate := range cases {
		cfg := base()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// Two carriers in one session need a secret, and with one they must validate:
// this is the configuration the panel generates for a multi-carrier channel.
func TestValidateMultiCarrierSession(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Secret = testSecret
	cfg.Carriers = []Carrier{
		{Name: "docs", Type: CarrierYandexDocs, URL: "https://docs.example/1", Priority: 50},
		{Name: "fast", Type: CarrierDirect, Priority: 100, Params: map[string]string{"dial": "1.2.3.4:443"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The KDF context must be derived the same way on both peers, or they derive
// different keys and the handshake silently never completes.
func TestContextDerivation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Carriers = []Carrier{
		{Type: CarrierYandexDocs, URL: "https://docs.example/low", Priority: 10},
		{Name: "high", Type: CarrierMailruDocs, URL: "https://mail.example/high", Priority: 90},
	}
	if got := cfg.context(); got != "https://mail.example/high" {
		t.Errorf("context = %q, want the highest-priority carrier's URL", got)
	}

	cfg.Context = "explicit"
	if got := cfg.context(); got != "explicit" {
		t.Errorf("context = %q, want the explicit value", got)
	}

	// Nothing to derive from: both peers must still agree, so it falls back
	// to the same placeholder upstream uses.
	bare := DefaultConfig()
	bare.Carriers = []Carrier{{Type: CarrierDirect, Params: map[string]string{"dial": "1.2.3.4:1"}}}
	if got := bare.context(); got != "http://#" {
		t.Errorf("context = %q, want the placeholder", got)
	}
}

func TestRunStopsWithContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Exit = true
	cfg.Mode = "l4"
	cfg.Carriers = []Carrier{{
		Type:   CarrierDirect,
		Params: map[string]string{"listen": fmt.Sprintf("127.0.0.1:%d", freePort(t))},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestCarriersListIsComplete(t *testing.T) {
	// Every carrier the factory handles must be listed, or the panel offers
	// a carrier nobody can start, or hides one that works.
	for _, name := range Carriers() {
		if !ValidCarrier(name) {
			t.Errorf("%s is listed but not valid", name)
		}
	}
	if ValidCarrier("nonsense") {
		t.Error("an unknown carrier validated")
	}
	if len(Carriers()) != 7 {
		t.Errorf("Carriers() has %d entries; update this test when a carrier is added: %v",
			len(Carriers()), strings.Join(Carriers(), ", "))
	}
}
