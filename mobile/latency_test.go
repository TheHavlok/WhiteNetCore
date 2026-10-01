package mobile

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

func measure(t *testing.T, server subscription.Server) *Latency {
	t.Helper()
	raw, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	return MeasureLatency(string(raw), 1500)
}

func TestTCPServerIsMeasured(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	result := measure(t, subscription.Server{
		Protocol: "vless", Transport: "reality",
		Address: "127.0.0.1", Port: addr.Port,
	})
	if !result.OK || result.Method != "tcp" || result.Milliseconds < 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestADeadServerIsNotFastButUnmeasured(t *testing.T) {
	// A closed port must come back as unmeasured, not as a very low number:
	// sorting by the figure would otherwise pick the dead server first.
	result := measure(t, subscription.Server{
		Protocol: "vless", Address: "127.0.0.1", Port: 1,
	})
	if result.OK || result.Milliseconds != -1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestFluxAndHysteriaAreReportedUnmeasured(t *testing.T) {
	flux := measure(t, subscription.Server{
		Protocol: "flux", Flux: &subscription.Flux{Mode: "l4", Lease: "https://x/lease/t"},
	})
	if flux.OK || flux.Method != "none" || flux.Milliseconds != -1 {
		t.Fatalf("flux = %+v", flux)
	}

	// Hysteria is UDP only: a UDP dial measures local resolution, and
	// reporting that as a round trip would make it win every automatic
	// choice.
	hysteria := measure(t, subscription.Server{
		Protocol: "hysteria2", Transport: "hysteria", Address: "198.51.100.1", Port: 8443,
	})
	if hysteria.OK || hysteria.Milliseconds != -1 {
		t.Fatalf("hysteria = %+v", hysteria)
	}
}

func TestUnreadableServerIsRefused(t *testing.T) {
	if result := MeasureLatency("{not json", 100); result.OK {
		t.Fatalf("result = %+v", result)
	}
}

func TestDNSServerWithoutADomainIsUnmeasured(t *testing.T) {
	result := measure(t, subscription.Server{
		Protocol: "wndns", Transport: "dns", Address: "198.51.100.2", Port: 53,
		Params: map[string]string{},
	})
	if result.OK || result.Milliseconds != -1 {
		t.Fatalf("result = %+v", result)
	}
}
