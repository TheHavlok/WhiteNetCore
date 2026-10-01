package mobile

// Measuring how far away a server is, so the app can pick the closest one.
//
// Each protocol is measured by the thing it actually depends on, because a
// single probe would be wrong for most of them: a TCP handshake says nothing
// about a UDP-only server, and a flux server has no address to probe at all.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// Latency is one measurement.
type Latency struct {
	// OK is false when the server could not be measured. That is not the same
	// as "far away", so an app must not sort an unmeasured server as slow -
	// Milliseconds is -1 to make that mistake hard.
	OK bool
	// Milliseconds is the round trip, or -1 when OK is false.
	Milliseconds int64
	// Method says what was measured: "tcp", "dns" or "none".
	Method string
	// Message explains a failure, for the log rather than the user.
	Message string
}

// MeasureLatency probes one server. serverJSON is Server.RawJSON().
//
// timeoutMillis bounds the whole measurement; 0 means a sensible default.
// Measuring is deliberately cheap - a handshake, not a tunnel - so an app can
// do it for every server each time it connects.
func MeasureLatency(serverJSON string, timeoutMillis int) *Latency {
	var server subscription.Server
	if err := json.Unmarshal([]byte(serverJSON), &server); err != nil {
		return &Latency{Milliseconds: -1, Method: "none", Message: "that server cannot be read"}
	}
	if timeoutMillis <= 0 {
		timeoutMillis = 3000
	}
	timeout := time.Duration(timeoutMillis) * time.Millisecond

	switch server.Protocol {
	case subscription.ProtocolFlux:
		// A flux server is reached through a carrier, so there is nothing to
		// probe: whatever we measured would be the carrier's web service, not
		// the exit.
		return &Latency{Milliseconds: -1, Method: "none",
			Message: "flux has no address to probe"}

	case subscription.ProtocolWNDNS:
		// The tunnel's speed is the resolver path's speed, so that is what is
		// measured: one query for a name under the tunnel's own domain.
		domains := splitCSV(server.Params["domains"])
		if len(domains) == 0 {
			return &Latency{Milliseconds: -1, Method: "none", Message: "no domain to query"}
		}
		return measureDNS(domains[0], timeout)

	case subscription.ProtocolHysteria2:
		// Hysteria is UDP only, and a UDP "dial" measures nothing but local
		// resolution - reporting that as a round trip would make every
		// Hysteria server look like the fastest one and win every automatic
		// choice. Probing it properly means speaking the protocol, so it is
		// reported as unmeasured instead.
		return &Latency{Milliseconds: -1, Method: "none",
			Message: "UDP cannot be probed without speaking the protocol"}

	default:
		return measureTCP(server.Address, server.Port, timeout)
	}
}

func measureTCP(host string, port int, timeout time.Duration) *Latency {
	if host == "" || port <= 0 {
		return &Latency{Milliseconds: -1, Method: "tcp", Message: "no address"}
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Three attempts, best of: a phone's first packet after a radio idle
	// period is routinely hundreds of milliseconds slower than the next, and
	// sorting servers by that noise picks the wrong one.
	best := int64(-1)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		elapsed := time.Since(start).Milliseconds()
		_ = conn.Close()
		if elapsed < 0 {
			elapsed = 0
		}
		if best < 0 || elapsed < best {
			best = elapsed
		}
	}
	if best < 0 {
		return &Latency{Milliseconds: -1, Method: "tcp", Message: errorText(lastErr)}
	}
	return &Latency{OK: true, Milliseconds: best, Method: "tcp"}
}

func measureDNS(domain string, timeout time.Duration) *Latency {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// A random label, so a resolver's cache does not answer instantly and
	// make every tunnel look equally fast. The name does not have to exist:
	// an NXDOMAIN travels the same path as an answer.
	name := fmt.Sprintf("wn%d.%s", rand.Int63(), domain)

	resolver := &net.Resolver{}
	start := time.Now()
	_, err := resolver.LookupHost(ctx, name)
	elapsed := time.Since(start).Milliseconds()

	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return &Latency{OK: true, Milliseconds: elapsed, Method: "dns"}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		// The expected outcome: the query reached the tunnel's authority and
		// came back.
		return &Latency{OK: true, Milliseconds: elapsed, Method: "dns"}
	default:
		return &Latency{Milliseconds: -1, Method: "dns", Message: errorText(err)}
	}
}

func errorText(err error) string {
	if err == nil {
		return "unreachable"
	}
	return err.Error()
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
