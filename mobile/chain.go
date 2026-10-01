package mobile

// Chained profiles: the DNS tunnel with a protocol spoken through it.
//
// The tunnel authenticates nobody - one shared key per server - so the panel
// chains it into a local inbound on the node, and the client has to do the
// matching thing. Both cores run at once: the tunnel offers a SOCKS proxy on
// its own port, Xray dials out through that and serves the device on the usual
// one.

import (
	"fmt"
	"log"

	"github.com/thehavlok/whitenet/internal/xray"
)

// encryptionMethod keeps the tunnel's method in range, defaulting to ChaCha20.
//
// A profile written before the method travelled in the subscription has a zero
// here, and zero means "no encryption" to the tunnel - which would be a silent
// downgrade, not a default.
func encryptionMethod(method int) int {
	if method <= 0 || method > 5 {
		return 2
	}
	return method
}

// StartChained brings up a profile that needs two cores: outerConfig is the
// tunnel's YAML, innerConfig the Xray configuration that dials out through it.
//
// The device's traffic goes to Xray, which is the half that authenticates, so
// the packet stack is pointed there once both are up. Any failure stops
// everything rather than leaving a bare tunnel running, since a bare tunnel
// carries traffic that nothing has authenticated.
func StartChained(outerConfig, innerConfig string) (*Client, error) {
	return startChained(outerConfig, innerConfig, StartVPN, func(port int) *Client {
		activeClient = &Client{socksPort: port}
		return activeClient
	})
}

// StartChainedAndroid is StartChained for the Android VpnService, which keeps
// its own active client - the same split the rest of this package uses.
func StartChainedAndroid(outerConfig, innerConfig string) (*Client, error) {
	return startChained(outerConfig, innerConfig, StartVPNAndroid, func(port int) *Client {
		activeClientAndroid = &Client{socksPort: port}
		return activeClientAndroid
	})
}

func startChained(
	outerConfig, innerConfig string,
	startTunnel func(string) (*Client, error),
	pointPacketStackAt func(int) *Client,
) (*Client, error) {
	if outerConfig == "" || innerConfig == "" {
		return nil, fmt.Errorf("a chained profile needs both halves")
	}

	tunnel, err := startTunnel(outerConfig)
	if err != nil {
		return nil, fmt.Errorf("the tunnel did not come up: %w", err)
	}
	log.Printf("StartChained: tunnel ready, SOCKS5 on 127.0.0.1:%d", tunnel.socksPort)

	// Deliberately not startXrayCore: that stops whatever is running first,
	// which here would be the tunnel this config has to dial through.
	waitForPortFree(xraySocksPort, portFreeTimeout)
	if err := xray.Start(innerConfig, xraySocksPort); err != nil {
		Stop()
		return nil, fmt.Errorf("the inner protocol did not start: %w", err)
	}
	if err := waitForSocks(xraySocksPort, xrayReadyTimeout); err != nil {
		Stop()
		return nil, fmt.Errorf("the inner protocol never became ready: %w", err)
	}

	log.Printf("StartChained: ready, device traffic goes to 127.0.0.1:%d through the tunnel", xraySocksPort)
	return pointPacketStackAt(xraySocksPort), nil
}
