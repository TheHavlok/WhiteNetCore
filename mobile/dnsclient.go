package mobile

// The DNS tunnel's client configuration, shared by StartVPN (iOS) and
// StartVPNAndroid. It used to be built twice, once in each, with the resolver
// list pasted into both.

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	masterdnsvpn_config "github.com/thehavlok/whitenet/masterdnsvpn/config"
)

// defaultDNSResolvers is where queries go when the profile names none.
//
// The tunnel can only be as reachable as the resolvers that carry it, and
// which ones answer differs by operator, region and day, most of all under
// mobile whitelists. So the list is wide on purpose: the client's MTU test at
// start-up drops every resolver that does not get through to the server, and
// the balancer spreads queries over those that remain.
//
// Only one entry per address: the client keys resolvers by address, so a
// second port on the same one would be dropped anyway.
var defaultDNSResolvers = []string{
	// Yandex DNS.
	"77.88.8.8",
	"77.88.8.1",
	"77.88.8.88",
	"77.88.8.2",
	"77.88.8.7",
	"77.88.8.3",
	// NSDI, the national domain name system's public resolvers. Reported to
	// keep answering when mobile internet is restricted to a whitelist.
	"195.208.4.1",
	"195.208.5.1",
	// MSK-IX public resolvers.
	"62.76.76.62",
	"62.76.62.76",
}

// dnsDownloadPollWindow is how many empty queries the tunnel keeps in flight
// while the server has data queued. Measured on masterdnsvpn/benchtest at a
// 200 ms resolver round trip with 1% loss: about 1.2 Mbit/s with none,
// 2.1 with 16 and 3.7 with 32. Polls are only spent while data is flowing.
const dnsDownloadPollWindow = 32

// dnsClientJSON is the tunnel library's configuration for a DNS profile.
func dnsClientJSON(cfg yamlConfig, port int) (string, error) {
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
		return "", fmt.Errorf("the DNS profile names no domain to tunnel through")
	}

	// The method is written only when the profile names one. Writing a
	// default here would change the method under every profile that
	// predates the field, and the two ends must agree on it.
	method := ""
	if cfg.MasterDns.Method != nil {
		method = fmt.Sprintf("\n\t\"DATA_ENCRYPTION_METHOD\": %d,", *cfg.MasterDns.Method)
	}

	return fmt.Sprintf(`{
	"PROTOCOL_TYPE": "SOCKS5",
	"DOMAINS": [%s],%s
	"ENCRYPTION_KEY": %s,
	"LISTEN_IP": "127.0.0.1",
	"LISTEN_PORT": %d,
	"MAX_DOWNLOAD_MTU": 2500,
	"RX_TX_WORKERS": 12,
	"TUNNEL_PROCESS_WORKERS": 4,
	"ARQ_WINDOW_SIZE": 1500,
	"PACKET_DUPLICATION_COUNT": 1,
	"DOWNLOAD_POLL_WINDOW": %d
}`, strings.Join(domains, ", "), method, strconv.Quote(cfg.Crypto.Key), port, dnsDownloadPollWindow), nil
}

// dnsResolvers is the profile's resolver list, or the default one when the
// profile names none or none of its entries parse.
func dnsResolvers(cfg yamlConfig) ([]masterdnsvpn_config.ResolverAddress, map[string]int) {
	if resolvers, ports := masterdnsvpn_config.ParseResolverList(cfg.MasterDns.Resolvers); len(resolvers) > 0 {
		return resolvers, ports
	}
	return masterdnsvpn_config.ParseResolverList(defaultDNSResolvers)
}

// dnsClientConfig is the loaded tunnel configuration for a DNS profile.
func dnsClientConfig(cfg yamlConfig, port int) (masterdnsvpn_config.ClientConfig, error) {
	raw, err := dnsClientJSON(cfg, port)
	if err != nil {
		return masterdnsvpn_config.ClientConfig{}, err
	}
	appCfg, err := masterdnsvpn_config.LoadClientConfigFromJSONBase64WithOverrides(
		base64.StdEncoding.EncodeToString([]byte(raw)), masterdnsvpn_config.ClientConfigOverrides{})
	if err != nil {
		return appCfg, fmt.Errorf("failed to load masterdnsvpn config: %w", err)
	}
	appCfg.Resolvers, appCfg.ResolverMap = dnsResolvers(cfg)
	return appCfg, nil
}
