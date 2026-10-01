package nodeca

import "net"

// parseIP is net.ParseIP, wrapped so the host-classifying logic above reads as
// one idea rather than mixing in the net package's name.
func parseIP(host string) net.IP { return net.ParseIP(host) }
