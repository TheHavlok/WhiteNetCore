// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package handlers

import (
	Enums "github.com/thehavlok/whitenet/masterdnsvpn/enums"
	VpnProto "github.com/thehavlok/whitenet/masterdnsvpn/vpnproto"
	"net"
)

func init() {
	RegisterHandler(Enums.PACKET_DNS_QUERY_REQ_ACK, handleDNSQueryAck)
	RegisterHandler(Enums.PACKET_DNS_QUERY_RES, handleDNSQueryRes)
}

func handleDNSQueryAck(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDNSQueryAck(packet)
}

func handleDNSQueryRes(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDNSQueryRes(packet)
}
