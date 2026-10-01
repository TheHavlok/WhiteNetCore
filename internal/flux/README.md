# internal/flux — ported from OpenFlux

This tree is the OpenFlux network stack, ported into WhiteNetCore so the node
agent and the client can speak its transports natively instead of shelling out
to a third-party binary.

## Provenance

Upstream: <https://github.com/p1neappleXpress/OpenFlux>, by
[@p1neappleXpress](https://github.com/p1neappleXpress) and contributors (see
`COPYRIGHT.upstream` and `NOTICE.upstream`).

**Licence: GNU GPL v3** (`LICENSE` in this directory). The rest of WhiteNetCore
is WTFPL, which is GPL-compatible, so combining them is allowed — but the
combined work must be distributed under the GPL-3. That matters most for the
mobile apps: shipping a GPL-3 binary through the App Store is a known conflict
with Apple's terms. Two ways out when it comes to that: keep the OpenFlux
transports out of the store builds (a build tag already makes this easy), or
ask upstream for a licence exception.

## What changed from upstream

- Import paths: `github.com/p1neappleXpress/OpenFlux/...` →
  `github.com/thehavlok/whitenet/internal/flux/...`.
- `pion/webrtc/v3` → `v4`, to match the rest of this repository. Only the
  `oneme` carrier uses WebRTC, and the API surface it touches is unchanged.
- Nothing else. The wire protocol is byte-for-byte upstream's, so a WhiteNet
  node interoperates with an upstream OpenFlux client and vice versa. The
  upstream test suite is included and passes unmodified; keeping it that way
  is how that compatibility stays honest.

`PROTOCOL_NEGOTIATION.md` is upstream's description of the authenticated
session, kept here because it is the normative description of the handshake.

## Layout

| Package | What it does |
|---|---|
| `transport/` | the carrier interface, the batched+zstd codec, AES-256-GCM records, framing, port and frame demultiplexing, cookie jars, and `Session` — one logical client↔exit session |
| `transport/control/` | the control-plane messages inside a session |
| `transport/manager/` | several carriers in one session, with priorities and failover |
| `transport/yandex/` | Yandex.Docs (`yandex`), Volga (`vyandex`), Yandex Boards (`boards`) |
| `transport/mailru/` | Mail.ru Docs |
| `transport/oneme/` | MAX/OneMe, over a WebRTC data channel |
| `transport/cupsonline/` | Cups.online Centrifugo rooms |
| `transport/phpbox/` | a PHP node on ordinary web hosting, no server of our own |
| `transport/ipc/` | the socket an app uses for captcha and cookie handoff |
| `tunnel/` | the client tunnel, the virtual NIC, exit dispatchers |
| `tunnel/l3/` | the Linux raw-socket exit: SNAT/DNAT, conntrack, ICMP |
| `socks5/` | SOCKS5 server, for the client's local inbound |
| `share/` | share-link encoding (upstream `openflux://`; WhiteNet wraps this in `whitenet://`) |
| `netbind`, `network`, `utils`, `streamproxy` | supporting pieces |

## Carriers

| Name | Carrier | Needs |
|---|---|---|
| `direct` | plain TCP | a reachable address and port |
| `yandex` | Yandex.Docs over WebSocket | a document URL |
| `vyandex` | Yandex Volga, HTTP relay + WebSocket | a document URL and a Netscape `cookies.txt` with a Yandex login |
| `boards` | Yandex Boards over WebSocket | a board URL |
| `oneme` | MAX/OneMe WebRTC data channel | a MAX token and user id |
| `cupsonline` | Cups.online Centrifugo rooms | a room URL |
| `mailru` | Mail.ru Docs over WebSocket | a document URL |
| `phpbox` | a PHP script on any web hosting | the script's URL |

## Exit modes

- `l3` — Linux only, needs root or `CAP_NET_RAW`. Raw IPv4 with its own
  conntrack and NAT, no userspace TCP stack. The fast path.
- `l4` — portable, no root. Terminates TCP/UDP in a userspace gVisor stack and
  dials the real server. Slower, because traffic is terminated twice.
