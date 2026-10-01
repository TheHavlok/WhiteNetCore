# Protocols: setting them up and connecting

Every protocol is configured in the same two places:

* **Nodes → _a node_ → Inbounds & DNS tunnel** - everything that listens on a
  port, including the DNS tunnel.
* **Nodes → _a node_ → OpenFlux channels** - flux, which has channels instead
  of a port.

And every protocol comes out the same way. Give a user a **subscription link**
(Users → _a user_ → Subscription) and the app gets all of their servers and
keeps them up to date. To try one server by itself, or hand one to one person,
use the **per-server `whitenet://` link** on the same page: it carries that one
server's credentials and nothing else. [LINKS.md](LINKS.md) describes both
formats, [SUBSCRIPTION.md](SUBSCRIPTION.md) the JSON the app consumes.

An inbound on several nodes at once is a **template**: Inbounds → Add template,
then pick the nodes or a group. A node can also override a template's port, SNI
or dest for itself, which is what the fields on the node's own inbound are for.

Users are added to and removed from a running node **without restarting Xray** -
the agent uses the Xray gRPC HandlerService. Only a change to the inbounds
themselves restarts the core, and the panel says so when it does.

## Keys and passwords

Never type these by hand. Every field that takes a generated value has a
button next to it:

| Button | Gives |
| --- | --- |
| Reality keys | an x25519 private/public pair; the private half is stored encrypted and never leaves the panel |
| shortId | an 8-byte hex id |
| UUID | a v4 UUID for VLESS and VMess |
| Password | a long random password for Trojan and Hysteria2 |
| Shadowsocks key | a key of exactly the length the chosen method needs, base64 for the 2022 methods |
| Flux secret | a 32-byte channel secret, hex |

Secrets are stored encrypted with the master key, so a database dump without
that key does not hand over your Reality private keys.

## VLESS + REALITY

The default, and what to use unless you have a reason not to.

1. **Add inbound** → protocol **VLESS**, transport **raw**, security
   **reality**.
2. Port **443**. REALITY is only convincing on the port the site it borrows
   would use.
3. **Dest** and **Server names**: a real TLS site that is reachable from the
   node, close to it, and that is not itself blocked where your users are -
   `www.microsoft.com:443` is a safe default.
4. Press **Reality keys** and **shortId**.
5. Flow `xtls-rprx-vision`, fingerprint `chrome`.

The client needs `uuid`, `flow`, `sni`, `pbk`, `sid`, `fp` - the subscription
fills all of them in. A wrong `sni` or `pbk` fails as a TLS error with no
explanation, which is the point of the protocol; the per-server link is how to
avoid transcribing them.

## VLESS + XHTTP

For a node behind a CDN, or where a long-lived connection is what gets noticed.

1. Protocol **VLESS**, transport **xhttp**, security **tls** (or **reality**).
2. **Path** something unremarkable, e.g. `/wn`.
3. **Mode**: `auto` unless you know otherwise. `packet-up` survives a CDN that
   buffers; `stream-one` is the cheapest when nothing is in the way.
4. Behind a CDN, **Host** is the CDN host name and the TLS **SNI** matches it.

## VMess, Trojan, Shadowsocks

* **VMess** - `uuid` plus `security` (`auto` is right). Present for clients that
  only speak it; VLESS is better on every axis.
* **Trojan** - a password and TLS. Needs a real certificate or REALITY; plain
  TLS with a self-signed certificate is recognisable at a glance.
* **Shadowsocks** - method and password. The panel only offers methods this
  Xray build supports, and marks which can serve several users: a single-user
  method on a shared node means every user shares one password, so the panel
  builds Shadowsocks inbounds multi-user and derives a placeholder key.
* **Shadowsocks 2022** - `2022-blake3-*`. Prefer these: they are what
  Shadowsocks should always have been, and the key length is fixed per method,
  which is why the generate button exists.

## Hysteria2

Native to this Xray build - **no sing-box is involved**, which is worth stating
because the usual advice is that it is needed.

1. Protocol **Hysteria2**. Transport and security are fixed (`hysteria`, `tls`).
2. A port of its own, UDP. It must be open in the node's firewall; this is the
   one protocol that does not ride TCP.
3. Password, and TLS: a real certificate for the node's name.
4. Bandwidth: `up` and `down` in the form `100 mbps`. Hysteria uses these as a
   congestion-control hint, so numbers close to the node's real capacity make
   it behave; wildly high ones make it worse, not faster.

Obfuscation is configured as a **`finalmask` mask of type `salamander`**, which
is where this Xray version keeps it - there is no `obfs` block any more. The
subscription hands the client `obfs: salamander` and `obfs_password`, which is
the same thing in the form the client expects.

## The DNS tunnel (wndns)

VPN over DNS. Slow, and it works where everything else is blocked - a captive
portal that resolves names before you pay, a network that permits nothing but
port 53.

The tunnel has **no accounts of its own**: a single shared key per server lets
anyone who has it in. So the panel gives it a user model by chaining it:

```
client ──DNS queries──▶ wndns on :53 ──TCP──▶ 127.0.0.1:21080 (VLESS, local)
                                                   └─ this is what authenticates the user
```

The agent enforces that the forward target is on loopback, so the tunnel can
never be pointed at something off the node.

To set it up:

1. Create the inner inbound first: **Add inbound** → VLESS, transport raw,
   security none, listen address `127.0.0.1`, port e.g. `21080`, and clear
   **Published**. An unpublished inbound never appears in a subscription on its
   own - it exists only to be chained into.
2. **Add inbound** → protocol **WhiteNet DNS tunnel**, port **53**,
   **Forward to** the inbound from step 1.
3. **Domains**: one or more names whose NS records point at this node. This is
   the part that is not in the panel - the delegation has to exist in your DNS
   zone:

   ```
   t1.tun.example.   IN NS   node2.example.
   t2.tun.example.   IN NS   node2.example.
   ```

   More than one name is worth having: a resolver that rate-limits one still
   leaves the others.
4. **Encryption**: method and key. The button generates a key of the right
   length - 16 bytes for AES-128, 24 for AES-192, 32 for ChaCha20 and
   AES-256 - and the tunnel refuses a key of any other length rather than
   padding it.

The client gets `domains`, `encryption_method` and `encryption_key`, plus
`chain` with the inner protocol's credentials. It brings the tunnel up, then
speaks the chained protocol through it. Both halves are in one `whitenet://`
link.

Expect a few hundred kbit/s. It is an escape hatch, not a daily driver.

## Flux

The ported OpenFlux stack. Traffic rides an ordinary web service - a Yandex
document, a Mail.ru document, a Cups.online room, a MAX data channel - so there
is no VPN-shaped connection to see, and no port of yours to block.

**Flux has no traffic accounting and no limits.** Access is by node group
alone: a user in a group that has a flux-enabled node can use it, and nothing
is metered. This is deliberate - the carriers give no reliable per-user byte
counts - and it is why a flux-only user's traffic figures stay at zero.

### Turning it on

**Nodes → _a node_ → OpenFlux channels**:

1. **Enabled**, and a **mode**:
   * **l4** (gVisor) - a userspace network stack. No kernel configuration, no
     privileges, works anywhere. Start here.
   * **l3** (raw sockets, Linux) - faster, and needs one firewall rule, below.
2. Add **channels**. Each channel is one rendezvous: a carrier plus a secret.
   The secret is generated for you.

### One channel, one client

A flux channel carries **exactly one client at a time**. That is a property of
the carriers, not a limit the panel invented.

So channels are a **pool with leases**: the app asks the subscription for a
free channel when it connects, renews while it uses it, and releases it when it
disconnects. A lease that is not renewed lapses, so a client that vanished
frees its channel instead of holding it forever.

**This means the number of channels is the number of simultaneous flux users on
that node.** Three channels, three clients. The panel shows which channels are
leased; if users are being refused, add channels.

A channel can also be dedicated to one user, in which case the credentials
travel in the link instead of being leased.

### Carriers

| Carrier | Needs | Notes |
| --- | --- | --- |
| **Direct** | a listen address | Plain TCP. Fast, and an ordinary port - no cover at all. Useful for testing, and as a fallback when nothing else is blocked. |
| **Yandex.Docs** | a document URL | A WebSocket to a Yandex document. |
| **Yandex Volga** | URL + `cookies.txt` | Needs a Netscape cookie file for a signed-in Yandex account. |
| **Yandex Boards** | a board URL | |
| **Mail.ru Docs** | a document URL | |
| **Cups.online** | a room URL | A Centrifugo room. Only the exit creates rooms. |
| **MAX / OneMe** | token + uid | A WebRTC data channel. The token belongs to the exit's own MAX account, so this carrier is **never put in a share link** - it would hand out that account. |

Several carriers in one channel is failover: the client tries them by priority
and moves on when one is blocked. Mixing a cover carrier with `direct` gives
you "use the quiet path, fall back to the fast one".

### The l3 firewall rule

`l3` sends traffic from the host's own address with SNAT, so the kernel sees
return packets for connections it never opened and answers them with RST -
which tears down the tunnel's flows. The rule has to exist outside the agent:

```bash
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <local_ip> -j DROP
```

Set **local_ip** to a dedicated alias address on the node and scope the rule to
it. Without one, the only version of this rule drops *every* outbound RST on
the host, which affects everything else running there. If that trade is not
acceptable, use **l4**: it needs no rule at all.

The panel returns this warning when you save an l3 configuration, and the agent
logs it on start, so it is not something you have to remember.

## When something does not connect

In this order, because each step rules out the one below:

1. **Nodes** - is the node online? An offline node is left out of subscriptions
   entirely, so "my server disappeared" is usually this.
2. **Journal** - the node's events: core restarts, failed state applies, the
   reason a node went degraded.
3. **Nodes → _a node_ → Logs** - the core's own log, fetched through the agent.
   A REALITY handshake failing against a dead `dest` shows up here and nowhere
   else.
4. **Users → _a user_** - status. `expired` or `limited` means the subscription
   is served with an empty server list on purpose, and the app says why.
5. **Devices** - past the device limit, a new device is refused with
   `device_limit`. Delete a device to free the slot.
6. The per-server link - paste it into the app directly. If that connects and
   the subscription does not, the problem is the subscription (groups, online
   state, publication), not the protocol.
