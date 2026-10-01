# WhiteNet panel — architecture

Three parts:

- **Main** (`cmd/wn-main`) — REST API, admin UI, subscriptions, the gRPC
  endpoint agents connect to, MariaDB.
- **Agent** (`cmd/wn-agent`) — one per VPN node. Supervises the cores, applies
  the desired state Main gives it, reports metrics and traffic.
- **Client** — the existing WhiteNetVPN app. Consumes the subscription JSON.

The agent always dials Main, never the other way round. A node therefore needs
no inbound firewall holes apart from its own VPN ports, and works behind NAT.

## Repository layout

```
api/proto/whitenet/node/v1/   Main <-> agent protocol (state.proto, node.proto)
cmd/wn-main/                  panel binary
cmd/wn-agent/                 node agent binary
internal/nodepb/              generated protobuf code (script/gen-proto.sh)
internal/panel/config/        Main configuration (TOML + WN_* environment)
internal/panel/secret/        AES-256-GCM box for every stored secret
internal/panel/store/         database handle, migrations, queries
internal/agentd/config/       agent configuration
internal/wnlog/               slog setup shared by both binaries
masterdnsvpn/                 the existing DNS tunnel, reused as a core
internal/xray/                the existing embedded xray-core (client side)
```

The panel lives in this repository so the agent can reuse `masterdnsvpn/`
directly rather than duplicating it or splitting it into its own module.

## The three cores on a node

Each runs as a separate supervised process, not linked into the agent. That
keeps "update the core" independent of "update the agent", keeps a panicking
core from taking the agent down with it, and avoids a single Go module having
to satisfy three different dependency trees at once.

| Core | Binary | What it serves | User model |
|---|---|---|---|
| xray-core | `xray` | VLESS+Reality, XHTTP, VMess, Trojan, Shadowsocks (incl. 2022), Hysteria2 | many users per inbound, live add/remove over gRPC |
| WhiteNet DNS tunnel | `whitenet` (this repo, `dns-server` mode) | VPN over DNS | none of its own — see below |
| OpenFlux | `openflux` | Yandex.Docs, Volga, Yandex Boards, MAX/OneMe, Cups.online, Mail.ru Docs, direct, phpbox | none — one client per channel |

### Hysteria2 needs no sing-box

Checked against the current Xray documentation and the pinned
`xtls/xray-core v1.260327.0` in `go.mod`: it ships `proxy/hysteria` and
`transport/internet/hysteria`. The inbound is `"protocol": "hysteria"` with
`"version": 2` plus `streamSettings.hysteriaSettings`, and users are an array
with an `auth` field. `shadowsocks_2022`, `splithttp` (XHTTP) and `reality`
are all present too, as are both API services the agent needs:
`app/proxyman/command` (HandlerService, for adding users without a restart)
and `app/stats/command` (StatsService, for traffic counters).

sing-box is therefore not installed. `Core` in the protocol is an enum, so
adding it later is additive.

### The DNS tunnel gets users by chaining into Xray

`masterdnsvpn` authenticates with one shared encryption key per server and has
no accounts, no per-user counters and no way to revoke one client. Rather than
forking its wire protocol, the node runs it in `PROTOCOL_TYPE=TCP` mode with
`FORWARD_IP/FORWARD_PORT` pointing at a local Xray inbound on the loopback
interface. Every tunnelled stream then lands on Xray, which supplies
authentication, live user add/remove and traffic statistics for free.

In the schema this is `node_inbounds.protocol = 'wndns'` with
`forward_to_tag` naming the Xray inbound it feeds. The target inbound is
marked `published = 0`, so it serves the tunnel without appearing in anyone's
subscription.

### OpenFlux is a pool of channels, not an inbound

OpenFlux is GPL-3.0 and a separate Go module;
`transport.Session` is "one logical session between a client and an exit
node", and the handshake envelope requires the two peers to hold opposite
roles. **One channel carries one client at a time.** A channel is therefore a
unit of capacity: a carrier rendezvous (a Yandex document, a MAX room, a
`direct` listen address) plus an AES-256-GCM key and KDF context.

Main leases a channel to a user for a bounded time and renews it while the
client keeps using it. `openflux_leases` enforces one live lease per channel in
the database: `active` is `1` while held and `NULL` once released, and
`UNIQUE (channel_id, active)` makes that a partial unique index, because NULLs
do not collide in a MariaDB unique index.

Per-user traffic accounting and limits are deliberately **not** applied to
OpenFlux: its exit terminates to the internet rather than forwarding to a
local inbound, so there is no per-user hook. Access is by node group only.

Two things to decide before the client work in stage 9:

1. **GPL-3.0.** Linking OpenFlux into the mobile apps makes the apps GPL-3,
   which does not sit well with App Store distribution. On the server it is a
   separate process, so only the usual source-offer obligation applies.
2. OpenFlux pins `pion/webrtc/v3` where this repository uses v4, and a
   different gVisor revision. Another reason it stays a separate binary.

## Desired state

Main owns the state; the agent only applies it.

1. Anything that affects a node bumps `nodes.config_version` and renders a new
   `NodeState` into `node_desired_state` (encrypted — it carries every user
   secret and Reality private key for that node).
2. The agent sends `Hello` with the version it has. Main replies with
   `HelloAck`, and pushes a `StateUpdate` only when the agent is behind.
3. The agent applies it and answers `StateApplied`, which writes
   `nodes.applied_version`. The two columns differing is exactly "this node is
   out of date".
4. A node that was offline for a week converges by applying the newest state
   it receives — applying a state is idempotent, so there is no replay of the
   intervening versions.
5. `UserDelta` is the fast path for adding and removing users without touching
   inbounds, which is what keeps Xray from restarting. It carries the version
   it produces, and a gap in that sequence makes the agent ask for a full
   state instead. It is an optimisation, never a second source of truth.
6. While Main is unreachable the agent keeps serving from `state.pb` on disk.

Xray restarts only when inbounds themselves change.

## Security

- Enrolment: the panel mints a one-time token (only its hash is stored). The
  install script passes it to `wn-agent enroll`, which generates a key pair
  locally, sends a CSR, and gets a client certificate back. The token is spent
  before the reply is sent. The private key never leaves the node.
- Everything after enrolment is mutual TLS against Main's own node CA, whose
  private key is stored encrypted in `ca_keys`.
- Every secret in the database is AES-256-GCM under one master key from the
  configuration: Reality private keys, user passwords, TOTP seeds, OpenFlux
  channel keys, the CA key, the rendered state. The master key is never
  stored in the database. Losing it loses those values.
- Admin login is argon2id plus TOTP, with a lockout counter on the row. The
  panel can be served on an unguessable path and on a different host name from
  the subscriptions.

## Traffic accounting

The agent reads Xray's StatsService and ships **deltas**, because Xray's own
counters reset when it restarts. Each report carries a `batch_id`;
`traffic_batches` has it as a primary key, so a retry after a dropped
connection is rejected rather than double counted. Main adds the delta to
`users.traffic_used` (the number limits are checked against) and to
`user_traffic_daily` (what the charts read).

## Schema

25 tables, `internal/panel/store/migrations/000001_init.up.sql`. Verified on
MariaDB 10.11 in both directions.

Conventions: `BIGINT` surrogate keys for joins plus a public `CHAR(36)` uuid
on anything that appears in a URL or a client config; `VARBINARY` for
ciphertext; `DATETIME(3)` in UTC; `JSON` for protocol-specific knobs so a new
Xray option is not a migration.

The migration runner is in `internal/panel/store/migrate.go` rather than
golang-migrate: the file naming is golang-migrate's, so its CLI still works on
the directory, but its module pulls Docker and a test harness into the build
graph for what is a version table and an ordered loop.

## Known deployment notes

- `systemd-resolved` holds `127.0.0.53:53` on a stock Ubuntu. A node serving
  the DNS tunnel on port 53 needs `DNSStubListener=no`; the stage 3 install
  script has to handle it.
- Building the React admin UI needs Node, so it is built in CI or on a
  workstation and embedded into the binary. The 1 GB test nodes cannot build
  it, and should not have to.
