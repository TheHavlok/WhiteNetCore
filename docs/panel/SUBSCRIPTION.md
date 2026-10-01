# The subscription format

What the app fetches, and the rules the panel follows when it answers. The Go
definitions are in [`internal/panel/subscription/schema.go`](../../internal/panel/subscription/schema.go);
this document is the contract around them.

No v2ray links, no Clash. The app is ours, so the format says exactly what it
needs and nothing else.

## One URL, two answers

```
https://sub.example.com/sub/<token>
```

| Caller | Gets |
| --- | --- |
| a browser | the branded subscription page: logo, days left, traffic, QR code, "Open in WhiteNetVPN", install steps |
| the app | the JSON below |

The panel decides by three signals, in order of how much they prove:

1. the `X-HWID` header, which the app always sends;
2. `Accept: application/json` without `text/html`;
3. a user agent mentioning `whitenet`, `okhttp`, `cfnetwork`, `dart` or
   `go-http-client`.

`/sub/<token>/json` forces the JSON and `/sub/<token>/qr.png` is the QR code,
both for when you need one specifically.

## Headers the app sends

| Header | Used for |
| --- | --- |
| `X-HWID` | the device limit. This is what the ledger counts, so it has to be stable for the life of the install |
| `X-Device-Model` | the admin's device list only |
| `X-Platform` | the same |
| `X-App-Version` | the same |

Without `X-HWID` the request is anonymous: it is served, but it neither
registers a device nor counts against the limit. With one past the limit the
answer is `403` and

```json
{"error": {"code": "device_limit", "message": "this account allows 3 devices"}}
```

Devices are listed per user in the panel and can be deleted there, which frees
the slot immediately.

## The document

```json
{
  "version": 1,
  "issued_at": "2026-10-01T18:22:04Z",
  "update_interval_hours": 12,
  "user": {
    "uuid": "4f1c9e0a-7b2d-4e8a-9c31-5a6b7c8d9e0f",
    "name": "pat",
    "expires_at": "2026-12-31T23:59:59Z",
    "traffic_used": 4294967296,
    "traffic_limit": 107374182400,
    "devices_limit": 3,
    "devices_used": 2,
    "status": "active"
  },
  "servers": [ /* see below */ ],
  "branding": {
    "app_name": "WhiteNetVPN",
    "logo_url": "https://cdn.example.com/logo.svg",
    "support_url": "https://t.me/whitenet",
    "accent_color": "#3b82f6",
    "message": ""
  }
}
```

`expires_at` is `null` for an account that never expires, and a `traffic_limit`
or `devices_limit` of `0` means unlimited. `status` is `active`, `disabled`,
`expired` or `limited`.

**A blocked user still gets a document**, with an empty `servers` and a status
saying why. That is deliberate: the app can tell the user "your traffic ran
out" instead of showing a network error, and it stops an expired account from
looking like an outage.

`update_interval_hours` comes from the panel's settings, so the refresh rate can
be changed without an app update.

### Which servers appear

A server is in the list when all of these hold:

* the node is in a group the user is assigned to;
* the inbound is enabled and published (`published = 0` inbounds, such as the
  local one the DNS tunnel forwards into, never appear on their own);
* the node is online - unless **Settings → Include nodes that are offline** is
  on. Off by default: handing a client a dead server is worse than handing it
  one fewer.

Rendered documents are cached for **Settings → Cache, seconds**, so a fleet of
phones refreshing at once is not a query storm, and the endpoint is rate
limited per client address, which is what stops the token space being walked.

### A server object

```json
{
  "id": "4f1c9e0a-7b2d-4e8a-9c31-5a6b7c8d9e0f:vless-reality-443",
  "name": "🇩🇪 Germany 1",
  "country": "DE",
  "group": "Europe",
  "protocol": "vless",
  "transport": "reality",
  "address": "185.68.184.144",
  "port": 443,
  "sort": 10,
  "params": {
    "uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
    "flow": "xtls-rprx-vision",
    "sni": "www.microsoft.com",
    "pbk": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
    "sid": "6ba85179e30d4fc2",
    "fp": "chrome"
  }
}
```

`id` is `<node-uuid>:<inbound-tag>` and is stable across fetches, so the app can
remember a preferred server and keep per-server statistics. `params` is flat
strings throughout; the keys per protocol and per transport are tabulated in
[LINKS.md](LINKS.md#fields-per-protocol).

Two protocols carry more than `params`:

* **`wndns`** adds `chain`, the Xray inbound the DNS tunnel forwards into. The
  app brings up the tunnel, then speaks `chain.protocol` through it. `chain`
  has no address on purpose: the app dials whatever local endpoint its own
  tunnel exposes.
* **`flux`** adds `flux`, and has no `address` or `port` at all - it reaches
  its exit through a carrier rather than an address.

## Flux leases

A flux channel carries one client at a time, so a subscription normally hands
the app a lease endpoint instead of a channel:

```json
{
  "protocol": "flux",
  "transport": "yandex",
  "flux": { "mode": "l4", "lease": "https://sub.example.com/lease/<token>" }
}
```

```
POST /lease/<token>                      -> LeaseResponse
POST /lease/<token>/<leaseID>/renew      -> LeaseResponse
POST /lease/<token>/<leaseID>/release    -> 204
```

```json
{
  "channel": {
    "id": "ch-7",
    "secret": "7b1f0c9d…",
    "context": "https://cups.online/room/ab12cd",
    "carriers": [{ "type": "yandex", "url": "https://…", "priority": 50 }]
  },
  "expires_at": "2026-10-01T18:27:04Z",
  "renew_url": "https://sub.example.com/lease/<token>/9/renew",
  "release_url": "https://sub.example.com/lease/<token>/9/release"
}
```

Renew at about half the remaining time, and release on disconnect so the
channel does not sit idle until the lease lapses. Asking again while you hold a
lease returns the same channel, so a retry does not burn two of them.

Flux has no traffic accounting and no limits by design - access is by node
group alone. See [PROTOCOLS.md](PROTOCOLS.md#flux).

## Compatibility rules

These are what let an old app keep working:

* `version` is bumped only for a change an old client cannot ignore. A client
  seeing a higher number should tell the user to update rather than guess.
* New fields are added as optional, and optional in meaning as well as in
  encoding.
* **A client must skip a server whose `protocol` or `transport` it does not
  recognise**, rather than failing the whole subscription. This is the rule
  that lets a new protocol be rolled out to nodes before every app has caught
  up.

## Reissuing

**Users → … → Reissue subscription token** mints a new token and the old URL
stops working at once, answering `404`. The answer for an unknown token is the
same whether it never existed or was reissued, so the endpoint never confirms a
guess.
