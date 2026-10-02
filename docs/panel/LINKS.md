# whitenet:// links and subscriptions

Two ways to get a configuration into WhiteNetVPN, for two different jobs.

| | `whitenetvpn://import?url=…` | `whitenet://v1/…` |
|---|---|---|
| Carries | a subscription URL | the servers themselves |
| Updates | yes, the app refetches | no, it is a snapshot |
| Limits and expiry enforced | yes | no |
| Revocable | yes, reissue the token | no, only by changing the credentials |
| Size | tiny | grows with the number of servers |
| Use it for | every real user | a test server, a one-off, handing one node to someone |

Give a user a subscription link. Reach for a share link when there is no
panel in the loop, or when something has to work before the first fetch.

## Subscription links

```
https://sub.whitenet.example/sub/7f3a9c1e2d5b8406
```

Opened in a browser it shows the branded subscription page — days left,
traffic used, a QR code, an "Open in WhiteNetVPN" button and setup
instructions. Requested by the app (recognised by `User-Agent` or the
`X-HWID` header) it answers the JSON described in
[SUBSCRIPTION.md](SUBSCRIPTION.md).

The deep link the page's button and the QR code use:

```
whitenetvpn://import?url=https%3A%2F%2Fsub.whitenet.example%2Fsub%2F7f3a9c1e2d5b8406
```

Build one with:

```bash
wn-main link import https://sub.whitenet.example/sub/7f3a9c1e2d5b8406
```

The subscription URL is percent-encoded in a query parameter, so a token with
characters that mean something in a URL cannot break the link. `https` is
required and enforced: the subscription carries every credential the user has.

## Share links

```
whitenet://v1/<base64url(deflate(json))>
```

DEFLATE'd JSON in base64url without padding — the same encoding OpenFlux uses,
for the same reason: it is compact enough for a QR code. The payload is a
bundle:

```json
{
  "name": "WhiteNet DE-1",
  "servers": [ /* subscription-format server objects */ ],
  "sub": "https://sub.whitenet.example/sub/TOKEN",
  "branding": { "support_url": "https://t.me/whitenet" }
}
```

`servers` is the point of the link. `sub` is optional and makes the link both
instant and self-updating: the app connects with the embedded servers, then
switches to the subscription. `branding` travels along so a shared server still
looks right in the app.

Build, read and render links with the CLI, which needs no database:

```bash
wn-main link make bundle.json      # bundle JSON -> link
wn-main link read 'whitenet://v1/…' # link -> bundle JSON
wn-main link qr 'whitenet://v1/…'   # link -> QR code in the terminal
```

Decoding is deliberately forgiving about what travel does to a link: leading
and trailing whitespace, line breaks inside it (a link wraps when copied out
of a terminal or a chat), added base64 padding, and the standard base64
alphabet where this uses the URL alphabet. One thing it cannot survive is a
change of case, because the payload is case-sensitive — a mail client or chat
app that lowercases URLs destroys the link, and the app says so specifically
instead of reporting generic corruption.

**A share link is a bearer credential.** It contains the user's UUID or
password, the Reality public key, and for flux the channel's encryption
secret. Whoever has the link has the access until those values change.

## Examples

Every link below is real output from `wn-main link make`; paste one into
`wn-main link read` to see it expand.

### VLESS + Reality

```json
{
  "name": "WhiteNet DE-1",
  "servers": [{
    "id": "4f1c9e0a-7b2d-4e8a-9c31-5a6b7c8d9e0f:vless-reality-443",
    "name": "🇩🇪 Germany 1",
    "country": "DE",
    "group": "Europe",
    "protocol": "vless",
    "transport": "reality",
    "address": "185.68.184.144",
    "port": 443,
    "params": {
      "uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
      "flow": "xtls-rprx-vision",
      "sni": "www.microsoft.com",
      "pbk": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
      "sid": "6ba85179e30d4fc2",
      "fp": "chrome"
    }
  }]
}
```

```
whitenet://v1/NJDNbtQwFIVfZXTWdhRPnD-vZwQFVEGpABWxcByHSUni6NrJdBjNuo_RNTzdPAJKRNfn3vMdfWcMurdQ-Hpog721YbPbcwEGb2m25KG-n9HWUJCNMKWNNc-rbc2lLTQvTSJ4qrMqN0Vd2rhRc2e952R114YTlzIBewVcX57_XF-e_27eWOr1cNosFOOmIdAJCrs9GH6Sm0Yo7CdyowXDSC444zoorNVgCKQHPzoKUPgPAoOua1pyBVGkUVZEopCRkHLpWG-lTBhGTbr3UGc0nTtC4Sl0ntNIT3xufesGMDTLAHMg168Dql9QeLz99jaI052L591kDp-6m4_ZQ_wwP94n78PvLzf8Xu7zO_fh3ed4Ubf6yipdpCIvbRLXsjHbJRhaKByPx6hvDTnvmhAZ14NhmtafsilsXmeGp5XUPCm3BRd5nPEmtbJOzLYSOsbl8uPyLwAA__8
```

### VLESS + XHTTP behind a CDN

```json
{
  "params": {
    "uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
    "path": "/wn",
    "host": "cdn.example.com",
    "mode": "auto",
    "security": "tls",
    "sni": "cdn.example.com",
    "fp": "chrome"
  }
}
```

```
whitenet://v1/bNBBitswGAXgq4S3llzLlmNbJ-iihC4CLZQuZOk3NtiWkeQ0JWSdY-QMw1wsRxhkmN2s_5_vPd4Ni54JCr-GMdKJ4uH39_P5JxgC-Qv5APXnhtFCQfbCtJRrXneF5ZIazVtTCl7pY1ebxraU9-oyUQj8OsS48kbKEuwz4PV8vL-ej7fDieJAftKLDQcBBuO2Jfr_UDj9AMPqXXTGTVDYMTBEr5ewOh-hsNNg0Nb6dFUQZZOJQmaizYSskrB_pnSGVXs9B6gb-hUKZvBuJjAMLiTN2CWjq57XiTLjZjDMzqa2eosuUToOUPj2b9kXMZsfY2oap9QrLOOXxrbtg7V9Q7U9Gl51UvOyLRou6vzI-4qkLU3RCZ3jfv97_wgAAP__
```

### Hysteria2 with Salamander obfuscation

```json
{
  "protocol": "hysteria2",
  "port": 8443,
  "params": {
    "auth": "Zm9vYmFyYmF6cXV1eA",
    "sni": "bing.com",
    "obfs": "salamander",
    "obfs_password": "s3cr3t",
    "up_mbps": "100",
    "down_mbps": "300"
  }
}
```

```
whitenet://v1/PNBBasMwEAXQq4S_lo1lO4mtXTem3XTZNi0ljCWlMUSSkZSEELzOMXKAQs-WIxRB0-UMzBv-P8OS0RB43Q5RP-s4e1yVYAjaH7QPEB9nDAoC9YbLVheULftSZbVuKGtlxbM5LfqlbFSri43YnkLUfqAya-q6Arvjt-vl-3a9_My6we7IqhkHg3R7G_0JAt0TGEbvopNuB4F_BgyklNchQIBXTc7LOudtzut5unA-QqRPDCN5MgHiDNrHLQTeTXtYme60Mt1Cvr1w_QAG5Y52bfoxcVVRgMH1mzQE2pEhq7T_261HCuHofIoeKumrmEqxAwT6wX7l0hkw7Me7xosC0_Q5_QYAAP__
```

### Shadowsocks 2022

```json
{
  "protocol": "shadowsocks2022",
  "port": 9443,
  "params": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "c2VydmVyS2V5OnVzZXJLZXk="
  }
}
```

```
whitenet://v1/NI5BTgIxGIWvQt66JbRTZKaJSzfG6GKSkWBclPZHCMyU9K8SJLPmGOw9gcfiCGZI3L_ve98JnWsJFq_rTaZnyqO6hgBT-qLEsG8nbAIszEr5iiZOzpY6SEOlk5UvlJy6u-XMl6Giycoy64nWsjKmgPgXXy_n3-vl_DOqDxSoGykI-PjZ5XSERf0AgX2KOfq4gwWvXYgHjn57c0HAhZCIGRaqKMdKm7GqxspMBy6mDDvcCexdci3DntBSXseh-Raz3LktFdIRS6VL-eHbAXTMh5iGkdfNMbTNsdbN9KVrvhfzx6fFfHuPvn_v_wIAAP__
```

### The DNS tunnel, chained into VLESS

The DNS tunnel has no accounts of its own, so it forwards into a local Xray
inbound and that inbound authenticates the user. The app therefore needs both
halves: the tunnel's parameters and, in `chain`, the protocol to speak through
it.

```json
{
  "protocol": "wndns",
  "transport": "dns",
  "address": "185.68.184.144",
  "port": 53,
  "params": {
    "domains": "t1.wn-dns.example,t2.wn-dns.example",
    "encryption_method": "2",
    "encryption_key": "4f3c2b1a09876543210fedcba9876543"
  },
  "chain": {
    "protocol": "vless",
    "transport": "raw",
    "params": { "uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0" }
  }
}
```

```
whitenet://v1/XJA9jtswFISvYkyVAKQg6l-sHaRzs0WKIAieyCdYiEUKJL2OYajeY2ydnG6PEMjZALsp38PM4Ju5wdHM0PhynBIfOO32hwcIRA6PHCL01xsmC41qVKbnnGQ7FFZW3JHsTalkTc3Qms72nI_64qyLsi4h_sW-PD_9enl--r37zGEmd92p3Yf94eEjBIw_uxSu0Nh_gsASfPLGn6Bxj4FACuTi4kOCxt8PWRs4Rmiors6aLlNdlamq2vx3XV0KLBRojtA3WD_T5DZ5UtnFSetixj9pXk4sUvHfBwLsTLguafLu-w--3luXphgU5X3XNnVVFiof2ZqBXu_3npnT0W9jFVgFzJEmt1G8afZ42ujfNwt0wVvo8_k-eD923NrGyHqoSJZ90UnV5o0ca67sKxXWdf22_gkAAP__
```

### flux: a leased channel

One flux channel carries one client at a time, so the normal shape is a lease
endpoint rather than a channel. The app asks for a free channel when it
connects and renews while it uses it.

```json
{
  "protocol": "flux",
  "transport": "yandex",
  "flux": {
    "mode": "l4",
    "lease": "https://sub.whitenet.example/lease/7f3a9c1e2d5b8406"
  }
}
```

```
whitenet://v1/NE_PaoMwHH4V-U4bxKqtrZrz2Gl4HWPsEJOfWIiJJHGziOc-Rp9h7MX6CMOWHj--_zOM6Akc790xUE0hetXjBAZP7pucB_-ccVTgyNtMVpSKuGi2Ks6pFHEld1m8F4emkKWqKG15q8cpHqzVYI_g6-X8d72cf6OaQkdOC6N89PQhjKIperHSP4NB2tEEdwJH_QaGwdlgpdXgaO9zghPGD9YFcJxuXrA7x2f0Vq1NOgeDJuFX0IUweJ4kfmw2P-s3Q2FDk-gHTclNlBTtTlQyo63aN2WeHrAsX8t_AAAA__8
```

### flux: a dedicated channel with two carriers

When a channel belongs to one user, the credentials travel in the link. Two
carriers in one channel means a session with failover: the app prefers
`direct` and falls back to the Cups.online room when it is blocked.

```json
{
  "protocol": "flux",
  "transport": "cupsonline",
  "flux": {
    "mode": "l3",
    "channels": [{
      "id": "ch-7",
      "secret": "7b1f0c9d2e3a4b5c6d7e8f90a1b2c3d47b1f0c9d2e3a4b5c6d7e8f90a1b2c3d4",
      "context": "https://cups.online/room/ab12cd",
      "carriers": [
        { "type": "cupsonline", "url": "https://cups.online/room/ab12cd", "priority": 50 },
        { "type": "direct", "priority": 100, "params": { "dial": "138.124.19.145:8444" } }
      ]
    }]
  }
}
```

```
whitenet://v1/jJE_jtUwEMavEk0FwvnjxNkk7mio4LUgoS0ce6JYcuxo4qD39JR6j7FnQFxsj4C8yz4QDTRuPuv3_WbmCl4tCBI-zzbiCWP2we3nzFhCHYHBhvQNaQP59QrWgAQxcT1gpfJurE0usFf5oBuet-pu7HRvBqwmObn9nOu5A_aKf3p8-PH0-PA9O2GckZzyZsvefHr_JXv3q-wtMNBh95EuIOH0ERisFGLQwYGERAQGkZTf1kARJOh93YJ31iOwl1xeYQkm1bkm0WblPbo_5PWcd89DacKE6EY-VXowNTZKjK2-Mx3201ApPta6MeJf-bOyj3hOsDnGdZNlmbyKF7GSQlhKNfJam_RXEdnXbcbLin9PsZP7L9BKNpCNF5BtdbAb63a13zmvKgarIrVsaT3GqtTAm77gtSj4UHDRyl4IAcdxf9yn52cAAAD__w
```

## Fields per protocol

`params` is flat strings throughout — that is what every consumer wants, and it
keeps the format stable when a new knob appears.

| Protocol | `params` |
|---|---|
| `vless` | `uuid`, `flow`, and the transport's keys |
| `vmess` | `uuid`, `security` (`auto`, `aes-128-gcm`, `none`), `alter_id` |
| `trojan` | `password` |
| `shadowsocks` | `method`, `password` |
| `shadowsocks2022` | `method` (a `2022-blake3-*` method), `password` (base64) |
| `hysteria2` | `auth`, `sni`, `obfs`, `obfs_password`, `up_mbps`, `down_mbps`. These are the client's view: on the node the same obfuscation is configured as a `finalmask` mask of type `salamander`, which is where this Xray version keeps it - see [PROTOCOLS.md](PROTOCOLS.md#hysteria2) |
| `wndns` | `domains` (comma separated), `encryption_method`, `encryption_key`, optional `resolvers` (comma separated `address[:port]`), plus `chain` |
| `flux` | nothing; see the `flux` block |

Transport keys, by `transport`:

| Transport | `params` |
|---|---|
| `reality` | `sni`, `pbk`, `sid`, `fp`, `spx` |
| `tls` | `sni`, `fp`, `alpn`, `allow_insecure` |
| `xhttp` | `path`, `host`, `mode` (`auto`, `packet-up`, `stream-up`, `stream-one`), plus the TLS keys |
| `ws` | `path`, `host`, plus the TLS keys |
| `httpupgrade` | `path`, `host`, plus the TLS keys |
| `grpc` | `service_name`, `multi_mode`, plus the TLS keys |
| `kcp` | `seed`, `header` |
| `raw` | none |
| `dns` | see `wndns` above |

## Error codes

The app words these for its users; the panel and the core only decide which
one it is.

| Code | Means |
|---|---|
| `not_link` | not a `whitenet://` or `whitenetvpn://` link at all |
| `unsupported_version` | a newer link format; the app needs updating |
| `case_changed` | something lowercased or uppercased the link in transit |
| `damaged` | truncated or mangled payload |
| `too_large` | payload over 256 KiB |
| `bad_payload` | decompresses, but is not a bundle |
| `no_servers` | a bundle with an empty server list |
| `bad_server` | a server the app cannot connect with; `Param` names it |
| `no_url` | an import link with no `url`, or one with no host |
| `not_https` | a subscription URL that is not `https` |
