import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import type { Inbound, Meta, Protocol, Security } from "../types";
import { Banner, Field, Modal, useAsync } from "../components/ui";

/**
 * InboundForm creates and edits one node's inbound.
 *
 * The form is driven by the protocol: each one needs a different handful of
 * parameters, and showing all of them for every protocol is how an operator
 * ends up with a REALITY inbound that has no target. The generate buttons are
 * here too, because a key typed by hand is a key that is wrong.
 */
export default function InboundForm({
  nodeID,
  inbound,
  existing,
  onClose,
  onSaved,
}: {
  nodeID: number;
  inbound?: Inbound;
  existing: Inbound[];
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const meta = useAsync(() => api.meta(), []);
  const editing = Boolean(inbound);
  const fromTemplate = Boolean(inbound?.from_template);

  const [protocol, setProtocol] = useState<Protocol>(inbound?.protocol ?? "vless");
  const [tag, setTag] = useState(inbound?.tag ?? "");
  const [network, setNetwork] = useState(inbound?.network ?? "raw");
  const [security, setSecurity] = useState<Security>(inbound?.security ?? "reality");
  const [listenAddress, setListenAddress] = useState(inbound?.listen_address ?? "");
  const [port, setPort] = useState(String(inbound?.listen_port ?? 443));
  const [published, setPublished] = useState(inbound?.published ?? true);
  const [enabled, setEnabled] = useState(inbound?.enabled ?? true);
  const [forwardTo, setForwardTo] = useState(inbound?.forward_to_tag ?? "");

  const [params, setParams] = useState<Record<string, string>>(inbound?.params ?? {});
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const setParam = (key: string, value: string) =>
    setParams((current) => ({ ...current, [key]: value }));
  const setSecret = (key: string, value: string) =>
    setSecrets((current) => ({ ...current, [key]: value }));

  // A tag is what traffic counters are keyed by, so it is suggested once and
  // then left alone: renaming one loses that inbound's history.
  useEffect(() => {
    if (editing || tag) return;
    setTag(`${protocol}-${port}`.replace(/[^a-zA-Z0-9._-]/g, "-"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [protocol, port]);

  // Each protocol has a transport and a security that make sense for it.
  useEffect(() => {
    if (editing) return;
    if (protocol === "hysteria2") {
      setNetwork("hysteria");
      setSecurity("tls");
      setPort("8443");
    } else if (protocol === "wndns") {
      setNetwork("");
      setSecurity("none");
      setPort("53");
    } else if (protocol === "shadowsocks" || protocol === "shadowsocks2022") {
      setNetwork("raw");
      setSecurity("none");
      setPort("8388");
    } else if (protocol === "trojan") {
      setSecurity("tls");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [protocol]);

  const protocolMeta = useMemo(
    () => meta.data?.protocols.find((entry) => entry.value === protocol),
    [meta.data, protocol],
  );

  const forwardCandidates = existing.filter(
    (candidate) =>
      candidate.id !== inbound?.id &&
      candidate.protocol !== "wndns" &&
      (candidate.listen_address === "127.0.0.1" || candidate.listen_address === "::1"),
  );

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (editing && inbound) {
        // A template instance's parameters come from the template; only the
        // overrides, and the per-node fields, are editable here.
        const body: Record<string, unknown> = {
          listen_address: listenAddress,
          listen_port: Number(port),
          published,
          enabled,
          forward_to_tag: forwardTo,
          secrets,
        };
        if (!fromTemplate) body.params = params;
        else body.overrides = params;
        await api.updateInbound(inbound.id, body);
      } else {
        await api.createInbound(nodeID, {
          tag: tag.trim(),
          protocol,
          network,
          security,
          listen_address: listenAddress.trim(),
          listen_port: Number(port),
          params,
          secrets,
          forward_to_tag: forwardTo,
          published,
          enabled,
        });
      }
      onSaved();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={editing ? `Edit ${inbound?.tag}` : "Add inbound"}
      onClose={onClose}
      wide
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={save} disabled={busy}>
            {busy ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      {fromTemplate && (
        <Banner>
          This inbound comes from a template. Changing a parameter here sets an override for this
          node; the template keeps the rest.
        </Banner>
      )}

      <div className="grid cols-2">
        <Field label="Protocol">
          <select
            value={protocol}
            onChange={(event) => setProtocol(event.target.value as Protocol)}
            disabled={editing}
          >
            {(meta.data?.protocols ?? []).map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Tag" help="The key traffic is counted under; it cannot be changed later.">
          <input value={tag} onChange={(event) => setTag(event.target.value)} disabled={editing} />
        </Field>
        <Field label="Port">
          <input value={port} onChange={(event) => setPort(event.target.value)} inputMode="numeric" />
        </Field>
        <Field
          label="Listen address"
          help="Empty means every interface. Use 127.0.0.1 for an inbound only the DNS tunnel reaches."
        >
          <input
            value={listenAddress}
            onChange={(event) => setListenAddress(event.target.value)}
            placeholder="(all interfaces)"
          />
        </Field>
      </div>

      {protocol !== "wndns" && protocol !== "hysteria2" && (
        <div className="grid cols-2">
          <Field label="Transport">
            <select value={network} onChange={(event) => setNetwork(event.target.value)} disabled={editing}>
              {(protocolMeta?.networks ?? ["raw"]).map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Security">
            <select
              value={security}
              onChange={(event) => setSecurity(event.target.value as Security)}
              disabled={editing}
            >
              {(protocolMeta?.securities ?? ["none"]).map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
        </div>
      )}

      {security === "reality" && (
        <RealityFields params={params} setParam={setParam} secrets={secrets} setSecret={setSecret} existing={inbound} />
      )}
      {security === "tls" && (
        <TLSFields params={params} setParam={setParam} secrets={secrets} setSecret={setSecret} existing={inbound} />
      )}
      {(network === "xhttp" || network === "ws" || network === "httpupgrade") && (
        <div className="grid cols-2">
          <Field label="Path">
            <input value={params.path ?? ""} onChange={(event) => setParam("path", event.target.value)} placeholder="/" />
          </Field>
          <Field label="Host header">
            <input value={params.host ?? ""} onChange={(event) => setParam("host", event.target.value)} />
          </Field>
          {network === "xhttp" && (
            <Field label="Mode">
              <select value={params.mode ?? "auto"} onChange={(event) => setParam("mode", event.target.value)}>
                {["auto", "packet-up", "stream-up", "stream-one"].map((mode) => (
                  <option key={mode} value={mode}>
                    {mode}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>
      )}
      {network === "grpc" && (
        <Field label="Service name">
          <input
            value={params.service_name ?? ""}
            onChange={(event) => setParam("service_name", event.target.value)}
          />
        </Field>
      )}

      {(protocol === "shadowsocks" || protocol === "shadowsocks2022") && (
        <ShadowsocksFields
          protocol={protocol}
          meta={meta.data}
          params={params}
          setParam={setParam}
          secrets={secrets}
          setSecret={setSecret}
        />
      )}

      {protocol === "hysteria2" && (
        <Hysteria2Fields params={params} setParam={setParam} secrets={secrets} setSecret={setSecret} existing={inbound} />
      )}

      {protocol === "wndns" && (
        <WNDNSFields
          params={params}
          setParam={setParam}
          secrets={secrets}
          setSecret={setSecret}
          forwardTo={forwardTo}
          setForwardTo={setForwardTo}
          candidates={forwardCandidates}
          existing={inbound}
        />
      )}

      <label className="checkline">
        <input type="checkbox" checked={published} onChange={(event) => setPublished(event.target.checked)} />
        Offer this in subscriptions
      </label>
      <label className="checkline">
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        Enabled
      </label>
    </Modal>
  );
}

type FieldProps = {
  params: Record<string, string>;
  setParam: (key: string, value: string) => void;
  secrets: Record<string, string>;
  setSecret: (key: string, value: string) => void;
  existing?: Inbound;
};

function RealityFields({ params, setParam, secrets, setSecret, existing }: FieldProps): ReactNode {
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const hasStoredKey = existing?.secret_keys?.includes("private_key") ?? false;

  const generate = async () => {
    const keys = await api.generateReality();
    setSecret("private_key", keys.private_key);
    setPublicKey(keys.public_key);
    setParam("short_ids", keys.short_ids.join(","));
  };

  return (
    <>
      <div className="grid cols-2">
        <Field
          label="Target"
          help="The real site unmatched traffic is handed to. Pick one that is fast from this node and serves TLS 1.3."
        >
          <input
            value={params.target ?? params.dest ?? ""}
            onChange={(event) => setParam("target", event.target.value)}
            placeholder="www.microsoft.com:443"
          />
        </Field>
        <Field label="Server names" help="Comma separated; the first is what clients send as SNI.">
          <input
            value={params.server_names ?? ""}
            onChange={(event) => setParam("server_names", event.target.value)}
            placeholder="www.microsoft.com"
          />
        </Field>
      </div>
      <Field label="Short IDs" help="Comma separated hex, up to 16 characters each.">
        <div className="field-row">
          <input
            value={params.short_ids ?? ""}
            onChange={(event) => setParam("short_ids", event.target.value)}
          />
          <button
            type="button"
            className="small"
            onClick={async () => {
              const result = await api.generateShortIDs(4, 8);
              setParam("short_ids", result.short_ids.join(","));
            }}
          >
            Generate
          </button>
        </div>
      </Field>
      <Field
        label="Private key"
        help={
          hasStoredKey
            ? "A key is stored. Leave empty to keep it."
            : "x25519. The client's public key is derived from this, so it is never entered by hand."
        }
      >
        <div className="field-row">
          <input
            value={secrets.private_key ?? ""}
            onChange={(event) => setSecret("private_key", event.target.value)}
            placeholder={hasStoredKey ? "(unchanged)" : ""}
          />
          <button type="button" className="small" onClick={generate}>
            Generate
          </button>
        </div>
      </Field>
      {publicKey && (
        <Banner kind="ok">
          Public key for clients: <span className="mono">{publicKey}</span> — the panel derives this
          for subscriptions, so there is nothing to copy.
        </Banner>
      )}
      <div className="grid cols-2">
        <Field label="Client fingerprint" help="What the client's TLS should look like.">
          <select value={params.fp ?? "chrome"} onChange={(event) => setParam("fp", event.target.value)}>
            {["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"].map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </Field>
      </div>
    </>
  );
}

function TLSFields({ params, setParam, secrets, setSecret, existing }: FieldProps): ReactNode {
  const hasStored = existing?.secret_keys?.includes("certificate") ?? false;
  return (
    <>
      <div className="grid cols-2">
        <Field label="Server name (SNI)">
          <input value={params.sni ?? ""} onChange={(event) => setParam("sni", event.target.value)} />
        </Field>
        <Field label="ALPN" help="Comma separated; leave empty for the default.">
          <input value={params.alpn ?? ""} onChange={(event) => setParam("alpn", event.target.value)} />
        </Field>
      </div>
      <Field
        label="Certificate file on the node"
        help="The simplest option when something already manages the certificate there."
      >
        <input
          value={params.cert_file ?? ""}
          onChange={(event) => setParam("cert_file", event.target.value)}
          placeholder="/etc/letsencrypt/live/example.com/fullchain.pem"
        />
      </Field>
      <Field label="Key file on the node">
        <input
          value={params.key_file ?? ""}
          onChange={(event) => setParam("key_file", event.target.value)}
          placeholder="/etc/letsencrypt/live/example.com/privkey.pem"
        />
      </Field>
      <Field
        label="Or paste the certificate"
        help={hasStored ? "A certificate is stored. Leave empty to keep it." : "PEM, including the chain."}
      >
        <textarea
          value={secrets.certificate ?? ""}
          onChange={(event) => setSecret("certificate", event.target.value)}
          placeholder={hasStored ? "(unchanged)" : "-----BEGIN CERTIFICATE-----"}
        />
      </Field>
      <Field label="And its private key">
        <textarea
          value={secrets.key ?? ""}
          onChange={(event) => setSecret("key", event.target.value)}
          placeholder={hasStored ? "(unchanged)" : "-----BEGIN PRIVATE KEY-----"}
        />
      </Field>
    </>
  );
}

function ShadowsocksFields({
  protocol,
  meta,
  params,
  setParam,
  secrets,
  setSecret,
}: FieldProps & { protocol: Protocol; meta: Meta | null }): ReactNode {
  const methods = (meta?.shadowsocks_methods ?? []).filter((entry) => entry.protocol === protocol);
  const current = methods.find((entry) => entry.value === params.method);

  return (
    <>
      <Field label="Method">
        <select value={params.method ?? ""} onChange={(event) => setParam("method", event.target.value)}>
          <option value="">Choose a method…</option>
          {methods.map((entry) => (
            <option key={entry.value} value={entry.value}>
              {entry.value}
              {!entry.multiuser ? " (one user only)" : ""}
            </option>
          ))}
        </select>
      </Field>
      {current && !current.multiuser && (
        <Banner kind="warn">
          This method has no per-user key derivation, so one inbound can serve only one user. Choose
          an aes method for a shared node.
        </Banner>
      )}
      {protocol === "shadowsocks2022" && (
        <Field
          label="Server key"
          help="Base64. Clients are given serverKey:userKey, so this is half of every user's credential."
        >
          <div className="field-row">
            <input
              value={secrets.password ?? ""}
              onChange={(event) => setSecret("password", event.target.value)}
            />
            <button
              type="button"
              className="small"
              disabled={!params.method}
              onClick={async () => {
                const result = await api.generateShadowsocks(params.method ?? "");
                setSecret("password", result.password);
              }}
            >
              Generate
            </button>
          </div>
        </Field>
      )}
      {protocol === "shadowsocks" && (
        <Field
          label="Fallback password"
          help="Used only while the node has no users, so the inbound can start. Nobody is given it."
        >
          <div className="field-row">
            <input
              value={secrets.password ?? ""}
              onChange={(event) => setSecret("password", event.target.value)}
            />
            <button
              type="button"
              className="small"
              onClick={async () => {
                const result = await api.generatePassword();
                setSecret("password", result.password);
              }}
            >
              Generate
            </button>
          </div>
        </Field>
      )}
    </>
  );
}

function Hysteria2Fields({ params, setParam, secrets, setSecret, existing }: FieldProps): ReactNode {
  const hasStored = existing?.secret_keys?.includes("certificate") ?? false;
  const obfs = (params.finalmask_udp ?? "").includes("salamander");

  return (
    <>
      <Banner>
        Hysteria2 runs over QUIC, so it needs TLS. Each user's password is their own; there is
        nothing per-inbound to set.
      </Banner>
      <div className="grid cols-2">
        <Field label="Server name (SNI)">
          <input value={params.sni ?? ""} onChange={(event) => setParam("sni", event.target.value)} />
        </Field>
        <Field label="Congestion control" help="Leave empty for the implementation's own choice.">
          <select
            value={params.congestion ?? ""}
            onChange={(event) => setParam("congestion", event.target.value)}
          >
            <option value="">default</option>
            <option value="bbr">bbr</option>
            <option value="brutal">brutal</option>
          </select>
        </Field>
        <Field label="Up, Mbit/s" help="Optional hint for the sender.">
          <input
            value={params.up_mbps ?? ""}
            onChange={(event) => setParam("up_mbps", event.target.value)}
            inputMode="numeric"
          />
        </Field>
        <Field label="Down, Mbit/s">
          <input
            value={params.down_mbps ?? ""}
            onChange={(event) => setParam("down_mbps", event.target.value)}
            inputMode="numeric"
          />
        </Field>
      </div>
      <label className="checkline">
        <input
          type="checkbox"
          checked={obfs}
          onChange={(event) => setParam("finalmask_udp", event.target.checked ? "salamander" : "")}
        />
        Salamander obfuscation — makes the QUIC handshake harder to recognise
      </label>
      {obfs && (
        <Field label="Obfuscation password">
          <div className="field-row">
            <input
              value={secrets.obfs_password ?? ""}
              onChange={(event) => setSecret("obfs_password", event.target.value)}
            />
            <button
              type="button"
              className="small"
              onClick={async () => {
                const result = await api.generatePassword();
                setSecret("obfs_password", result.password);
              }}
            >
              Generate
            </button>
          </div>
        </Field>
      )}
      <Field
        label="Certificate"
        help={hasStored ? "A certificate is stored. Leave empty to keep it." : "PEM, or use a file path below."}
      >
        <textarea
          value={secrets.certificate ?? ""}
          onChange={(event) => setSecret("certificate", event.target.value)}
          placeholder={hasStored ? "(unchanged)" : "-----BEGIN CERTIFICATE-----"}
        />
      </Field>
      <Field label="Private key">
        <textarea
          value={secrets.key ?? ""}
          onChange={(event) => setSecret("key", event.target.value)}
          placeholder={hasStored ? "(unchanged)" : "-----BEGIN PRIVATE KEY-----"}
        />
      </Field>
      <Field label="Or a certificate file on the node">
        <input
          value={params.cert_file ?? ""}
          onChange={(event) => setParam("cert_file", event.target.value)}
        />
      </Field>
      <Field label="And its key file">
        <input value={params.key_file ?? ""} onChange={(event) => setParam("key_file", event.target.value)} />
      </Field>
    </>
  );
}

function WNDNSFields({
  params,
  setParam,
  secrets,
  setSecret,
  forwardTo,
  setForwardTo,
  candidates,
  existing,
}: FieldProps & {
  forwardTo: string;
  setForwardTo: (value: string) => void;
  candidates: Inbound[];
}): ReactNode {
  const hasKey = existing?.secret_keys?.includes("encryption_key") ?? false;
  const method = params.encryption_method ?? "2";
  const keyLength = method === "3" ? 16 : method === "4" ? 24 : 32;

  return (
    <>
      <Banner>
        The DNS tunnel has no accounts of its own. It forwards every stream into an inbound on this
        node, and that inbound authenticates the user, counts their traffic and can revoke them.
        Point it at one that listens on 127.0.0.1.
      </Banner>
      <Field
        label="Forward into"
        help={
          candidates.length === 0
            ? "No loopback inbound on this node yet. Create one first — a VLESS inbound on 127.0.0.1 with a free port, not offered in subscriptions."
            : "Only inbounds on the loopback interface are offered: a public one would make the chain bypassable."
        }
      >
        <select value={forwardTo} onChange={(event) => setForwardTo(event.target.value)}>
          <option value="">Choose an inbound…</option>
          {candidates.map((candidate) => (
            <option key={candidate.id} value={candidate.tag}>
              {candidate.tag} — {candidate.protocol} on {candidate.listen_address}:
              {candidate.listen_port}
            </option>
          ))}
        </select>
      </Field>
      <Field
        label="Domains"
        help="Comma separated. Each must have an NS record pointing at this node."
      >
        <input
          value={params.domains ?? ""}
          onChange={(event) => setParam("domains", event.target.value)}
          placeholder="t1.tunnel.example.com,t2.tunnel.example.com"
        />
      </Field>
      <Field
        label="Resolvers"
        help="Optional, comma separated: address, address:port or [v6]:port. Where the app sends the tunnel's queries. Empty keeps the app's built-in list; set it when the resolvers that get through change, and every app picks it up on its next subscription update."
      >
        <input
          value={params.resolvers ?? ""}
          onChange={(event) => setParam("resolvers", event.target.value)}
          placeholder="195.208.4.1,195.208.5.1,77.88.8.8"
        />
      </Field>
      <div className="grid cols-2">
        <Field label="Encryption">
          <select
            value={method}
            onChange={(event) => setParam("encryption_method", event.target.value)}
          >
            <option value="0">none</option>
            <option value="1">XOR</option>
            <option value="2">ChaCha20</option>
            <option value="3">AES-128-GCM</option>
            <option value="4">AES-192-GCM</option>
            <option value="5">AES-256-GCM</option>
          </select>
        </Field>
        <Field
          label="Encryption key"
          help={
            hasKey
              ? `A key is stored. Leave empty to keep it. This method needs ${keyLength} hex characters.`
              : `${keyLength} hex characters for this method.`
          }
        >
          <div className="field-row">
            <input
              value={secrets.encryption_key ?? ""}
              onChange={(event) => setSecret("encryption_key", event.target.value)}
              placeholder={hasKey ? "(unchanged)" : ""}
            />
            <button
              type="button"
              className="small"
              onClick={() => {
                // Hex of the exact length the tunnel's key file wants; it
                // reads the file as text and insists on it.
                const bytes = new Uint8Array(keyLength / 2);
                crypto.getRandomValues(bytes);
                setSecret(
                  "encryption_key",
                  Array.from(bytes)
                    .map((byte) => byte.toString(16).padStart(2, "0"))
                    .join(""),
                );
              }}
            >
              Generate
            </button>
          </div>
        </Field>
      </div>
    </>
  );
}
