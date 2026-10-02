import { useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import type { Channel, Node } from "../types";
import { Banner, Card, Confirm, CopyLine, Field, Modal, Pill, Spinner, formatDate, useAsync } from "../components/ui";

/**
 * FluxPanel configures a node's flux exit and its channel pool.
 *
 * A channel carries one client at a time, so the pool is the node's capacity
 * for flux - which is why the page talks about counts rather than about users.
 */
export default function FluxPanel({ node }: { node: Node }): ReactNode {
  const config = useAsync(() => api.nodeFlux(node.id), [node.id]);
  const channels = useAsync(() => api.channels(node.id), [node.id]);
  const meta = useAsync(() => api.meta(), []);

  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<Channel | null>(null);
  const [rotating, setRotating] = useState<Channel | null>(null);
  const [shareLink, setShareLink] = useState<{ name: string; link: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  if (!config.data) return <Spinner />;

  const setConfig = async (enabled: boolean, mode: string) => {
    setError(null);
    setMessage(null);
    try {
      const result = await api.setNodeFlux(node.id, { enabled, mode });
      if (result.warning) setMessage(result.warning);
      config.reload();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    }
  };

  const list = channels.data?.channels ?? [];
  const leased = list.filter((channel) => channel.session_active).length;

  return (
    <>
      {error && <Banner kind="error">{error}</Banner>}
      {message && <Banner kind="warn">{message}</Banner>}

      <Card title="Flux exit">
        <p className="muted" style={{ marginTop: 0 }}>
          Flux carries traffic over ordinary services — a Yandex document, a MAX room, a
          Cups.online room — or over a plain TCP port. Each channel serves one client at a time, so
          the number of channels is how many people can use flux on this node at once.
        </p>
        <div className="grid cols-2">
          <Field label="Enabled">
            <label className="checkline">
              <input
                type="checkbox"
                checked={config.data.enabled}
                onChange={(event) => setConfig(event.target.checked, config.data!.mode)}
              />
              Run the flux exit on this node
            </label>
          </Field>
          <Field
            label="Exit mode"
            help="l3 is faster but needs Linux and raw sockets. l4 terminates in a userspace stack and works anywhere."
          >
            <select
              value={config.data.mode}
              onChange={(event) => setConfig(config.data!.enabled, event.target.value)}
              disabled={!config.data.enabled}
            >
              <option value="l4">l4 — portable</option>
              <option value="l3">l3 — Linux, needs root</option>
            </select>
          </Field>
        </div>
        {config.data.mode === "l3" && config.data.enabled && (
          <Banner kind="warn">
            An l3 exit rewrites source addresses, so the kernel answers return packets with RST and
            tears the tunnel's connections down. The node needs an outbound RST filter; see
            docs/panel/PROTOCOLS.md.
          </Banner>
        )}
      </Card>

      <Card
        title={`Channels — ${leased} of ${list.length} carrying a session`}
        actions={
          <button className="primary small" onClick={() => setAdding(true)} disabled={!config.data.enabled}>
            Add channels
          </button>
        }
      >
        {!channels.data ? (
          <Spinner />
        ) : list.length === 0 ? (
          <div className="empty">
            No channels. Each one is a carrier plus its own key; add a few so more than one person
            can use flux at a time.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Carrier</th>
                  <th>Where</th>
                  <th>In use</th>
                  <th>Added</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.map((channel) => (
                  <tr key={channel.id}>
                    <td>
                      {channel.name}
                      {!channel.enabled && <span className="faint"> · disabled</span>}
                      {channel.last_error && (
                        <div className="error" style={{ fontSize: 12 }}>
                          {channel.last_error}
                        </div>
                      )}
                    </td>
                    <td>
                      {channel.transport_label ?? channel.transport}
                      {!channel.shareable && (
                        <div className="faint">not put in share links</div>
                      )}
                    </td>
                    <td className="mono" style={{ maxWidth: 280, overflowWrap: "anywhere" }}>
                      {channel.url || channel.params.listen || "—"}
                    </td>
                    <td>
                      {channel.session_active ? (
                        <Pill kind="ok" dot>
                          session
                        </Pill>
                      ) : (
                        <span className="faint">free</span>
                      )}
                    </td>
                    <td className="faint nowrap">{formatDate(channel.created_at)}</td>
                    <td className="actions">
                      <button
                        className="small"
                        onClick={() =>
                          api
                            .updateChannel(channel.id, { enabled: !channel.enabled })
                            .then(() => channels.reload())
                            .catch((caught: unknown) =>
                              setError(caught instanceof RequestError ? caught.message : String(caught)),
                            )
                        }
                      >
                        {channel.enabled ? "Disable" : "Enable"}
                      </button>{" "}
                      <button className="small" onClick={() => setRotating(channel)}>
                        Rotate key
                      </button>{" "}
                      {channel.shareable && channel.enabled && (
                        <>
                          <button
                            className="small"
                            title="A self-contained whitenet:// link to this channel, to hand to someone"
                            onClick={() =>
                              api
                                .channelShareLink(channel.id)
                                .then((r) => setShareLink({ name: channel.name, link: r.link }))
                                .catch((caught: unknown) =>
                                  setError(
                                    caught instanceof RequestError ? caught.message : String(caught),
                                  ),
                                )
                            }
                          >
                            Share link
                          </button>{" "}
                        </>
                      )}
                      <button className="small danger" onClick={() => setDeleting(channel)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {adding && (
        <AddChannels
          nodeID={node.id}
          carriers={meta.data?.flux_carriers ?? []}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            channels.reload();
          }}
        />
      )}

      {shareLink && (
        <Modal title={`Share “${shareLink.name}”`} onClose={() => setShareLink(null)}>
          <p className="muted" style={{ marginTop: 0 }}>
            A self-contained link to this channel. Whoever opens it in WhiteNetVPN connects straight
            to this exit — no subscription needed. A flux channel carries one client at a time, so
            treat it as dedicated to whoever you give it to.
          </p>
          <CopyLine value={shareLink.link} />
        </Modal>
      )}

      {rotating && (
        <Confirm
          title={`Rotate the key for ${rotating.name}?`}
          confirmLabel="Rotate"
          message="Whoever is connected on this channel stops decrypting and has to ask for a channel again. This is how a leaked channel is taken back."
          onCancel={() => setRotating(null)}
          onConfirm={async () => {
            const target = rotating;
            setRotating(null);
            try {
              await api.rotateChannel(target.id);
              channels.reload();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}

      {deleting && (
        <Confirm
          title={`Delete ${deleting.name}?`}
          danger
          confirmLabel="Delete"
          message="The channel and its lease history go. Anyone using it right now is disconnected."
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const target = deleting;
            setDeleting(null);
            try {
              await api.deleteChannel(target.id);
              channels.reload();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
    </>
  );
}

function AddChannels({
  nodeID,
  carriers,
  onClose,
  onSaved,
}: {
  nodeID: number;
  carriers: { value: string; label: string; needs: string[]; note: string }[];
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const [transport, setTransport] = useState("direct");
  const [name, setName] = useState("");
  const [url, setURL] = useState("");
  const [listen, setListen] = useState("0.0.0.0:8444");
  const [token, setToken] = useState("");
  const [uid, setUID] = useState("");
  const [cookiesFile, setCookiesFile] = useState("");
  const [count, setCount] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const carrier = carriers.find((entry) => entry.value === transport);
  const needs = (key: string) => carrier?.needs.includes(key) ?? false;

  const submit = async () => {
    setBusy(true);
    setError(null);
    const params: Record<string, string> = {};
    if (needs("listen")) params.listen = listen.trim();
    if (needs("token")) params.token = token.trim();
    if (needs("uid")) params.uid = uid.trim();
    if (needs("cookies_file")) params.cookies_file = cookiesFile.trim();

    try {
      await api.createChannels(nodeID, {
        name: name.trim() || transport,
        transport,
        url: url.trim(),
        params,
        count,
      });
      onSaved();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Add flux channels"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={submit} disabled={busy}>
            {busy ? "Creating…" : count > 1 ? `Create ${count} channels` : "Create channel"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}

      <Field label="Carrier">
        <select value={transport} onChange={(event) => setTransport(event.target.value)}>
          {carriers.map((entry) => (
            <option key={entry.value} value={entry.value}>
              {entry.label}
            </option>
          ))}
        </select>
      </Field>
      {carrier?.note && <p className="faint" style={{ margin: 0 }}>{carrier.note}</p>}

      <Field label="Name" help="Just for the panel's list.">
        <input value={name} onChange={(event) => setName(event.target.value)} placeholder={transport} />
      </Field>

      {needs("url") && (
        <Field label="Document or room URL">
          <input value={url} onChange={(event) => setURL(event.target.value)} placeholder="https://…" />
        </Field>
      )}
      {needs("listen") && (
        <Field
          label="Listen address"
          help="The exit listens here. Clients are given this node's own address with the same port."
        >
          <input value={listen} onChange={(event) => setListen(event.target.value)} />
        </Field>
      )}
      {needs("token") && (
        <Field label="MAX token" help="Belongs to the exit's own account, so it never goes into a share link.">
          <input value={token} onChange={(event) => setToken(event.target.value)} />
        </Field>
      )}
      {needs("uid") && (
        <Field label="MAX user id">
          <input value={uid} onChange={(event) => setUID(event.target.value)} inputMode="numeric" />
        </Field>
      )}
      {needs("cookies_file") && (
        <Field
          label="Cookies file on the node"
          help="A Netscape cookies.txt with a signed-in Yandex account. Put it on the node and give the path."
        >
          <input
            value={cookiesFile}
            onChange={(event) => setCookiesFile(event.target.value)}
            placeholder="/var/lib/whitenet-agent/cores/yandex-cookies.txt"
          />
        </Field>
      )}

      <Field
        label="How many"
        help="Each channel gets its own key, so one being taken back does not affect the others. Channels of the same carrier can share a document only if the carrier allows it — for direct, each needs its own port."
      >
        <input
          type="number"
          min={1}
          max={100}
          value={count}
          onChange={(event) => setCount(Math.max(1, Number(event.target.value)))}
          style={{ width: 110 }}
        />
      </Field>
    </Modal>
  );
}
