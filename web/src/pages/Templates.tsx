import { useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import type { Group, Node, Protocol, Security, Template } from "../types";
import {
  Banner,
  Card,
  Confirm,
  Field,
  Modal,
  Pill,
  Spinner,
  useAsync,
} from "../components/ui";

/**
 * Templates is the inbound page: one definition, applied to many nodes.
 *
 * A template is the usual way to run the same protocol everywhere. A node can
 * still override a port or an SNI, and a one-off inbound belongs on the node's
 * own page.
 */
export default function Templates(): ReactNode {
  const templates = useAsync(() => api.templates(), []);
  const nodes = useAsync(() => api.nodes(), []);
  const groups = useAsync(() => api.groups(), []);

  const [editing, setEditing] = useState<Template | "new" | null>(null);
  const [targeting, setTargeting] = useState<Template | null>(null);
  const [deleting, setDeleting] = useState<Template | null>(null);
  const [error, setError] = useState<string | null>(null);

  const groupName = (id: number) =>
    groups.data?.groups.find((group) => group.id === id)?.name ?? `#${id}`;
  const nodeName = (id: number) =>
    nodes.data?.nodes.find((node) => node.id === id)?.name ?? `#${id}`;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Inbounds</h1>
          <div className="sub">
            Templates applied to nodes and groups. A node's own inbounds are on its page.
          </div>
        </div>
        <div className="actions">
          <button className="primary" onClick={() => setEditing("new")}>
            New template
          </button>
        </div>
      </div>

      {error && <Banner kind="error">{error}</Banner>}

      <Card>
        {!templates.data ? (
          <Spinner />
        ) : templates.data.templates.length === 0 ? (
          <div className="empty">
            No templates. One template per protocol, applied to a group, is how a fleet is usually
            set up.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Protocol</th>
                  <th>Port</th>
                  <th>Applied to</th>
                  <th>Secrets</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {templates.data.templates.map((template) => (
                  <tr key={template.id}>
                    <td style={{ fontWeight: 600 }}>
                      {template.name}
                      {!template.enabled && <span className="faint"> · disabled</span>}
                    </td>
                    <td>
                      {template.protocol}
                      {template.security !== "none" && (
                        <span className="faint"> · {template.security}</span>
                      )}
                      {template.network && <span className="faint"> · {template.network}</span>}
                    </td>
                    <td className="num">{template.listen_port ?? "—"}</td>
                    <td>
                      <div className="chips">
                        {template.group_ids.map((id) => (
                          <span key={`g${id}`} className="chip on">
                            {groupName(id)}
                          </span>
                        ))}
                        {template.node_ids.map((id) => (
                          <span key={`n${id}`} className="chip">
                            {nodeName(id)}
                          </span>
                        ))}
                        {template.group_ids.length === 0 && template.node_ids.length === 0 && (
                          <span className="faint">nowhere yet</span>
                        )}
                      </div>
                    </td>
                    <td className="faint">
                      {(template.secret_keys ?? []).length === 0
                        ? "—"
                        : (template.secret_keys ?? []).join(", ")}
                    </td>
                    <td className="actions">
                      <button className="small" onClick={() => setTargeting(template)}>
                        Apply to…
                      </button>{" "}
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            // The edit form needs the secrets, which the list
                            // deliberately leaves out.
                            setEditing(await api.template(template.id));
                          } catch (caught) {
                            setError(caught instanceof RequestError ? caught.message : String(caught));
                          }
                        }}
                      >
                        Edit
                      </button>{" "}
                      <button className="small danger" onClick={() => setDeleting(template)}>
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

      {editing && (
        <TemplateForm
          template={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            templates.reload();
          }}
        />
      )}

      {targeting && (
        <TargetPicker
          template={targeting}
          nodes={nodes.data?.nodes ?? []}
          groups={groups.data?.groups ?? []}
          onClose={() => setTargeting(null)}
          onSaved={() => {
            setTargeting(null);
            templates.reload();
          }}
        />
      )}

      {deleting && (
        <Confirm
          title={`Delete ${deleting.name}?`}
          danger
          confirmLabel="Delete"
          message="The inbounds this template created are removed from every node. Anyone connected through them is disconnected when xray-core restarts."
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const target = deleting;
            setDeleting(null);
            try {
              await api.deleteTemplate(target.id);
              templates.reload();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
    </>
  );
}

function TemplateForm({
  template,
  onClose,
  onSaved,
}: {
  template?: Template;
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const meta = useAsync(() => api.meta(), []);
  const [name, setName] = useState(template?.name ?? "");
  const [protocol, setProtocol] = useState<Protocol>(template?.protocol ?? "vless");
  const [network, setNetwork] = useState(template?.network ?? "raw");
  const [security, setSecurity] = useState<Security>(template?.security ?? "reality");
  const [port, setPort] = useState(String(template?.listen_port ?? 443));
  const [enabled, setEnabled] = useState(template?.enabled ?? true);
  const [params, setParams] = useState<Record<string, string>>(template?.params ?? {});
  const [secrets, setSecrets] = useState<Record<string, string>>(template?.secrets ?? {});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [publicKey, setPublicKey] = useState<string | null>(null);

  const setParam = (key: string, value: string) =>
    setParams((current) => ({ ...current, [key]: value }));
  const setSecret = (key: string, value: string) =>
    setSecrets((current) => ({ ...current, [key]: value }));

  const protocolMeta = meta.data?.protocols.find((entry) => entry.value === protocol);

  const save = async () => {
    setBusy(true);
    setError(null);
    const body = {
      name: name.trim(),
      protocol,
      network,
      security,
      listen_port: Number(port) || null,
      params,
      secrets,
      enabled,
    };
    try {
      if (template) await api.updateTemplate(template.id, body);
      else await api.createTemplate(body);
      onSaved();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={template ? `Edit ${template.name}` : "New template"}
      onClose={onClose}
      wide
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={save} disabled={busy || !name.trim()}>
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}

      <div className="grid cols-2">
        <Field label="Name">
          <input value={name} onChange={(event) => setName(event.target.value)} autoFocus />
        </Field>
        <Field label="Protocol">
          <select
            value={protocol}
            onChange={(event) => setProtocol(event.target.value as Protocol)}
            disabled={Boolean(template)}
          >
            {(meta.data?.protocols ?? [])
              // A DNS tunnel is per-node by nature: it forwards into an
              // inbound on its own node, so a template cannot describe it.
              .filter((entry) => entry.value !== "wndns")
              .map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {entry.label}
                </option>
              ))}
          </select>
        </Field>
        <Field label="Transport">
          <select value={network} onChange={(event) => setNetwork(event.target.value)}>
            {(protocolMeta?.networks ?? ["raw"]).map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Security">
          <select value={security} onChange={(event) => setSecurity(event.target.value as Security)}>
            {(protocolMeta?.securities ?? ["none"]).map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Port" help="A node can override this.">
          <input value={port} onChange={(event) => setPort(event.target.value)} inputMode="numeric" />
        </Field>
      </div>

      {security === "reality" && (
        <>
          <div className="grid cols-2">
            <Field label="Target" help="The real site unmatched traffic is handed to.">
              <input
                value={params.target ?? ""}
                onChange={(event) => setParam("target", event.target.value)}
                placeholder="www.microsoft.com:443"
              />
            </Field>
            <Field label="Server names">
              <input
                value={params.server_names ?? ""}
                onChange={(event) => setParam("server_names", event.target.value)}
                placeholder="www.microsoft.com"
              />
            </Field>
          </div>
          <Field label="Short IDs">
            <input
              value={params.short_ids ?? ""}
              onChange={(event) => setParam("short_ids", event.target.value)}
            />
          </Field>
          <Field
            label="Private key"
            help={
              template?.secret_keys?.includes("private_key")
                ? "A key is stored. Leave empty to keep it."
                : "Generate one — the client's public key is derived from it."
            }
          >
            <div className="field-row">
              <input
                value={secrets.private_key ?? ""}
                onChange={(event) => setSecret("private_key", event.target.value)}
              />
              <button
                type="button"
                className="small"
                onClick={async () => {
                  const keys = await api.generateReality();
                  setSecret("private_key", keys.private_key);
                  setPublicKey(keys.public_key);
                  setParam("short_ids", keys.short_ids.join(","));
                }}
              >
                Generate
              </button>
            </div>
          </Field>
          {publicKey && (
            <Banner kind="ok">
              Public key: <span className="mono">{publicKey}</span>
            </Banner>
          )}
          <Field label="Client fingerprint">
            <select value={params.fp ?? "chrome"} onChange={(event) => setParam("fp", event.target.value)}>
              {["chrome", "firefox", "safari", "ios", "android", "edge", "random"].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
        </>
      )}

      {security === "tls" && (
        <>
          <Field label="Server name (SNI)">
            <input value={params.sni ?? ""} onChange={(event) => setParam("sni", event.target.value)} />
          </Field>
          <Banner>
            A template shared by several nodes usually points at a certificate file each node
            manages itself, because one certificate rarely covers them all.
          </Banner>
          <Field label="Certificate file on the node">
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
            />
          </Field>
        </>
      )}

      {(network === "xhttp" || network === "ws" || network === "httpupgrade") && (
        <div className="grid cols-2">
          <Field label="Path">
            <input value={params.path ?? ""} onChange={(event) => setParam("path", event.target.value)} />
          </Field>
          <Field label="Host header">
            <input value={params.host ?? ""} onChange={(event) => setParam("host", event.target.value)} />
          </Field>
        </div>
      )}

      {(protocol === "shadowsocks" || protocol === "shadowsocks2022") && (
        <>
          <Field label="Method">
            <select value={params.method ?? ""} onChange={(event) => setParam("method", event.target.value)}>
              <option value="">Choose…</option>
              {(meta.data?.shadowsocks_methods ?? [])
                .filter((entry) => entry.protocol === protocol)
                .map((entry) => (
                  <option key={entry.value} value={entry.value}>
                    {entry.value}
                    {!entry.multiuser ? " (one user only)" : ""}
                  </option>
                ))}
            </select>
          </Field>
          <Field label={protocol === "shadowsocks2022" ? "Server key" : "Fallback password"}>
            <div className="field-row">
              <input
                value={secrets.password ?? ""}
                onChange={(event) => setSecret("password", event.target.value)}
              />
              <button
                type="button"
                className="small"
                onClick={async () => {
                  const result =
                    protocol === "shadowsocks2022"
                      ? await api.generateShadowsocks(params.method ?? "2022-blake3-aes-128-gcm")
                      : await api.generatePassword();
                  setSecret("password", "password" in result ? result.password : "");
                }}
              >
                Generate
              </button>
            </div>
          </Field>
        </>
      )}

      {protocol === "hysteria2" && (
        <>
          <Banner>Hysteria2 needs TLS. Each user's password is their own.</Banner>
          <div className="grid cols-2">
            <Field label="Server name (SNI)">
              <input value={params.sni ?? ""} onChange={(event) => setParam("sni", event.target.value)} />
            </Field>
            <Field label="Up / down, Mbit/s">
              <div className="field-row">
                <input
                  value={params.up_mbps ?? ""}
                  onChange={(event) => setParam("up_mbps", event.target.value)}
                  placeholder="up"
                  inputMode="numeric"
                />
                <input
                  value={params.down_mbps ?? ""}
                  onChange={(event) => setParam("down_mbps", event.target.value)}
                  placeholder="down"
                  inputMode="numeric"
                />
              </div>
            </Field>
          </div>
          <Field label="Certificate file on the node">
            <input
              value={params.cert_file ?? ""}
              onChange={(event) => setParam("cert_file", event.target.value)}
            />
          </Field>
          <Field label="Key file on the node">
            <input value={params.key_file ?? ""} onChange={(event) => setParam("key_file", event.target.value)} />
          </Field>
        </>
      )}

      <label className="checkline">
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        Enabled
      </label>
    </Modal>
  );
}

function TargetPicker({
  template,
  nodes,
  groups,
  onClose,
  onSaved,
}: {
  template: Template;
  nodes: Node[];
  groups: Group[];
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const [nodeIDs, setNodeIDs] = useState<number[]>(template.node_ids);
  const [groupIDs, setGroupIDs] = useState<number[]>(template.group_ids);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const toggle = (list: number[], id: number) =>
    list.includes(id) ? list.filter((value) => value !== id) : [...list, id];

  return (
    <Modal
      title={`Apply ${template.name}`}
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button
            className="primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await api.setTemplateTargets(template.id, nodeIDs, groupIDs);
                onSaved();
              } catch (caught) {
                setError(caught instanceof RequestError ? caught.message : String(caught));
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Applying…" : "Apply"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      <p className="muted" style={{ marginTop: 0 }}>
        A group keeps working as nodes are added to it: a new node gets this inbound without anyone
        coming back here. A node removed from the targets loses the inbound.
      </p>

      <Field label="Groups">
        <div className="chips">
          {groups.length === 0 ? (
            <span className="faint">No groups yet.</span>
          ) : (
            groups.map((group) => (
              <button
                key={group.id}
                type="button"
                className={groupIDs.includes(group.id) ? "chip on" : "chip"}
                onClick={() => setGroupIDs((current) => toggle(current, group.id))}
              >
                {group.name} <span className="faint">· {group.nodes ?? 0} node(s)</span>
              </button>
            ))
          )}
        </div>
      </Field>

      <Field label="Individual nodes">
        <div className="chips">
          {nodes.map((node) => (
            <button
              key={node.id}
              type="button"
              className={nodeIDs.includes(node.id) ? "chip on" : "chip"}
              onClick={() => setNodeIDs((current) => toggle(current, node.id))}
            >
              {node.name}
            </button>
          ))}
        </div>
      </Field>

      {template.protocol === "hysteria2" && (
        <Banner kind="warn">
          Hysteria2 needs a certificate on each node. Make sure every target has one at the path in
          the template, or it will fail to apply there.
        </Banner>
      )}
      <Pill>
        {groupIDs.length} group(s), {nodeIDs.length} node(s)
      </Pill>
    </Modal>
  );
}
