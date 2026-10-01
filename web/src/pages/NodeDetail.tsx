import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { api, RequestError } from "../api";
import type { Channel, Group, Inbound, MetricPoint, Node } from "../types";
import {
  Banner,
  Card,
  Confirm,
  Field,
  LineChart,
  Modal,
  Pill,
  Spinner,
  formatBytes,
  formatDate,
  formatDuration,
  formatRelative,
  useAsync,
  usePoll,
} from "../components/ui";
import { NodeStatusPill, flag } from "./Nodes";
import InboundForm from "./InboundForm";
import FluxPanel from "./FluxPanel";

type Tab = "overview" | "inbounds" | "flux" | "metrics" | "logs";

// Spelled out rather than capitalised from the key: "Flux" alone did not tell
// an operator that this is where OpenFlux is configured, and the DNS tunnel
// being a protocol under Inbounds is not obvious either.
const tabLabels: Record<Tab, string> = {
  overview: "Overview",
  inbounds: "Inbounds & DNS tunnel",
  flux: "OpenFlux channels",
  metrics: "Metrics",
  logs: "Logs",
};

export default function NodeDetail(): ReactNode {
  const params = useParams();
  const id = Number(params.id);
  const [tab, setTab] = useState<Tab>("overview");

  const node = usePoll(() => api.node(id), 10000, [id]);
  const groups = useAsync(() => api.groups(), []);

  if (node.error) return <Banner kind="error">{node.error}</Banner>;
  if (!node.data) return <Spinner />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>
            {node.data.country_code && `${flag(node.data.country_code)} `}
            {node.data.name}
          </h1>
          <div className="sub">
            <Link to="/nodes">Nodes</Link> · <span className="mono">{node.data.uuid}</span>
          </div>
        </div>
        <div className="actions">
          <NodeStatusPill node={node.data} />
        </div>
      </div>

      {node.data.apply_error && (
        <Banner kind="error">
          This node could not apply its configuration: {node.data.apply_error}
        </Banner>
      )}
      {node.data.status_reason && node.data.status === "degraded" && (
        <Banner kind="warn">{node.data.status_reason}</Banner>
      )}

      <div className="tabs">
        {(["overview", "inbounds", "flux", "metrics", "logs"] as Tab[]).map((name) => (
          <button
            key={name}
            className={tab === name ? "tab active" : "tab"}
            onClick={() => setTab(name)}
          >
            {tabLabels[name]}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <Overview node={node.data} groups={groups.data?.groups ?? []} onChanged={node.reload} />
      )}
      {tab === "inbounds" && <InboundsTab node={node.data} />}
      {tab === "flux" && <FluxPanel node={node.data} />}
      {tab === "metrics" && <MetricsTab node={node.data} />}
      {tab === "logs" && <LogsTab node={node.data} />}
    </>
  );
}

// --------------------------------------------------------------- overview

function Overview({
  node,
  groups,
  onChanged,
}: {
  node: Node;
  groups: Group[];
  onChanged: () => void;
}): ReactNode {
  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<"delete" | "revoke" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (what: string, action: () => Promise<unknown>) => {
    setError(null);
    setMessage(null);
    try {
      await action();
      setMessage(what);
      onChanged();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    }
  };

  return (
    <>
      {message && <Banner kind="ok">{message}</Banner>}
      {error && <Banner kind="error">{error}</Banner>}

      <div className="grid cols-2">
        <Card title="Node" actions={<button className="small" onClick={() => setEditing(true)}>Edit</button>}>
          <dl className="kv">
            <dt>Address clients dial</dt>
            <dd className="mono">{node.address || <span className="faint">not set</span>}</dd>
            <dt>Shown to users as</dt>
            <dd>{node.display_name || node.name}</dd>
            <dt>Groups</dt>
            <dd>
              {node.group_ids.length === 0 ? (
                <span className="faint">none — no user can reach this node</span>
              ) : (
                node.group_ids
                  .map((id) => groups.find((group) => group.id === id)?.name ?? `#${id}`)
                  .join(", ")
              )}
            </dd>
            <dt>Enabled</dt>
            <dd>{node.enabled ? "yes" : "no"}</dd>
            <dt>Notes</dt>
            <dd>{node.notes || <span className="faint">—</span>}</dd>
          </dl>
        </Card>

        <Card title="Agent">
          <dl className="kv">
            <dt>Connection</dt>
            <dd>
              {node.connected ? "connected" : "not connected"}
              {node.connected_at && <span className="faint"> since {formatDate(node.connected_at)}</span>}
            </dd>
            <dt>Last heartbeat</dt>
            <dd>{formatRelative(node.last_seen_at)}</dd>
            <dt>Configuration</dt>
            <dd>
              applied {node.applied_version} of {node.config_version}{" "}
              {node.in_sync ? (
                <Pill kind="ok">in sync</Pill>
              ) : (
                <Pill kind="warn">waiting</Pill>
              )}
            </dd>
            <dt>Agent</dt>
            <dd className="mono">{node.agent_version || "—"}</dd>
            <dt>xray-core</dt>
            <dd className="mono">{node.xray_version || "—"}</dd>
            <dt>DNS tunnel</dt>
            <dd className="mono">{node.wndns_version || "—"}</dd>
            <dt>Flux</dt>
            <dd className="mono">{node.openflux_version || "—"}</dd>
            <dt>Host</dt>
            <dd>
              {node.hostname || "—"} · {node.os || "?"}/{node.arch || "?"} ·{" "}
              {node.cpu_cores ?? "?"} core(s) · {formatBytes(node.mem_total_bytes)}
            </dd>
          </dl>
        </Card>
      </div>

      <Card title="Actions">
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <button
            disabled={!node.connected}
            onClick={() => run("Restarting xray-core.", () => api.restartCore(node.id, "xray"))}
          >
            Restart xray-core
          </button>
          <button
            disabled={!node.connected}
            onClick={() => run("Restarting the DNS tunnel.", () => api.restartCore(node.id, "wndns"))}
          >
            Restart the DNS tunnel
          </button>
          <button
            disabled={!node.connected}
            onClick={() => run("Restarting the flux channels.", () => api.restartCore(node.id, "openflux"))}
          >
            Restart flux
          </button>
          <button onClick={() => run("The node will re-apply its whole configuration.", () => api.resyncNode(node.id))}>
            Re-apply configuration
          </button>
          <div className="spacer" />
          <button className="danger" onClick={() => setConfirm("revoke")}>
            Revoke certificate
          </button>
          <button className="danger" onClick={() => setConfirm("delete")}>
            Delete node
          </button>
        </div>
        {!node.connected && (
          <p className="faint" style={{ marginBottom: 0 }}>
            Restarts need a connected agent. A configuration change is kept and applied when the
            node comes back.
          </p>
        )}
      </Card>

      {editing && (
        <EditNode
          node={node}
          groups={groups}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            onChanged();
          }}
        />
      )}

      {confirm === "revoke" && (
        <Confirm
          title="Revoke this node's certificate?"
          danger
          confirmLabel="Revoke"
          message="The agent is disconnected and refused until the node is enrolled again. Its configuration is kept, so a fresh install command brings it straight back."
          onCancel={() => setConfirm(null)}
          onConfirm={async () => {
            setConfirm(null);
            await run("The certificate was revoked.", () => api.revokeNode(node.id));
          }}
        />
      )}
      {confirm === "delete" && (
        <Confirm
          title={`Delete ${node.name}?`}
          danger
          confirmLabel="Delete"
          message="The node, its inbounds, its flux channels and its history are removed. Users who only reached this node lose access. This cannot be undone."
          onCancel={() => setConfirm(null)}
          onConfirm={async () => {
            setConfirm(null);
            try {
              await api.deleteNode(node.id);
              window.location.href = "../nodes";
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
    </>
  );
}

function EditNode({
  node,
  groups,
  onClose,
  onSaved,
}: {
  node: Node;
  groups: Group[];
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const [name, setName] = useState(node.name);
  const [displayName, setDisplayName] = useState(node.display_name);
  const [address, setAddress] = useState(node.address);
  const [country, setCountry] = useState(node.country_code);
  const [notes, setNotes] = useState(node.notes);
  const [enabled, setEnabled] = useState(node.enabled);
  const [selected, setSelected] = useState<number[]>(node.group_ids);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.updateNode(node.id, {
        name: name.trim(),
        display_name: displayName.trim(),
        address: address.trim(),
        country_code: country.trim().toUpperCase(),
        notes,
        enabled,
        group_ids: selected,
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
      title={`Edit ${node.name}`}
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      <Field label="Name">
        <input value={name} onChange={(event) => setName(event.target.value)} />
      </Field>
      <Field label="Shown to users as" help="Leave empty to use the name.">
        <input value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
      </Field>
      <Field
        label="Address clients dial"
        help="Never overwritten by what the agent reports: a node behind a proxy or with a vanity domain would break."
      >
        <input value={address} onChange={(event) => setAddress(event.target.value)} />
      </Field>
      <Field label="Country">
        <input
          value={country}
          onChange={(event) => setCountry(event.target.value)}
          maxLength={2}
          style={{ width: 90 }}
        />
      </Field>
      <Field label="Groups">
        <div className="chips">
          {groups.map((group) => (
            <button
              key={group.id}
              type="button"
              className={selected.includes(group.id) ? "chip on" : "chip"}
              onClick={() =>
                setSelected((current) =>
                  current.includes(group.id)
                    ? current.filter((id) => id !== group.id)
                    : [...current, group.id],
                )
              }
            >
              {group.name}
            </button>
          ))}
        </div>
      </Field>
      <Field label="Notes">
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)} />
      </Field>
      <label className="checkline">
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        Enabled — when off, the node stops serving and is left out of subscriptions
      </label>
    </Modal>
  );
}

// --------------------------------------------------------------- inbounds

function InboundsTab({ node }: { node: Node }): ReactNode {
  const inbounds = useAsync(() => api.inbounds(node.id), [node.id]);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Inbound | null>(null);
  const [deleting, setDeleting] = useState<Inbound | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <>
      {error && <Banner kind="error">{error}</Banner>}
      <Card
        title="Inbounds on this node"
        actions={
          <button className="primary small" onClick={() => setAdding(true)}>
            Add inbound
          </button>
        }
      >
        {!inbounds.data ? (
          <Spinner />
        ) : inbounds.data.inbounds.length === 0 ? (
          <div className="empty">
            Nothing here. Add an inbound, or apply a template to this node from the Inbounds page.
            Every protocol lives here, including the WhiteNet DNS tunnel - pick it as the protocol
            on the add form. OpenFlux is the one exception: it has its own tab, because it has
            channels rather than a port.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tag</th>
                  <th>Protocol</th>
                  <th>Listen</th>
                  <th>Source</th>
                  <th>In subscriptions</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {inbounds.data.inbounds.map((inbound) => (
                  <tr key={inbound.id}>
                    <td className="mono">{inbound.tag}</td>
                    <td>
                      {inbound.protocol}
                      {inbound.security !== "none" && (
                        <span className="faint"> · {inbound.security}</span>
                      )}
                      {inbound.network && <span className="faint"> · {inbound.network}</span>}
                      {inbound.forward_to_tag && (
                        <div className="faint">forwards into {inbound.forward_to_tag}</div>
                      )}
                    </td>
                    <td className="mono nowrap">
                      {inbound.listen_address || "*"}:{inbound.listen_port}
                    </td>
                    <td>
                      {inbound.from_template ? (
                        <Pill kind="accent">template</Pill>
                      ) : (
                        <span className="faint">this node only</span>
                      )}
                    </td>
                    <td>
                      {inbound.published ? (
                        "yes"
                      ) : (
                        <span className="faint">no — internal</span>
                      )}
                    </td>
                    <td className="actions">
                      <button className="small" onClick={() => setEditing(inbound)}>
                        Edit
                      </button>{" "}
                      <button className="small danger" onClick={() => setDeleting(inbound)}>
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
        <InboundForm
          nodeID={node.id}
          existing={inbounds.data?.inbounds ?? []}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            inbounds.reload();
          }}
        />
      )}
      {editing && (
        <InboundForm
          nodeID={node.id}
          inbound={editing}
          existing={inbounds.data?.inbounds ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            inbounds.reload();
          }}
        />
      )}
      {deleting && (
        <Confirm
          title={`Delete ${deleting.tag}?`}
          danger
          confirmLabel="Delete"
          message={
            deleting.from_template
              ? "This inbound comes from a template. Deleting it here removes it from this node only, and applying the template again will bring it back."
              : "Everyone connected through this inbound is disconnected when xray-core restarts."
          }
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const target = deleting;
            setDeleting(null);
            try {
              await api.deleteInbound(target.id);
              inbounds.reload();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------- metrics

function MetricsTab({ node }: { node: Node }): ReactNode {
  const [window, setWindow] = useState<"hour" | "day" | "week">("hour");
  const metrics = usePoll(() => api.nodeMetrics(node.id, window), 30000, [node.id, window]);
  const traffic = useAsync(() => api.nodeTraffic(node.id, 30), [node.id]);

  const points = metrics.data?.points ?? [];
  const series = (pick: (point: MetricPoint) => number | null) =>
    points.map((point) => ({ at: point.at, value: pick(point) }));

  const latest = points[points.length - 1];

  return (
    <>
      <div className="toolbar">
        {(["hour", "day", "week"] as const).map((name) => (
          <button
            key={name}
            className={window === name ? "primary small" : "small"}
            onClick={() => setWindow(name)}
          >
            {name === "hour" ? "Last hour" : name === "day" ? "Last day" : "Last week"}
          </button>
        ))}
        <div className="spacer" />
        <span className="faint">
          {metrics.data?.resolution === "hourly" ? "hourly averages" : "raw samples"}
        </span>
      </div>

      {metrics.error && <Banner kind="error">{metrics.error}</Banner>}

      {latest && (
        <div className="grid cols-4" style={{ marginBottom: 14 }}>
          <div className="card stat">
            <div className="label">CPU</div>
            <div className="value">
              {latest.cpu_percent === null ? "—" : `${latest.cpu_percent.toFixed(0)}%`}
            </div>
          </div>
          <div className="card stat">
            <div className="label">Memory</div>
            <div className="value">{formatBytes(latest.mem_used)}</div>
            <div className="hint">of {formatBytes(latest.mem_total ?? node.mem_total_bytes)}</div>
          </div>
          <div className="card stat">
            <div className="label">Disk</div>
            <div className="value">{formatBytes(latest.disk_used)}</div>
            <div className="hint">of {formatBytes(latest.disk_total)}</div>
          </div>
          <div className="card stat">
            <div className="label">Uptime</div>
            <div className="value">{formatDuration(latest.uptime)}</div>
            <div className="hint">{latest.tcp_conns ?? 0} connections</div>
          </div>
        </div>
      )}

      <div className="grid cols-2">
        <Card title="CPU">
          <LineChart
            points={series((point) => point.cpu_percent)}
            format={(value) => `${Math.round(value)}%`}
            max={100}
          />
        </Card>
        <Card title="Memory used">
          <LineChart points={series((point) => point.mem_used)} format={formatBytes} />
        </Card>
        <Card title="Users online">
          <LineChart
            points={series((point) => point.online_users)}
            format={(value) => String(Math.round(value))}
          />
        </Card>
        <Card title="Network, bytes in">
          <LineChart
            points={series((point) =>
              point.net_rx_delta !== undefined && point.net_rx_delta !== null
                ? point.net_rx_delta
                : point.net_rx,
            )}
            format={formatBytes}
          />
        </Card>
      </div>

      <Card title="Traffic by day, this node">
        {!traffic.data ? (
          <Spinner />
        ) : (
          <TrafficBars days={traffic.data.days} />
        )}
      </Card>
    </>
  );
}

function TrafficBars({ days }: { days: { day: string; total: number }[] }): ReactNode {
  if (days.length === 0) return <div className="empty">No traffic recorded yet.</div>;
  const max = Math.max(...days.map((day) => day.total), 1);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Day</th>
            <th>Total</th>
            <th style={{ width: "50%" }} />
          </tr>
        </thead>
        <tbody>
          {days
            .slice()
            .reverse()
            .map((day) => (
              <tr key={day.day}>
                <td className="nowrap">{day.day}</td>
                <td className="num">{formatBytes(day.total)}</td>
                <td>
                  <div className="bar">
                    <i style={{ width: `${(day.total / max) * 100}%` }} />
                  </div>
                </td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}

// ------------------------------------------------------------------- logs

function LogsTab({ node }: { node: Node }): ReactNode {
  const [core, setCore] = useState("xray");
  const [lines, setLines] = useState(300);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const fetchLog = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.nodeLogs(node.id, core, lines);
      setText(result.text || "(the log is empty)");
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
      setText(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Node logs">
      <div className="toolbar">
        <select value={core} onChange={(event) => setCore(event.target.value)}>
          <option value="xray">xray-core</option>
          <option value="wndns">DNS tunnel</option>
          <option value="openflux">agent and flux</option>
        </select>
        <select value={lines} onChange={(event) => setLines(Number(event.target.value))}>
          <option value={100}>100 lines</option>
          <option value={300}>300 lines</option>
          <option value={1000}>1000 lines</option>
        </select>
        <button className="primary" onClick={fetchLog} disabled={busy || !node.connected}>
          {busy ? "Fetching…" : "Fetch"}
        </button>
        {!node.connected && (
          <span className="faint">Logs are pulled from the node, so it has to be connected.</span>
        )}
      </div>
      {error && <Banner kind="error">{error}</Banner>}
      {text !== null && <pre className="logs">{text}</pre>}
    </Card>
  );
}

export type { Channel };
