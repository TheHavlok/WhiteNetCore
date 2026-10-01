import { useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { api, RequestError } from "../api";
import type { Group, InstallCommand, Node } from "../types";
import {
  Banner,
  Card,
  CopyLine,
  Field,
  Modal,
  Pill,
  Spinner,
  formatBytes,
  formatDate,
  formatRelative,
  usePoll,
  useAsync,
} from "../components/ui";

export default function Nodes(): ReactNode {
  const nodes = usePoll(() => api.nodes(), 10000);
  const groups = useAsync(() => api.groups(), []);
  const [adding, setAdding] = useState(false);
  const [install, setInstall] = useState<{ node: Node; command: InstallCommand } | null>(null);

  const groupName = (id: number) =>
    groups.data?.groups.find((group) => group.id === id)?.name ?? `#${id}`;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Nodes</h1>
          <div className="sub">
            {nodes.data ? `${nodes.data.nodes.length} node(s)` : "Loading…"}
          </div>
        </div>
        <div className="actions">
          <button className="primary" onClick={() => setAdding(true)}>
            Add node
          </button>
        </div>
      </div>

      {nodes.error && <Banner kind="error">{nodes.error}</Banner>}

      <Card>
        {!nodes.data ? (
          <Spinner />
        ) : nodes.data.nodes.length === 0 ? (
          <div className="empty">
            No nodes yet. Add one and run the command it gives you on the server.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Node</th>
                  <th>Status</th>
                  <th>Groups</th>
                  <th className="right">Users</th>
                  <th>Cores</th>
                  <th>Flux</th>
                  <th>Last seen</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {nodes.data.nodes.map((node) => (
                  <tr key={node.id}>
                    <td>
                      <Link to={`/nodes/${node.id}`} style={{ fontWeight: 600 }}>
                        {node.country_code && `${flag(node.country_code)} `}
                        {node.name}
                      </Link>
                      <div className="faint mono">{node.address || "no address set"}</div>
                    </td>
                    <td>
                      <NodeStatusPill node={node} />
                      {!node.in_sync && (
                        <div className="faint" style={{ marginTop: 4 }}>
                          config {node.applied_version} of {node.config_version}
                        </div>
                      )}
                    </td>
                    <td>
                      <div className="chips">
                        {node.group_ids.length === 0 ? (
                          <span className="faint">none</span>
                        ) : (
                          node.group_ids.map((id) => (
                            <span key={id} className="chip">
                              {groupName(id)}
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                    <td className="num">{node.online_users}</td>
                    <td className="faint nowrap">
                      {node.xray_version ? `xray ${node.xray_version}` : "xray —"}
                      <br />
                      {node.agent_version ? `agent ${node.agent_version}` : "agent —"}
                    </td>
                    <td className="nowrap">
                      {node.flux_pool ? (
                        <>
                          {node.flux_pool.leased} / {node.flux_pool.total}
                          <div className="faint">{node.flux_pool.active_sessions} active</div>
                        </>
                      ) : (
                        <span className="faint">off</span>
                      )}
                    </td>
                    <td className="faint nowrap">{formatRelative(node.last_seen_at)}</td>
                    <td className="actions">
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            const command = await api.installCommand(node.id);
                            setInstall({ node, command });
                          } catch (caught) {
                            alert(caught instanceof RequestError ? caught.message : String(caught));
                          }
                        }}
                      >
                        Install command
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
        <AddNode
          groups={groups.data?.groups ?? []}
          onClose={() => setAdding(false)}
          onCreated={(node) => {
            setAdding(false);
            nodes.reload();
            if (node.install) setInstall({ node, command: node.install });
          }}
        />
      )}

      {install && (
        <InstallModal
          node={install.node}
          command={install.command}
          onClose={() => setInstall(null)}
        />
      )}
    </>
  );
}

export function NodeStatusPill({ node }: { node: Node }): ReactNode {
  if (!node.enabled) return <Pill dot>disabled</Pill>;
  if (node.status === "online") {
    return node.in_sync ? (
      <Pill kind="ok" dot>
        online
      </Pill>
    ) : (
      <Pill kind="warn" dot>
        syncing
      </Pill>
    );
  }
  if (node.status === "degraded") {
    return (
      <Pill kind="warn" dot>
        degraded
      </Pill>
    );
  }
  return (
    <Pill kind="bad" dot>
      offline
    </Pill>
  );
}

function AddNode({
  groups,
  onClose,
  onCreated,
}: {
  groups: Group[];
  onClose: () => void;
  onCreated: (node: Node) => void;
}): ReactNode {
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [country, setCountry] = useState("");
  const [selected, setSelected] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const node = await api.createNode({
        name: name.trim(),
        address: address.trim(),
        country_code: country.trim().toUpperCase(),
        group_ids: selected,
      });
      onCreated(node);
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Add node"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={submit} disabled={busy || !name.trim()}>
            {busy ? "Creating…" : "Create and show the command"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      <Field label="Name" help="Shown in the panel and, unless overridden, to users.">
        <input value={name} onChange={(event) => setName(event.target.value)} autoFocus />
      </Field>
      <Field
        label="Address clients dial"
        help="The public IP or host name. The agent reports what it sees, but this is what goes into subscriptions."
      >
        <input
          value={address}
          onChange={(event) => setAddress(event.target.value)}
          placeholder="203.0.113.9"
        />
      </Field>
      <Field label="Country" help="Two letters, for the flag in the client's list.">
        <input
          value={country}
          onChange={(event) => setCountry(event.target.value)}
          maxLength={2}
          placeholder="DE"
          style={{ width: 90 }}
        />
      </Field>
      <Field
        label="Groups"
        help="Users reach a node through its groups, and templates can be applied to a whole group."
      >
        <div className="chips">
          {groups.length === 0 ? (
            <span className="faint">No groups yet — create one first.</span>
          ) : (
            groups.map((group) => (
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
            ))
          )}
        </div>
      </Field>
    </Modal>
  );
}

function InstallModal({
  node,
  command,
  onClose,
}: {
  node: Node;
  command: InstallCommand;
  onClose: () => void;
}): ReactNode {
  return (
    <Modal
      title={`Install ${node.name}`}
      onClose={onClose}
      wide
      footer={<button className="primary" onClick={onClose}>Done</button>}
    >
      <p className="muted" style={{ margin: 0 }}>
        Run this as root on the server. It installs the agent and the cores, registers a systemd
        service and enrols the node.
      </p>
      <CopyLine value={command.command} label="Copy command" />
      <Banner kind="warn">
        The token works once and expires {formatDate(command.expires_at)}. If the command is lost,
        generate a new one — an unused token is not worth keeping.
      </Banner>
      <dl className="kv">
        <dt>Agent endpoint</dt>
        <dd className="mono">{command.main}</dd>
        <dt>CA fingerprint</dt>
        <dd className="mono">{command.ca_fingerprint}</dd>
        <dt>Script</dt>
        <dd className="mono">{command.script_url}</dd>
      </dl>
      <p className="faint" style={{ margin: 0 }}>
        The fingerprint is how the node verifies this panel before it sends anything, so the command
        has to be copied whole.
      </p>
    </Modal>
  );
}

/** flag turns a country code into its emoji, so the list reads at a glance. */
export function flag(code: string): string {
  if (code.length !== 2) return "";
  const base = 0x1f1e6;
  const upper = code.toUpperCase();
  const first = upper.codePointAt(0);
  const second = upper.codePointAt(1);
  if (first === undefined || second === undefined) return "";
  return String.fromCodePoint(base + (first - 65), base + (second - 65));
}

export { formatBytes };
