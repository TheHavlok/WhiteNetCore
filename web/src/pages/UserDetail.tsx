import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { api, RequestError } from "../api";
import type { Group, SubscriptionLinks, User, UserServer } from "../types";
import {
  Banner,
  Card,
  Confirm,
  CopyLine,
  Field,
  Modal,
  Pill,
  Spinner,
  formatBytes,
  formatDate,
  formatRelative,
  useAsync,
} from "../components/ui";
import { StatusPill, TrafficCell } from "./Users";

export default function UserDetail(): ReactNode {
  const params = useParams();
  const id = Number(params.id);

  const user = useAsync(() => api.user(id), [id]);
  const groups = useAsync(() => api.groups(), []);
  const devices = useAsync(() => api.devices(id), [id]);
  const subscription = useAsync(() => api.subscription(id), [id]);
  const servers = useAsync(() => api.userServers(id), [id]);
  const traffic = useAsync(() => api.userTraffic(id, 30), [id]);

  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<"reissue" | "reset" | "delete" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  if (user.error) return <Banner kind="error">{user.error}</Banner>;
  if (!user.data) return <Spinner />;

  const reloadAll = () => {
    user.reload();
    devices.reload();
    subscription.reload();
    servers.reload();
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{user.data.name}</h1>
          <div className="sub">
            <Link to="/users">Users</Link> · <span className="mono">{user.data.uuid}</span>
          </div>
        </div>
        <div className="actions">
          <StatusPill status={user.data.status} />
          <button onClick={() => setEditing(true)}>Edit</button>
        </div>
      </div>

      {error && <Banner kind="error">{error}</Banner>}
      {message && <Banner kind="ok">{message}</Banner>}

      <div className="grid cols-2">
        <Card title="Account">
          <dl className="kv">
            <dt>Comment</dt>
            <dd>{user.data.comment || <span className="faint">—</span>}</dd>
            <dt>Expires</dt>
            <dd>
              {user.data.expires_at ? (
                <>
                  {formatDate(user.data.expires_at)}{" "}
                  <span className="faint">
                    ({user.data.days_remaining}d {user.data.days_remaining! < 0 ? "ago" : "left"})
                  </span>
                </>
              ) : (
                <span className="faint">never</span>
              )}
            </dd>
            <dt>Traffic</dt>
            <dd>
              <TrafficCell user={user.data} />
            </dd>
            <dt>Devices</dt>
            <dd>
              {user.data.devices_used}
              {user.data.devices_limit > 0 ? ` of ${user.data.devices_limit}` : " (no limit)"}
            </dd>
            <dt>Groups</dt>
            <dd>
              {user.data.group_ids.length === 0 ? (
                <span className="faint">none — this user can reach no node</span>
              ) : (
                user.data.group_ids
                  .map(
                    (groupID) =>
                      (groups.data?.groups ?? []).find((group) => group.id === groupID)?.name ??
                      `#${groupID}`,
                  )
                  .join(", ")
              )}
            </dd>
            <dt>Traffic reset</dt>
            <dd>
              {user.data.reset_strategy}
              {user.data.last_reset_at && (
                <span className="faint"> · last {formatDate(user.data.last_reset_at)}</span>
              )}
            </dd>
            <dt>Created</dt>
            <dd>{formatDate(user.data.created_at)}</dd>
            <dt>Last fetched their subscription</dt>
            <dd>{formatRelative(user.data.last_sub_fetch_at)}</dd>
          </dl>
        </Card>

        <Card title="Subscription">
          {!subscription.data ? (
            <Spinner />
          ) : (
            <SubscriptionBlock links={subscription.data} />
          )}
          <div className="toolbar" style={{ marginTop: 14, marginBottom: 0 }}>
            <button onClick={() => setConfirm("reissue")}>Reissue the link</button>
            <button onClick={() => setConfirm("reset")}>Reset traffic</button>
            <div className="spacer" />
            <button className="danger" onClick={() => setConfirm("delete")}>
              Delete user
            </button>
          </div>
        </Card>
      </div>

      <Card
        title="Per-server links"
        actions={<button className="small" onClick={() => servers.reload()}>Refresh</button>}
      >
        <p className="muted" style={{ marginTop: 0 }}>
          One link per server this user can reach, rendered by the same code that answers their
          subscription - so what is listed here is exactly what the app would receive. A
          subscription link is the right thing for a real user; these are for trying a protocol,
          or handing one server to one person.
        </p>
        {servers.error ? (
          <Banner kind="error">{servers.error}</Banner>
        ) : !servers.data ? (
          <Spinner />
        ) : servers.data.servers.length === 0 ? (
          <div className="empty">
            Nothing to connect to yet. A server appears here once the user is in a group that has
            an online node with a published inbound - or a flux channel, or a DNS tunnel.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {servers.data.servers.map((server) => (
              <ServerLink key={server.id} server={server} />
            ))}
          </div>
        )}
      </Card>

      <Card title={`Devices (${devices.data?.devices.length ?? 0})`}>
        {!devices.data ? (
          <Spinner />
        ) : devices.data.devices.length === 0 ? (
          <div className="empty">
            No device has fetched this subscription yet. A device is recorded the first time the app
            asks, using the identifier it sends.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Platform</th>
                  <th>App</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                  <th>Address</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {devices.data.devices.map((device) => (
                  <tr key={device.id}>
                    <td>
                      {device.model || <span className="faint">unknown model</span>}
                      <div className="faint mono" style={{ fontSize: 11 }}>
                        {device.hwid}
                      </div>
                    </td>
                    <td>{device.platform || "—"}</td>
                    <td>{device.app_version || "—"}</td>
                    <td className="faint nowrap">{formatDate(device.first_seen_at)}</td>
                    <td className="faint nowrap">{formatRelative(device.last_seen_at)}</td>
                    <td className="mono">{device.last_ip || "—"}</td>
                    <td className="actions">
                      <button
                        className="small danger"
                        onClick={async () => {
                          try {
                            await api.deleteDevice(id, device.id);
                            devices.reload();
                            user.reload();
                          } catch (caught) {
                            setError(caught instanceof RequestError ? caught.message : String(caught));
                          }
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {user.data.devices_limit > 0 && user.data.devices_used >= user.data.devices_limit && (
          <Banner kind="warn">
            This user is at their device limit, so a new device is refused. Remove one to free a
            slot.
          </Banner>
        )}
      </Card>

      <Card title="Traffic, last 30 days">
        {!traffic.data ? (
          <Spinner />
        ) : traffic.data.days.length === 0 ? (
          <div className="empty">No traffic recorded yet.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Day</th>
                  <th className="right">Up</th>
                  <th className="right">Down</th>
                  <th className="right">Total</th>
                  <th style={{ width: "40%" }} />
                </tr>
              </thead>
              <tbody>
                {traffic.data.days
                  .slice()
                  .reverse()
                  .map((day) => {
                    const max = Math.max(...traffic.data!.days.map((entry) => entry.total), 1);
                    return (
                      <tr key={day.day}>
                        <td className="nowrap">{day.day}</td>
                        <td className="num">{formatBytes(day.uplink)}</td>
                        <td className="num">{formatBytes(day.downlink)}</td>
                        <td className="num">{formatBytes(day.total)}</td>
                        <td>
                          <div className="bar">
                            <i style={{ width: `${(day.total / max) * 100}%` }} />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {editing && (
        <EditUser
          user={user.data}
          groups={groups.data?.groups ?? []}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            reloadAll();
          }}
        />
      )}

      {confirm === "reissue" && (
        <Confirm
          title="Reissue the subscription link?"
          confirmLabel="Reissue"
          message="The current link stops working immediately and every device has to import the new one. This is how a leaked link is taken back."
          onCancel={() => setConfirm(null)}
          onConfirm={async () => {
            setConfirm(null);
            try {
              await api.reissueToken(id);
              setMessage("A new link was issued. The old one no longer works.");
              reloadAll();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
      {confirm === "reset" && (
        <Confirm
          title="Reset the traffic counter?"
          confirmLabel="Reset"
          message="The running total goes to zero. A user who was cut off for being over their limit becomes usable again. The daily history is kept."
          onCancel={() => setConfirm(null)}
          onConfirm={async () => {
            setConfirm(null);
            try {
              await api.resetTraffic(id);
              setMessage("The traffic counter was reset.");
              reloadAll();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
      {confirm === "delete" && (
        <Confirm
          title={`Delete ${user.data.name}?`}
          danger
          confirmLabel="Delete"
          message="Their subscription stops working at once, they are removed from every node, and their devices and history go with them."
          onCancel={() => setConfirm(null)}
          onConfirm={async () => {
            setConfirm(null);
            try {
              await api.deleteUser(id);
              window.location.href = "../users";
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
    </>
  );
}

function SubscriptionBlock({ links }: { links: SubscriptionLinks }): ReactNode {
  return (
    <>
      <Field label="Subscription link">
        <CopyLine value={links.url} />
      </Field>
      {links.deep_link ? (
        <Field
          label="Import link"
          help="Opens straight in the app. This is what the button on the subscription page uses."
        >
          <CopyLine value={links.deep_link} />
        </Field>
      ) : (
        <Banner kind="warn">
          No import link: {links.deep_link_error ?? "the subscription URL is not https"}. The link
          above still works; set an https subscription domain in Settings to get a deep link and a
          QR code.
        </Banner>
      )}
      {links.qr_png_base64 && (
        <div style={{ textAlign: "center", marginTop: 12 }}>
          <div className="qr-box">
            <img src={links.qr_png_base64} alt="Subscription QR code" />
          </div>
        </div>
      )}
    </>
  );
}

/** One server with its link. The endpoint is shown too, because a link is
 *  opaque and an operator checking a port should not have to decode one. */
function ServerLink({ server }: { server: UserServer }): ReactNode {
  const where = server.address ? `${server.address}:${server.port}` : "through a carrier";
  return (
    <div>
      <div className="row-head">
        <strong>{server.name}</strong>
        <Pill>{server.protocol}</Pill>
        {server.transport && <Pill>{server.transport}</Pill>}
        <span className="faint mono">{where}</span>
      </div>
      {server.link ? (
        <CopyLine value={server.link} />
      ) : (
        <Banner kind="warn">This server has no link: {server.error}</Banner>
      )}
    </div>
  );
}

function EditUser({
  user,
  groups,
  onClose,
  onSaved,
}: {
  user: User;
  groups: Group[];
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const [name, setName] = useState(user.name);
  const [comment, setComment] = useState(user.comment);
  const [status, setStatus] = useState(user.status);
  const [never, setNever] = useState(user.expires_at === null);
  const [expiresAt, setExpiresAt] = useState(
    user.expires_at ? user.expires_at.slice(0, 10) : "",
  );
  const [limitGB, setLimitGB] = useState(
    user.traffic_limit === 0 ? "0" : (user.traffic_limit / 1024 ** 3).toString(),
  );
  const [devices, setDevices] = useState(String(user.devices_limit));
  const [resetStrategy, setResetStrategy] = useState(user.reset_strategy);
  const [selected, setSelected] = useState<number[]>(user.group_ids);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError(null);
    const body: Record<string, unknown> = {
      name: name.trim(),
      comment,
      status,
      traffic_limit: Math.round((Number(limitGB) || 0) * 1024 ** 3),
      devices_limit: Number(devices) || 0,
      reset_strategy: resetStrategy,
      group_ids: selected,
    };
    // Two different intentions: never expires, or expires on a date. Sending
    // neither leaves it alone.
    if (never) body.clear_expiry = true;
    else if (expiresAt) body.expires_at = new Date(`${expiresAt}T23:59:59Z`).toISOString();

    try {
      await api.updateUser(user.id, body);
      onSaved();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Edit ${user.name}`}
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
      <Field label="Comment">
        <input value={comment} onChange={(event) => setComment(event.target.value)} />
      </Field>
      <Field
        label="Status"
        help="Expired and out-of-traffic are set by the panel itself; setting one by hand is unusual."
      >
        <select value={status} onChange={(event) => setStatus(event.target.value as typeof status)}>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="expired">Expired</option>
          <option value="limited">Out of traffic</option>
        </select>
      </Field>
      <Field label="Expiry">
        <label className="checkline" style={{ marginBottom: 6 }}>
          <input type="checkbox" checked={never} onChange={(event) => setNever(event.target.checked)} />
          Never expires
        </label>
        <input
          type="date"
          value={expiresAt}
          onChange={(event) => setExpiresAt(event.target.value)}
          disabled={never}
        />
      </Field>
      <div className="grid cols-2">
        <Field label="Traffic, GB" help="0 means no limit.">
          <input value={limitGB} onChange={(event) => setLimitGB(event.target.value)} inputMode="decimal" />
        </Field>
        <Field label="Devices" help="0 means no limit.">
          <input value={devices} onChange={(event) => setDevices(event.target.value)} inputMode="numeric" />
        </Field>
      </div>
      <Field
        label="Traffic reset"
        help="Only manual resets happen today; the other options are recorded for when scheduled resets arrive."
      >
        <select value={resetStrategy} onChange={(event) => setResetStrategy(event.target.value)}>
          <option value="manual">Manual</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
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
                    ? current.filter((groupID) => groupID !== group.id)
                    : [...current, group.id],
                )
              }
            >
              {group.name}
            </button>
          ))}
        </div>
      </Field>
    </Modal>
  );
}
