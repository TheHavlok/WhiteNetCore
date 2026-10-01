import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api, RequestError } from "../api";
import type { Group, User, UserStatus } from "../types";
import {
  Banner,
  Card,
  Confirm,
  Field,
  Modal,
  Pill,
  Spinner,
  formatBytes,
  formatRelative,
  useAsync,
} from "../components/ui";

const PAGE = 50;

export default function Users(): ReactNode {
  const [searchParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [groupID, setGroupID] = useState(0);
  const [expiring, setExpiring] = useState(Number(searchParams.get("expiring") ?? 0));
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<number[]>([]);
  const [creating, setCreating] = useState(false);
  const [bulk, setBulk] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const groups = useAsync(() => api.groups(), []);
  const users = useAsync(
    () =>
      api.users({
        search,
        status,
        group_id: groupID || undefined,
        expiring_in_days: expiring || undefined,
        limit: PAGE,
        offset,
      }),
    [search, status, groupID, expiring, offset],
  );

  const list = users.data?.users ?? [];
  const total = users.data?.total ?? 0;
  const allSelected = list.length > 0 && list.every((user) => selected.includes(user.id));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Users</h1>
          <div className="sub">{users.data ? `${total} user(s)` : "Loading…"}</div>
        </div>
        <div className="actions">
          <button className="primary" onClick={() => setCreating(true)}>
            Add user
          </button>
        </div>
      </div>

      {error && <Banner kind="error">{error}</Banner>}
      {users.error && <Banner kind="error">{users.error}</Banner>}

      <Card>
        <div className="toolbar">
          <input
            placeholder="Search name or comment"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setOffset(0);
            }}
            style={{ minWidth: 220 }}
          />
          <select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any status</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
            <option value="expired">Expired</option>
            <option value="limited">Out of traffic</option>
          </select>
          <select
            value={groupID}
            onChange={(event) => {
              setGroupID(Number(event.target.value));
              setOffset(0);
            }}
          >
            <option value={0}>Any group</option>
            {(groups.data?.groups ?? []).map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
          <select
            value={expiring}
            onChange={(event) => {
              setExpiring(Number(event.target.value));
              setOffset(0);
            }}
          >
            <option value={0}>Any expiry</option>
            <option value={3}>Expiring in 3 days</option>
            <option value={7}>Expiring in a week</option>
            <option value={30}>Expiring in a month</option>
          </select>
          <div className="spacer" />
          {selected.length > 0 && (
            <>
              <span className="faint">{selected.length} selected</span>
              <button onClick={() => setBulk(true)}>Act on them…</button>
              <button className="ghost" onClick={() => setSelected([])}>
                Clear
              </button>
            </>
          )}
        </div>

        {!users.data ? (
          <Spinner />
        ) : list.length === 0 ? (
          <div className="empty">No user matches this filter.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 28 }}>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={(event) =>
                        setSelected(event.target.checked ? list.map((user) => user.id) : [])
                      }
                      aria-label="Select all on this page"
                    />
                  </th>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Expires</th>
                  <th>Traffic</th>
                  <th className="right">Devices</th>
                  <th>Groups</th>
                  <th>Last fetch</th>
                </tr>
              </thead>
              <tbody>
                {list.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selected.includes(user.id)}
                        onChange={(event) =>
                          setSelected((current) =>
                            event.target.checked
                              ? [...current, user.id]
                              : current.filter((id) => id !== user.id),
                          )
                        }
                        aria-label={`Select ${user.name}`}
                      />
                    </td>
                    <td>
                      <Link to={`/users/${user.id}`} style={{ fontWeight: 600 }}>
                        {user.name}
                      </Link>
                      {user.comment && <div className="faint">{user.comment}</div>}
                    </td>
                    <td>
                      <StatusPill status={user.status} />
                    </td>
                    <td className="nowrap">
                      {user.days_remaining === null ? (
                        <span className="faint">never</span>
                      ) : user.days_remaining < 0 ? (
                        <span style={{ color: "var(--bad)" }}>expired</span>
                      ) : (
                        `${user.days_remaining}d`
                      )}
                    </td>
                    <td style={{ minWidth: 160 }}>
                      <TrafficCell user={user} />
                    </td>
                    <td className="num">
                      {user.devices_used}
                      {user.devices_limit > 0 && <span className="faint"> / {user.devices_limit}</span>}
                    </td>
                    <td className="faint">
                      {user.group_ids
                        .map(
                          (id) =>
                            (groups.data?.groups ?? []).find((group) => group.id === id)?.name ??
                            `#${id}`,
                        )
                        .join(", ") || "none"}
                    </td>
                    <td className="faint nowrap">{formatRelative(user.last_sub_fetch_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {total > PAGE && (
          <div className="toolbar" style={{ marginTop: 12, marginBottom: 0 }}>
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              Previous
            </button>
            <span className="faint">
              {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
            </span>
            <button disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
              Next
            </button>
          </div>
        )}
      </Card>

      {creating && (
        <CreateUser
          groups={groups.data?.groups ?? []}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            users.reload();
          }}
        />
      )}

      {bulk && (
        <BulkActions
          count={selected.length}
          groups={groups.data?.groups ?? []}
          onClose={() => setBulk(false)}
          onDone={() => {
            setBulk(false);
            setSelected([]);
            users.reload();
          }}
          onError={setError}
          userIDs={selected}
        />
      )}
    </>
  );
}

export function StatusPill({ status }: { status: UserStatus }): ReactNode {
  switch (status) {
    case "active":
      return (
        <Pill kind="ok" dot>
          active
        </Pill>
      );
    case "disabled":
      return <Pill dot>disabled</Pill>;
    case "expired":
      return (
        <Pill kind="bad" dot>
          expired
        </Pill>
      );
    case "limited":
      return (
        <Pill kind="warn" dot>
          out of traffic
        </Pill>
      );
  }
}

export function TrafficCell({ user }: { user: User }): ReactNode {
  if (user.traffic_limit === 0) {
    return (
      <>
        {formatBytes(user.traffic_used)}
        <div className="faint">no limit</div>
      </>
    );
  }
  const percent = Math.min(100, Math.round((user.traffic_used / user.traffic_limit) * 100));
  return (
    <>
      <div className="tabular">
        {formatBytes(user.traffic_used)} <span className="faint">/ {formatBytes(user.traffic_limit)}</span>
      </div>
      <div className={percent >= 90 ? "bar bad" : percent >= 75 ? "bar warn" : "bar"}>
        <i style={{ width: `${percent}%` }} />
      </div>
    </>
  );
}

function CreateUser({
  groups,
  onClose,
  onCreated,
}: {
  groups: Group[];
  onClose: () => void;
  onCreated: () => void;
}): ReactNode {
  const [name, setName] = useState("");
  const [comment, setComment] = useState("");
  const [days, setDays] = useState("30");
  const [limitGB, setLimitGB] = useState("100");
  const [devices, setDevices] = useState("3");
  const [selected, setSelected] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.createUser({
        name: name.trim(),
        comment: comment.trim(),
        valid_days: Number(days) || 0,
        // The form asks for gigabytes because that is how anyone thinks about
        // an allowance; the API stores bytes.
        traffic_limit: Math.round((Number(limitGB) || 0) * 1024 * 1024 * 1024),
        devices_limit: Number(devices) || 0,
        group_ids: selected,
      });
      onCreated();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Add user"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={submit} disabled={busy || !name.trim()}>
            {busy ? "Creating…" : "Create"}
          </button>
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      <Field label="Name">
        <input value={name} onChange={(event) => setName(event.target.value)} autoFocus />
      </Field>
      <Field label="Comment" help="Only you see this.">
        <input value={comment} onChange={(event) => setComment(event.target.value)} />
      </Field>
      <div className="grid cols-3">
        <Field label="Valid for, days" help="0 means never expires.">
          <input value={days} onChange={(event) => setDays(event.target.value)} inputMode="numeric" />
        </Field>
        <Field label="Traffic, GB" help="0 means no limit.">
          <input value={limitGB} onChange={(event) => setLimitGB(event.target.value)} inputMode="decimal" />
        </Field>
        <Field label="Devices" help="0 means no limit.">
          <input value={devices} onChange={(event) => setDevices(event.target.value)} inputMode="numeric" />
        </Field>
      </div>
      <Field
        label="Groups"
        help="A user reaches only the nodes in their groups. With none, they get an empty subscription."
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
      <p className="faint" style={{ margin: 0 }}>
        Anything left empty comes from the defaults in Settings. Credentials and a subscription link
        are generated automatically.
      </p>
    </Modal>
  );
}

function BulkActions({
  count,
  userIDs,
  groups,
  onClose,
  onDone,
  onError,
}: {
  count: number;
  userIDs: number[];
  groups: Group[];
  onClose: () => void;
  onDone: () => void;
  onError: (message: string) => void;
}): ReactNode {
  const [action, setAction] = useState("extend");
  const [days, setDays] = useState("30");
  const [groupIDs, setGroupIDs] = useState<number[]>([]);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      await api.bulkUsers({
        user_ids: userIDs,
        action,
        extend_days: action === "extend" ? Number(days) || 0 : undefined,
        group_ids: action === "set_groups" ? groupIDs : undefined,
      });
      onDone();
    } catch (caught) {
      onError(caught instanceof RequestError ? caught.message : String(caught));
      onClose();
    } finally {
      setBusy(false);
    }
  };

  if (confirming) {
    return (
      <Confirm
        title={`Delete ${count} user(s)?`}
        danger
        confirmLabel="Delete them"
        message="Their subscriptions stop working at once and their history goes with them. This cannot be undone."
        onCancel={() => setConfirming(false)}
        onConfirm={run}
      />
    );
  }

  return (
    <Modal
      title={`${count} user(s) selected`}
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>Cancel</button>
          <button
            className={action === "delete" ? "danger" : "primary"}
            disabled={busy}
            onClick={() => (action === "delete" ? setConfirming(true) : run())}
          >
            {busy ? "Working…" : "Apply"}
          </button>
        </>
      }
    >
      <Field label="What to do">
        <select value={action} onChange={(event) => setAction(event.target.value)}>
          <option value="extend">Extend their expiry</option>
          <option value="enable">Enable</option>
          <option value="disable">Disable</option>
          <option value="reset_traffic">Reset their traffic counter</option>
          <option value="set_groups">Replace their groups</option>
          <option value="delete">Delete</option>
        </select>
      </Field>

      {action === "extend" && (
        <Field
          label="By how many days"
          help="A user who already expired is extended from today, not from a date in the past."
        >
          <input value={days} onChange={(event) => setDays(event.target.value)} inputMode="numeric" />
        </Field>
      )}

      {action === "set_groups" && (
        <Field label="Groups" help="This replaces whatever they had.">
          <div className="chips">
            {groups.map((group) => (
              <button
                key={group.id}
                type="button"
                className={groupIDs.includes(group.id) ? "chip on" : "chip"}
                onClick={() =>
                  setGroupIDs((current) =>
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
      )}

      {action === "disable" && (
        <Banner>
          Disabled users are removed from every node and lose any flux channel they hold.
        </Banner>
      )}
    </Modal>
  );
}
