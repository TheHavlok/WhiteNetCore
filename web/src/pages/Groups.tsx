import { useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import type { Group } from "../types";
import { Banner, Card, Confirm, Field, Modal, Spinner, useAsync } from "../components/ui";

/**
 * Groups is the only thing that connects users to nodes.
 *
 * A user reaches a node when they share a group with it, and a template can be
 * applied to a whole group. That makes groups the unit of access, which is
 * worth saying on the page.
 */
export default function Groups(): ReactNode {
  const groups = useAsync(() => api.groups(), []);
  const [editing, setEditing] = useState<Group | "new" | null>(null);
  const [deleting, setDeleting] = useState<Group | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Groups</h1>
          <div className="sub">
            A user reaches the nodes in their groups, and nothing else.
          </div>
        </div>
        <div className="actions">
          <button className="primary" onClick={() => setEditing("new")}>
            New group
          </button>
        </div>
      </div>

      {error && <Banner kind="error">{error}</Banner>}

      <Card>
        {!groups.data ? (
          <Spinner />
        ) : groups.data.groups.length === 0 ? (
          <div className="empty">
            No groups yet. Create one — without a group, a node serves nobody and a user reaches
            nothing.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th className="right">Nodes</th>
                  <th className="right">Users</th>
                  <th className="right">Order</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {groups.data.groups.map((group) => (
                  <tr key={group.id}>
                    <td style={{ fontWeight: 600 }}>{group.name}</td>
                    <td className="faint">{group.description || "—"}</td>
                    <td className="num">{group.nodes ?? 0}</td>
                    <td className="num">{group.users ?? 0}</td>
                    <td className="num">{group.sort_order}</td>
                    <td className="actions">
                      <button className="small" onClick={() => setEditing(group)}>
                        Edit
                      </button>{" "}
                      <button className="small danger" onClick={() => setDeleting(group)}>
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
        <GroupForm
          group={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            groups.reload();
          }}
        />
      )}

      {deleting && (
        <Confirm
          title={`Delete ${deleting.name}?`}
          danger
          confirmLabel="Delete"
          message={
            <>
              <p style={{ marginTop: 0 }}>
                {deleting.users ?? 0} user(s) and {deleting.nodes ?? 0} node(s) are in this group.
              </p>
              <p style={{ marginBottom: 0 }}>
                Users who reached a node only through this group lose access to it, and templates
                applied to this group stop applying.
              </p>
            </>
          }
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const target = deleting;
            setDeleting(null);
            try {
              await api.deleteGroup(target.id);
              groups.reload();
            } catch (caught) {
              setError(caught instanceof RequestError ? caught.message : String(caught));
            }
          }}
        />
      )}
    </>
  );
}

function GroupForm({
  group,
  onClose,
  onSaved,
}: {
  group?: Group;
  onClose: () => void;
  onSaved: () => void;
}): ReactNode {
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [sortOrder, setSortOrder] = useState(String(group?.sort_order ?? 0));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (group) {
        await api.updateGroup(group.id, {
          name: name.trim(),
          description,
          sort_order: Number(sortOrder) || 0,
        });
      } else {
        await api.createGroup({
          name: name.trim(),
          description,
          sort_order: Number(sortOrder) || 0,
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
      title={group ? `Edit ${group.name}` : "New group"}
      onClose={onClose}
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
      <Field label="Name" help="Shown to users as the group of a server in their list.">
        <input value={name} onChange={(event) => setName(event.target.value)} autoFocus />
      </Field>
      <Field label="Description" help="Only you see this.">
        <input value={description} onChange={(event) => setDescription(event.target.value)} />
      </Field>
      <Field label="Sort order" help="Lower comes first in lists.">
        <input
          value={sortOrder}
          onChange={(event) => setSortOrder(event.target.value)}
          inputMode="numeric"
          style={{ width: 110 }}
        />
      </Field>
    </Modal>
  );
}
