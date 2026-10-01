import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Banner, Card, Pill, Spinner, formatDate, useAsync } from "../components/ui";
import { severityKind } from "./Dashboard";

/**
 * Journal is two logs side by side: what the fleet did, and what an
 * administrator did.
 *
 * They are kept apart because they answer different questions and have
 * different retention: the fleet journal is pruned, the audit log is not.
 */
export default function Journal(): ReactNode {
  const [tab, setTab] = useState<"events" | "audit">("events");
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Journal</h1>
          <div className="sub">What happened, and who did it.</div>
        </div>
      </div>

      <div className="tabs">
        <button className={tab === "events" ? "tab active" : "tab"} onClick={() => setTab("events")}>
          Fleet events
        </button>
        <button className={tab === "audit" ? "tab active" : "tab"} onClick={() => setTab("audit")}>
          Admin actions
        </button>
      </div>

      {tab === "events" ? <Events /> : <Audit />}
    </>
  );
}

function Events(): ReactNode {
  const [severity, setSeverity] = useState("");
  const [hours, setHours] = useState(24);
  const events = useAsync(() => api.events({ severity, hours, limit: 200 }), [severity, hours]);

  return (
    <Card>
      <div className="toolbar">
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">Any severity</option>
          <option value="error">Errors</option>
          <option value="warning">Warnings</option>
          <option value="info">Information</option>
        </select>
        <select value={hours} onChange={(event) => setHours(Number(event.target.value))}>
          <option value={1}>Last hour</option>
          <option value={24}>Last day</option>
          <option value={168}>Last week</option>
          <option value={0}>Everything kept</option>
        </select>
        <div className="spacer" />
        <button className="small" onClick={events.reload}>
          Refresh
        </button>
      </div>

      {events.error && <Banner kind="error">{events.error}</Banner>}
      {!events.data ? (
        <Spinner />
      ) : events.data.events.length === 0 ? (
        <div className="empty">Nothing in this window.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Severity</th>
                <th>Type</th>
                <th>What</th>
              </tr>
            </thead>
            <tbody>
              {events.data.events.map((event) => (
                <tr key={event.id}>
                  <td className="faint nowrap">{formatDate(event.at)}</td>
                  <td>
                    <Pill kind={severityKind(event.severity)} dot>
                      {event.severity}
                    </Pill>
                  </td>
                  <td className="mono">
                    {event.type}
                    {event.core && <span className="faint"> · {event.core}</span>}
                  </td>
                  <td>{event.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {events.data && events.data.total > events.data.events.length && (
        <p className="faint" style={{ marginBottom: 0 }}>
          Showing the newest {events.data.events.length} of {events.data.total}.
        </p>
      )}
    </Card>
  );
}

function Audit(): ReactNode {
  const [hours, setHours] = useState(168);
  const entries = useAsync(() => api.audit({ hours, limit: 200 }), [hours]);

  return (
    <Card>
      <div className="toolbar">
        <select value={hours} onChange={(event) => setHours(Number(event.target.value))}>
          <option value={24}>Last day</option>
          <option value={168}>Last week</option>
          <option value={720}>Last month</option>
          <option value={0}>Everything</option>
        </select>
        <div className="spacer" />
        <button className="small" onClick={entries.reload}>
          Refresh
        </button>
      </div>

      {entries.error && <Banner kind="error">{entries.error}</Banner>}
      {!entries.data ? (
        <Spinner />
      ) : entries.data.entries.length === 0 ? (
        <div className="empty">No actions recorded in this window.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>Action</th>
                <th>On what</th>
                <th>From</th>
              </tr>
            </thead>
            <tbody>
              {entries.data.entries.map((entry) => (
                <tr key={entry.id}>
                  <td className="faint nowrap">{formatDate(entry.at)}</td>
                  <td>{entry.admin || <span className="faint">system</span>}</td>
                  <td className="mono">{entry.action}</td>
                  <td className="faint">
                    {entry.object_type}
                    {entry.object_id && <span className="mono"> {entry.object_id}</span>}
                  </td>
                  <td className="mono faint">{entry.ip || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
