import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { api } from "../api";
import { Banner, Card, Pill, Spinner, Stat, formatBytes, formatRelative, usePoll } from "../components/ui";

export default function Dashboard(): ReactNode {
  // The dashboard is the page left open on a second monitor, so it refreshes
  // itself - and stops while the tab is hidden.
  const { data, error, loading } = usePoll(() => api.dashboard(), 15000);

  if (error) return <Banner kind="error">{error}</Banner>;
  if (!data) return <Spinner />;

  const nodeHint =
    data.nodes.out_of_sync > 0
      ? `${data.nodes.out_of_sync} waiting for a configuration`
      : "all up to date";

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <div className="sub">
            {loading ? "Refreshing…" : "Refreshes every 15 seconds"}
          </div>
        </div>
      </div>

      <div className="grid cols-4">
        <Stat
          label="Nodes online"
          value={`${data.nodes.online} / ${data.nodes.total}`}
          hint={nodeHint}
        />
        <Stat
          label="Users online"
          value={data.users.online_now}
          hint={`${data.users.active} active of ${data.users.total}`}
        />
        <Stat
          label="Traffic, 7 days"
          value={formatBytes(data.traffic.last_7_days_bytes)}
          hint="across every node"
        />
        <Stat
          label="Flux channels"
          value={`${data.flux.leased} / ${data.flux.channels}`}
          hint={`${data.flux.active_sessions} carrying a session`}
        />
      </div>

      {(data.nodes.degraded > 0 || data.nodes.out_of_sync > 0) && (
        <div style={{ marginTop: 14 }}>
          <Banner kind="warn">
            <div>
              {data.nodes.degraded > 0 && (
                <div>
                  {data.nodes.degraded} node(s) are reachable but not well — a core is down or
                  restarting. <Link to="/nodes">Open the node list</Link>.
                </div>
              )}
              {data.nodes.out_of_sync > 0 && (
                <div>
                  {data.nodes.out_of_sync} node(s) have not applied their configuration yet.
                </div>
              )}
            </div>
          </Banner>
        </div>
      )}

      {data.users.expiring_in_week > 0 && (
        <div style={{ marginTop: 14 }}>
          <Banner>
            {data.users.expiring_in_week} user(s) expire within a week.{" "}
            <Link to="/users?expiring=7">See who</Link>.
          </Banner>
        </div>
      )}

      <div style={{ marginTop: 14 }}>
        <Card
          title="Recent activity"
          actions={<Link className="button small" to="/journal">Full journal</Link>}
        >
          {data.recent_events.length === 0 ? (
            <div className="empty">Nothing has happened yet.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Severity</th>
                    <th>What</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_events.map((event) => (
                    <tr key={event.id}>
                      <td className="nowrap faint">{formatRelative(event.at)}</td>
                      <td>
                        <Pill kind={severityKind(event.severity)} dot>
                          {event.severity}
                        </Pill>
                      </td>
                      <td>{event.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

export function severityKind(severity: string): "ok" | "warn" | "bad" | undefined {
  switch (severity) {
    case "error":
      return "bad";
    case "warning":
      return "warn";
    case "info":
      return "ok";
    default:
      return undefined;
  }
}
