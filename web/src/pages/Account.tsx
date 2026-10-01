import { useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import type { Admin } from "../types";
import { Banner, Card, CopyLine, Field, Pill, Spinner, formatDate, useAsync } from "../components/ui";

export default function Account({
  admin,
  onChange,
}: {
  admin: Admin;
  onChange: () => void;
}): ReactNode {
  const sessions = useAsync(() => api.sessions(), []);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{admin.username}</h1>
          <div className="sub">
            {admin.role} · signed in {formatDate(admin.last_login_at)}
          </div>
        </div>
      </div>

      <div className="grid cols-2">
        <PasswordCard totpEnabled={admin.totp_enabled} />
        <TwoFactorCard admin={admin} onChange={onChange} />
      </div>

      <Card title="Where you are signed in">
        {!sessions.data ? (
          <Spinner />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Address</th>
                  <th>Started</th>
                  <th>Last used</th>
                  <th>Expires</th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.sessions.map((session) => (
                  <tr key={session.id}>
                    <td style={{ maxWidth: 320, overflowWrap: "anywhere" }}>
                      {session.user_agent || <span className="faint">unknown</span>}
                    </td>
                    <td className="mono">{session.ip || "—"}</td>
                    <td className="faint nowrap">{formatDate(session.created_at)}</td>
                    <td className="faint nowrap">{formatDate(session.last_seen_at)}</td>
                    <td className="faint nowrap">{formatDate(session.expires_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="faint" style={{ marginBottom: 0 }}>
          Changing your password signs out every other session.
        </p>
      </Card>
    </>
  );
}

function PasswordCard({ totpEnabled }: { totpEnabled: boolean }): ReactNode {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (next !== confirm) {
      setError("The two new passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      await api.changePassword(current, next, code);
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
      setCode("");
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Password">
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {error && <Banner kind="error">{error}</Banner>}
        {done && <Banner kind="ok">Changed. Other sessions were signed out.</Banner>}
        <Field
          label="Current password"
          help="Required even though you are signed in: a borrowed session must not be enough to lock you out."
        >
          <input
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>
        <Field label="New password" help="At least 12 characters.">
          <input
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            autoComplete="new-password"
            required
          />
        </Field>
        <Field label="Repeat the new password">
          <input
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            autoComplete="new-password"
            required
          />
        </Field>
        {totpEnabled && (
          <Field label="Authenticator code">
            <input value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" />
          </Field>
        )}
        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Changing…" : "Change password"}
        </button>
      </form>
    </Card>
  );
}

function TwoFactorCard({ admin, onChange }: { admin: Admin; onChange: () => void }): ReactNode {
  const [setup, setSetup] = useState<{ secret: string; url: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      setSetup(await api.totpStart());
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.totpConfirm(code);
      setSetup(null);
      setCode("");
      onChange();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.totpDisable(password, code);
      setPassword("");
      setCode("");
      onChange();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title="Two-factor"
      actions={admin.totp_enabled ? <Pill kind="ok">on</Pill> : <Pill>off</Pill>}
    >
      {error && <Banner kind="error">{error}</Banner>}

      {admin.totp_enabled ? (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            A code from your authenticator is required to sign in. Turning it off needs both your
            password and a current code.
          </p>
          <Field label="Password">
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
            />
          </Field>
          <Field label="Authenticator code">
            <input value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" />
          </Field>
          <button className="danger" onClick={disable} disabled={busy || !password || !code}>
            Turn two-factor off
          </button>
        </>
      ) : setup ? (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            Add this to your authenticator, then enter a code to finish. Nothing changes until a
            code checks out, so a half-finished setup cannot lock you out.
          </p>
          <Field label="Secret">
            <CopyLine value={setup.secret} />
          </Field>
          <Field label="Or paste this into the app">
            <CopyLine value={setup.url} />
          </Field>
          <Field label="Code from the app">
            <input
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoFocus
            />
          </Field>
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <button className="primary" onClick={confirm} disabled={busy || code.length < 6}>
              Finish
            </button>
            <button onClick={() => setSetup(null)}>Cancel</button>
          </div>
        </>
      ) : (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            With two-factor on, a stolen password is not enough to sign in. The panel is the one
            place that can reach every node, so this is worth turning on.
          </p>
          <button className="primary" onClick={start} disabled={busy}>
            Set up two-factor
          </button>
        </>
      )}
    </Card>
  );
}
