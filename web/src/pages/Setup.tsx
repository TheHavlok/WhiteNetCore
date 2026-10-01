import { useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import { Banner, Field } from "../components/ui";

/**
 * Setup creates the first administrator.
 *
 * It is only reachable while the panel has none; afterwards the endpoint
 * refuses, so this cannot be used to add an account to a running panel.
 */
export default function Setup({ onDone }: { onDone: () => void }): ReactNode {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.setup(username, password);
      onDone();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <form onSubmit={submit}>
        <div className="brand">
          <div className="mark">W</div>
          <div className="name">WhiteNet</div>
        </div>
        <p className="muted" style={{ margin: 0 }}>
          This panel has no administrator yet. Create the first one.
        </p>

        {error && <Banner kind="error">{error}</Banner>}

        <Field label="Username">
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
          />
        </Field>
        <Field label="Password" help="At least 12 characters. Length is what matters.">
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="new-password"
            required
          />
        </Field>
        <Field label="Repeat the password">
          <input
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            autoComplete="new-password"
            required
          />
        </Field>

        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Creating…" : "Create administrator"}
        </button>
      </form>
    </div>
  );
}
