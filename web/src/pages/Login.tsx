import { useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import { Banner, Field } from "../components/ui";

export default function Login({ onSignedIn }: { onSignedIn: () => void }): ReactNode {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // The code field only appears once the panel asks for it, so an account
  // without two-factor never sees it.
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password, code);
      onSignedIn();
    } catch (caught) {
      if (caught instanceof RequestError && caught.code === "totp_required") {
        setNeedCode(true);
        setError(null);
      } else if (caught instanceof RequestError) {
        setError(caught.message);
      } else {
        setError(String(caught));
      }
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

        {error && <Banner kind="error">{error}</Banner>}

        <Field label="Username">
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </Field>
        <Field label="Password">
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>
        {needCode && (
          <Field label="Authenticator code" help="Six digits from your authenticator app.">
            <input
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              required
            />
          </Field>
        )}

        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
