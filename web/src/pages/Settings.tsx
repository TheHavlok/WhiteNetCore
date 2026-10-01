import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api, RequestError } from "../api";
import type { Branding, Domains, Settings, SubscriptionSettings, UserDefaults } from "../types";
import { Banner, Card, CopyLine, Field, Spinner, useAsync } from "../components/ui";

export default function SettingsPage(): ReactNode {
  const loaded = useAsync(() => api.settings(), []);
  const groups = useAsync(() => api.groups(), []);

  const [branding, setBranding] = useState<Branding | null>(null);
  const [domains, setDomains] = useState<Domains | null>(null);
  const [defaults, setDefaults] = useState<UserDefaults | null>(null);
  const [subscription, setSubscription] = useState<SubscriptionSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loaded.data) return;
    setBranding(loaded.data.branding);
    setDomains(loaded.data.domains);
    setDefaults(loaded.data.user_defaults);
    setSubscription(loaded.data.subscription);
  }, [loaded.data]);

  if (loaded.error) return <Banner kind="error">{loaded.error}</Banner>;
  if (!loaded.data || !branding || !domains || !defaults || !subscription) return <Spinner />;

  const save = async (patch: Partial<Settings>) => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await api.saveSettings(patch);
      setSaved(true);
      loaded.reload();
    } catch (caught) {
      setError(caught instanceof RequestError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const httpsSub = domains.sub_base_url.startsWith("https://");

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <div className="sub">Branding, domains and the defaults for new users.</div>
        </div>
      </div>

      {error && <Banner kind="error">{error}</Banner>}
      {saved && <Banner kind="ok">Saved.</Banner>}

      <Card
        title="Domains"
        actions={
          <button className="primary small" disabled={busy} onClick={() => save({ domains })}>
            Save
          </button>
        }
      >
        <Field
          label="Panel URL"
          help="Where this panel is reached. It goes into the install command, so a node has to be able to fetch it from here."
        >
          <input
            value={domains.panel_url}
            onChange={(event) => setDomains({ ...domains, panel_url: event.target.value })}
            placeholder="https://panel.example.com"
          />
        </Field>
        <Field
          label="Subscription URL"
          help="The base of subscription links. Keeping it on its own domain means a blocked subscription host does not take the panel with it."
        >
          <input
            value={domains.sub_base_url}
            onChange={(event) => setDomains({ ...domains, sub_base_url: event.target.value })}
            placeholder="https://sub.example.com"
          />
        </Field>
        {domains.sub_base_url && !httpsSub && (
          <Banner kind="warn">
            This is not https, so the app's import deep link and the QR code are refused: a
            subscription carries every credential a user has, and over plain http anyone on the
            path can read it. The plain link still works for testing.
          </Banner>
        )}
        <Field
          label="Agent endpoint"
          help="host:port the agents connect to. This is what goes into install commands."
        >
          <input
            value={domains.agent_endpoint}
            onChange={(event) => setDomains({ ...domains, agent_endpoint: event.target.value })}
            placeholder="panel.example.com:8443"
          />
        </Field>
        <Field
          label="CA fingerprint"
          help="The nodes pin this to verify the panel. It is in every install command; this is here so it can be checked by hand."
        >
          <CopyLine value={loaded.data.ca_fingerprint} />
        </Field>
      </Card>

      <Card
        title="Branding"
        actions={
          <button className="primary small" disabled={busy} onClick={() => save({ branding })}>
            Save
          </button>
        }
      >
        <p className="muted" style={{ marginTop: 0 }}>
          This is what a user sees on the subscription page and in the app, so it can be changed
          without a new app build.
        </p>
        <div className="grid cols-2">
          <Field label="App name">
            <input
              value={branding.app_name}
              onChange={(event) => setBranding({ ...branding, app_name: event.target.value })}
            />
          </Field>
          <Field label="Accent colour">
            <div className="field-row">
              <input
                type="color"
                value={branding.accent_color || "#3b82f6"}
                onChange={(event) => setBranding({ ...branding, accent_color: event.target.value })}
                style={{ width: 54, padding: 2 }}
              />
              <input
                value={branding.accent_color}
                onChange={(event) => setBranding({ ...branding, accent_color: event.target.value })}
              />
            </div>
          </Field>
          <Field label="Logo URL" help="Shown on the subscription page.">
            <input
              value={branding.logo_url}
              onChange={(event) => setBranding({ ...branding, logo_url: event.target.value })}
            />
          </Field>
          <Field label="Support link">
            <input
              value={branding.support_url}
              onChange={(event) => setBranding({ ...branding, support_url: event.target.value })}
              placeholder="https://t.me/your_support"
            />
          </Field>
        </div>
        <Field label="Message to users" help="Shown on the page and passed to the app.">
          <input
            value={branding.message}
            onChange={(event) => setBranding({ ...branding, message: event.target.value })}
          />
        </Field>

        <h3 style={{ marginTop: 8 }}>Download links</h3>
        <div className="grid cols-2">
          <Field label="Android">
            <input
              value={branding.android_url}
              onChange={(event) => setBranding({ ...branding, android_url: event.target.value })}
            />
          </Field>
          <Field label="iOS">
            <input
              value={branding.ios_url}
              onChange={(event) => setBranding({ ...branding, ios_url: event.target.value })}
            />
          </Field>
          <Field label="Windows">
            <input
              value={branding.windows_url}
              onChange={(event) => setBranding({ ...branding, windows_url: event.target.value })}
            />
          </Field>
          <Field label="macOS">
            <input
              value={branding.macos_url}
              onChange={(event) => setBranding({ ...branding, macos_url: event.target.value })}
            />
          </Field>
          <Field label="Linux">
            <input
              value={branding.linux_url}
              onChange={(event) => setBranding({ ...branding, linux_url: event.target.value })}
            />
          </Field>
        </div>

        <Field
          label="Setup instructions"
          help="HTML, shown on the subscription page instead of the default steps. Only an administrator can set this, so it is rendered as given."
        >
          <textarea
            value={branding.instructions_html}
            onChange={(event) =>
              setBranding({ ...branding, instructions_html: event.target.value })
            }
            placeholder="<ol><li>Install the app…</li></ol>"
          />
        </Field>
      </Card>

      <Card
        title="Defaults for new users"
        actions={
          <button
            className="primary small"
            disabled={busy}
            onClick={() => save({ user_defaults: defaults })}
          >
            Save
          </button>
        }
      >
        <p className="muted" style={{ marginTop: 0 }}>
          Anything left empty on the add-user form comes from here, which is what makes creating a
          user one field in the common case.
        </p>
        <div className="grid cols-3">
          <Field label="Traffic, GB" help="0 means no limit.">
            <input
              value={defaults.traffic_limit_bytes ? defaults.traffic_limit_bytes / 1024 ** 3 : 0}
              onChange={(event) =>
                setDefaults({
                  ...defaults,
                  traffic_limit_bytes: Math.round((Number(event.target.value) || 0) * 1024 ** 3),
                })
              }
              inputMode="decimal"
            />
          </Field>
          <Field label="Valid for, days" help="0 means never expires.">
            <input
              value={defaults.valid_days}
              onChange={(event) =>
                setDefaults({ ...defaults, valid_days: Number(event.target.value) || 0 })
              }
              inputMode="numeric"
            />
          </Field>
          <Field label="Devices" help="0 means no limit.">
            <input
              value={defaults.devices_limit}
              onChange={(event) =>
                setDefaults({ ...defaults, devices_limit: Number(event.target.value) || 0 })
              }
              inputMode="numeric"
            />
          </Field>
        </div>
        <Field label="Groups">
          <div className="chips">
            {(groups.data?.groups ?? []).map((group) => (
              <button
                key={group.id}
                type="button"
                className={defaults.group_ids?.includes(group.id) ? "chip on" : "chip"}
                onClick={() =>
                  setDefaults({
                    ...defaults,
                    group_ids: (defaults.group_ids ?? []).includes(group.id)
                      ? (defaults.group_ids ?? []).filter((id) => id !== group.id)
                      : [...(defaults.group_ids ?? []), group.id],
                  })
                }
              >
                {group.name}
              </button>
            ))}
          </div>
        </Field>
      </Card>

      <Card
        title="Subscriptions"
        actions={
          <button
            className="primary small"
            disabled={busy}
            onClick={() => save({ subscription })}
          >
            Save
          </button>
        }
      >
        <div className="grid cols-3">
          <Field label="Refresh every, hours" help="How often the app refetches.">
            <input
              value={subscription.update_interval_hours}
              onChange={(event) =>
                setSubscription({
                  ...subscription,
                  update_interval_hours: Number(event.target.value) || 12,
                })
              }
              inputMode="numeric"
            />
          </Field>
          <Field
            label="Requests a minute"
            help="Per client address. This is what stops the token space being walked."
          >
            <input
              value={subscription.rate_limit_per_minute}
              onChange={(event) =>
                setSubscription({
                  ...subscription,
                  rate_limit_per_minute: Number(event.target.value) || 0,
                })
              }
              inputMode="numeric"
            />
          </Field>
          <Field
            label="Cache, seconds"
            help="A rendered subscription is reused this long, so a fleet of phones refreshing is not a query storm."
          >
            <input
              value={subscription.cache_seconds}
              onChange={(event) =>
                setSubscription({
                  ...subscription,
                  cache_seconds: Number(event.target.value) || 0,
                })
              }
              inputMode="numeric"
            />
          </Field>
        </div>
        <label className="checkline">
          <input
            type="checkbox"
            checked={subscription.include_offline_nodes}
            onChange={(event) =>
              setSubscription({ ...subscription, include_offline_nodes: event.target.checked })
            }
          />
          Include nodes that are offline
        </label>
        <p className="faint" style={{ margin: 0 }}>
          Off by default: handing a client a dead server is worse than handing it one fewer.
        </p>
      </Card>
    </>
  );
}
