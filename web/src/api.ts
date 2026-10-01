// The one place that talks to the panel.
//
// Everything goes through request(), so the session handling, the error shape
// and the base path are decided once. The base path matters: the panel can be
// served from an unguessable path, and the interface has to work wherever it
// was mounted without being rebuilt.

import type {
  Admin,
  AuditEntry,
  Channel,
  Dashboard,
  Device,
  Event,
  FluxConfig,
  Group,
  Inbound,
  InstallCommand,
  Meta,
  MetricsResponse,
  Node,
  RealityKeys,
  Settings,
  SubscriptionLinks,
  Template,
  TrafficDay,
  User,
} from "./types";

/** The error a failed request throws, carrying the API's machine-readable code. */
export class RequestError extends Error {
  code: string;
  field?: string;
  status: number;

  constructor(status: number, code: string, message: string, field?: string) {
    super(message);
    this.name = "RequestError";
    this.status = status;
    this.code = code;
    this.field = field;
  }

  /** True when the session is gone and the user has to sign in again. */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }
}

/**
 * apiBase is where the API lives.
 *
 * The panel rewrites a placeholder in index.html with the path it mounted the
 * interface at, which may be unguessable rather than /admin. Reading it is
 * exact, where guessing from the URL would break as soon as a route looked
 * like a path segment.
 */
function apiBase(): string {
  // In the dev server the interface runs on its own origin and the proxy in
  // vite.config.ts forwards this prefix.
  if (import.meta.env.DEV) return "/admin/api";

  const injected = (window as { __WN_BASE__?: string }).__WN_BASE__;
  // An un-substituted placeholder means the page was opened directly from the
  // build output rather than served by the panel.
  if (injected && !injected.includes("__WN_BASE")) {
    return trimSlash(injected) + "/api";
  }
  return "/admin/api";
}

function trimSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

const BASE = apiBase();

/** The path the interface itself is mounted at, for the router. */
export const UI_BASE = BASE.replace(/\/api$/, "") || "/";

let onUnauthorized: (() => void) | null = null;

/** Called when a request finds the session gone, so the app can show the login. */
export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options: { signal?: AbortSignal } = {},
): Promise<T> {
  const init: RequestInit = {
    method,
    // The session is a cookie, so it has to be sent.
    credentials: "same-origin",
    headers: {},
    signal: options.signal,
  };
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }

  const response = await fetch(BASE + path, init);

  if (response.status === 204) return undefined as T;

  let payload: unknown = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      // A non-JSON body from a proxy or a crash: report the status rather
      // than a parse error, which would say nothing useful.
      throw new RequestError(response.status, "internal", `HTTP ${response.status}`);
    }
  }

  if (!response.ok) {
    const error = (payload as { error?: { code: string; message: string; field?: string } })?.error;
    const requestError = new RequestError(
      response.status,
      error?.code ?? "internal",
      error?.message ?? `HTTP ${response.status}`,
      error?.field,
    );
    // A dead session is handled centrally: every page would otherwise need
    // the same check.
    if (requestError.isUnauthorized && onUnauthorized) onUnauthorized();
    throw requestError;
  }

  return payload as T;
}

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "" || value === false) continue;
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? "?" + encoded : "";
}

export const api = {
  // -- session ------------------------------------------------------------
  setupNeeded: () => request<{ setup_needed: boolean }>("GET", "/auth/setup"),
  setup: (username: string, password: string) =>
    request<Admin>("POST", "/auth/setup", { username, password }),
  login: (username: string, password: string, code?: string) =>
    request<Admin>("POST", "/auth/login", { username, password, code: code ?? "" }),
  logout: () => request<{ ok: boolean }>("POST", "/auth/logout"),
  me: () => request<Admin>("GET", "/auth/me"),
  changePassword: (current: string, next: string, code?: string) =>
    request<{ ok: boolean }>("POST", "/auth/password", { current, new: next, code: code ?? "" }),
  totpStart: () => request<{ secret: string; url: string }>("POST", "/auth/totp/start"),
  totpConfirm: (code: string) => request<{ ok: boolean }>("POST", "/auth/totp/confirm", { code }),
  totpDisable: (password: string, code: string) =>
    request<{ ok: boolean }>("POST", "/auth/totp/disable", { password, code }),
  sessions: () =>
    request<{
      sessions: {
        id: number;
        user_agent: string;
        ip: string;
        created_at: string;
        last_seen_at: string;
        expires_at: string;
      }[];
    }>("GET", "/auth/sessions"),

  // -- dashboard ----------------------------------------------------------
  dashboard: () => request<Dashboard>("GET", "/dashboard"),
  meta: () => request<Meta>("GET", "/meta"),

  // -- nodes --------------------------------------------------------------
  nodes: () => request<{ nodes: Node[] }>("GET", "/nodes"),
  node: (id: number) => request<Node>("GET", `/nodes/${id}`),
  createNode: (body: {
    name: string;
    address: string;
    country_code?: string;
    group_ids?: number[];
  }) => request<Node>("POST", "/nodes", body),
  updateNode: (id: number, body: Partial<Record<string, unknown>>) =>
    request<Node>("PATCH", `/nodes/${id}`, body),
  deleteNode: (id: number) => request<{ ok: boolean }>("DELETE", `/nodes/${id}`),
  installCommand: (id: number) =>
    request<InstallCommand>("POST", `/nodes/${id}/install-command`),
  restartCore: (id: number, core: string) =>
    request<{ ok: boolean }>("POST", `/nodes/${id}/restart`, { core }),
  resyncNode: (id: number) => request<{ ok: boolean }>("POST", `/nodes/${id}/resync`),
  revokeNode: (id: number) => request<{ ok: boolean }>("POST", `/nodes/${id}/revoke`),
  nodeLogs: (id: number, core: string, lines = 300) =>
    request<{ core: string; text: string }>("GET", `/nodes/${id}/logs${query({ core, lines })}`),
  nodeMetrics: (id: number, window: "hour" | "day" | "week") =>
    request<MetricsResponse>("GET", `/nodes/${id}/metrics${query({ window })}`),
  nodeTraffic: (id: number, days = 30) =>
    request<{ days: TrafficDay[] }>("GET", `/nodes/${id}/traffic${query({ days })}`),

  // -- groups -------------------------------------------------------------
  groups: () => request<{ groups: Group[] }>("GET", "/groups"),
  createGroup: (body: { name: string; description?: string; sort_order?: number }) =>
    request<Group>("POST", "/groups", body),
  updateGroup: (id: number, body: { name: string; description: string; sort_order: number }) =>
    request<Group>("PATCH", `/groups/${id}`, body),
  deleteGroup: (id: number) => request<{ ok: boolean }>("DELETE", `/groups/${id}`),

  // -- templates ----------------------------------------------------------
  templates: () => request<{ templates: Template[] }>("GET", "/templates"),
  template: (id: number) => request<Template>("GET", `/templates/${id}`),
  createTemplate: (body: Record<string, unknown>) =>
    request<Template>("POST", "/templates", body),
  updateTemplate: (id: number, body: Record<string, unknown>) =>
    request<Template>("PUT", `/templates/${id}`, body),
  deleteTemplate: (id: number) => request<{ ok: boolean }>("DELETE", `/templates/${id}`),
  setTemplateTargets: (id: number, nodeIDs: number[], groupIDs: number[]) =>
    request<Template>("PUT", `/templates/${id}/targets`, {
      node_ids: nodeIDs,
      group_ids: groupIDs,
    }),

  // -- inbounds -----------------------------------------------------------
  inbounds: (nodeID: number) =>
    request<{ inbounds: Inbound[] }>("GET", `/nodes/${nodeID}/inbounds`),
  createInbound: (nodeID: number, body: Record<string, unknown>) =>
    request<Inbound>("POST", `/nodes/${nodeID}/inbounds`, body),
  updateInbound: (id: number, body: Record<string, unknown>) =>
    request<Inbound>("PATCH", `/inbounds/${id}`, body),
  deleteInbound: (id: number) => request<{ ok: boolean }>("DELETE", `/inbounds/${id}`),

  // -- flux ---------------------------------------------------------------
  nodeFlux: (nodeID: number) => request<FluxConfig>("GET", `/nodes/${nodeID}/flux`),
  setNodeFlux: (nodeID: number, body: { enabled: boolean; mode: string; params?: Record<string, string> }) =>
    request<FluxConfig>("PUT", `/nodes/${nodeID}/flux`, body),
  channels: (nodeID: number) =>
    request<{ channels: Channel[] }>("GET", `/nodes/${nodeID}/channels`),
  createChannels: (nodeID: number, body: Record<string, unknown>) =>
    request<{ channels: Channel[] }>("POST", `/nodes/${nodeID}/channels`, body),
  updateChannel: (id: number, body: Record<string, unknown>) =>
    request<Channel>("PATCH", `/channels/${id}`, body),
  deleteChannel: (id: number) => request<{ ok: boolean }>("DELETE", `/channels/${id}`),
  rotateChannel: (id: number) => request<{ ok: boolean }>("POST", `/channels/${id}/rotate`),

  // -- users --------------------------------------------------------------
  users: (params: {
    search?: string;
    status?: string;
    group_id?: number;
    expiring_in_days?: number;
    limit?: number;
    offset?: number;
  }) =>
    request<{ users: User[]; total: number; limit: number; offset: number }>(
      "GET",
      `/users${query(params)}`,
    ),
  user: (id: number) => request<User>("GET", `/users/${id}`),
  createUser: (body: Record<string, unknown>) => request<User>("POST", "/users", body),
  updateUser: (id: number, body: Record<string, unknown>) =>
    request<User>("PATCH", `/users/${id}`, body),
  deleteUser: (id: number) => request<{ ok: boolean }>("DELETE", `/users/${id}`),
  reissueToken: (id: number) =>
    request<SubscriptionLinks>("POST", `/users/${id}/reissue-token`),
  resetTraffic: (id: number) => request<{ ok: boolean }>("POST", `/users/${id}/reset-traffic`),
  devices: (id: number) => request<{ devices: Device[] }>("GET", `/users/${id}/devices`),
  deleteDevice: (userID: number, deviceID: number) =>
    request<{ ok: boolean }>("DELETE", `/users/${userID}/devices/${deviceID}`),
  userTraffic: (id: number, days = 30) =>
    request<{ days: TrafficDay[] }>("GET", `/users/${id}/traffic${query({ days })}`),
  subscription: (id: number) =>
    request<SubscriptionLinks>("GET", `/users/${id}/subscription`),
  bulkUsers: (body: {
    user_ids: number[];
    action: string;
    extend_days?: number;
    status?: string;
    group_ids?: number[];
  }) => request<{ affected: number }>("POST", "/users/bulk", body),

  // -- journal ------------------------------------------------------------
  events: (params: {
    severity?: string;
    type?: string;
    node_id?: number;
    user_id?: number;
    hours?: number;
    limit?: number;
    offset?: number;
  }) => request<{ events: Event[]; total: number }>("GET", `/events${query(params)}`),
  audit: (params: { admin_id?: number; action?: string; hours?: number; limit?: number; offset?: number }) =>
    request<{ entries: AuditEntry[]; total: number }>("GET", `/audit${query(params)}`),

  // -- settings -----------------------------------------------------------
  settings: () => request<Settings>("GET", "/settings"),
  saveSettings: (body: Partial<Settings>) => request<Settings>("PUT", "/settings", body),

  // -- key generation -----------------------------------------------------
  generateReality: () => request<RealityKeys>("POST", "/keys/reality"),
  generateShortIDs: (count = 4, bytes = 8) =>
    request<{ short_ids: string[] }>("POST", `/keys/shortid${query({ count, bytes })}`),
  generateUUID: () => request<{ uuid: string }>("POST", "/keys/uuid"),
  generatePassword: () => request<{ password: string }>("POST", "/keys/password"),
  generateShadowsocks: (method: string) =>
    request<{ method: string; password: string; multiuser: boolean }>(
      "POST",
      `/keys/shadowsocks${query({ method })}`,
    ),
  generateFluxSecret: () => request<{ secret: string }>("POST", "/keys/flux-secret"),
};
