// The shapes the panel's API returns.
//
// These mirror the Go handlers rather than the database: a column rename must
// not reach this file, and a field the API stops sending should break the
// build here rather than render as "undefined" in a table.

export interface ApiError {
  code: string;
  message: string;
  field?: string;
}

export interface Admin {
  id: number;
  username: string;
  role: string;
  totp_enabled: boolean;
  last_login_at: string | null;
}

export type NodeStatus = "online" | "offline" | "degraded";

export interface FluxPool {
  total: number;
  leased: number;
  active_sessions: number;
}

export interface Node {
  id: number;
  uuid: string;
  name: string;
  display_name: string;
  address: string;
  country_code: string;
  notes: string;
  enabled: boolean;
  status: NodeStatus;
  status_reason: string;
  connected: boolean;
  last_seen_at: string | null;
  connected_at: string | null;

  config_version: number;
  applied_version: number;
  in_sync: boolean;
  apply_error: string;

  agent_version: string;
  xray_version: string;
  wndns_version: string;
  openflux_version: string;

  hostname: string;
  os: string;
  arch: string;
  cpu_cores: number | null;
  mem_total_bytes: number | null;
  online_users: number;

  group_ids: number[];
  created_at: string;
  flux_pool?: FluxPool;
  install?: InstallCommand;
}

export interface InstallCommand {
  command: string;
  token: string;
  main: string;
  ca_fingerprint: string;
  expires_at: string;
  script_url: string;
}

export interface Group {
  id: number;
  uuid: string;
  name: string;
  description: string;
  sort_order: number;
  nodes?: number;
  users?: number;
}

export type Protocol =
  | "vless"
  | "vmess"
  | "trojan"
  | "shadowsocks"
  | "shadowsocks2022"
  | "hysteria2"
  | "wndns";

export type Security = "none" | "tls" | "reality";

export interface Template {
  id: number;
  uuid: string;
  name: string;
  protocol: Protocol;
  network: string;
  security: Security;
  listen_port: number | null;
  params: Record<string, string>;
  secrets?: Record<string, string>;
  secret_keys?: string[];
  enabled: boolean;
  node_ids: number[];
  group_ids: number[];
}

export interface Inbound {
  id: number;
  node_id: number;
  tag: string;
  protocol: Protocol;
  network: string;
  security: Security;
  listen_address: string;
  listen_port: number;
  params: Record<string, string>;
  overrides: Record<string, string>;
  forward_to_tag: string;
  published: boolean;
  enabled: boolean;
  sort_order: number;
  from_template: boolean;
  template_id: number | null;
  secret_keys?: string[];
  secrets?: Record<string, string>;
}

export type UserStatus = "active" | "disabled" | "expired" | "limited";

export interface User {
  id: number;
  uuid: string;
  name: string;
  comment: string;
  status: UserStatus;
  expires_at: string | null;
  traffic_limit: number;
  traffic_used: number;
  traffic_remaining: number | null;
  days_remaining: number | null;
  devices_limit: number;
  devices_used: number;
  reset_strategy: string;
  last_reset_at: string | null;
  last_sub_fetch_at: string | null;
  group_ids: number[];
  created_at: string;
  sub_token: string;
}

export interface Device {
  id: number;
  hwid: string;
  model: string;
  platform: string;
  app_version: string;
  first_seen_at: string;
  last_seen_at: string;
  last_ip: string;
}

export interface SubscriptionLinks {
  url: string;
  token: string;
  deep_link?: string;
  deep_link_error?: string;
  qr_png_base64?: string;
}

/** One server the user would be served, with a link that carries it alone. */
export interface UserServer {
  id: string;
  name: string;
  protocol: Protocol | "flux";
  transport: string;
  address: string;
  port: number;
  link?: string;
  error?: string;
}

export interface FluxConfig {
  enabled: boolean;
  mode: "l3" | "l4";
  params: Record<string, string>;
  warning?: string;
}

export interface Channel {
  id: number;
  uuid: string;
  node_id: number;
  name: string;
  transport: string;
  transport_label?: string;
  url: string;
  params: Record<string, string>;
  session_context: string;
  enabled: boolean;
  session_active: boolean;
  last_error: string;
  has_secret: boolean;
  shareable: boolean;
  secret?: string;
  created_at: string;
}

export interface Event {
  id: number;
  at: string;
  severity: "info" | "warning" | "error";
  type: string;
  core: string;
  message: string;
  details: unknown;
  node_id?: number;
  user_id?: number;
}

export interface AuditEntry {
  id: number;
  at: string;
  admin: string;
  action: string;
  object_type: string;
  object_id: string;
  ip: string;
  details: unknown;
}

export interface Dashboard {
  nodes: {
    total: number;
    online: number;
    offline: number;
    degraded: number;
    out_of_sync: number;
  };
  users: {
    total: number;
    active: number;
    expiring_in_week: number;
    online_now: number;
  };
  traffic: { last_7_days_bytes: number };
  flux: { channels: number; leased: number; active_sessions: number };
  recent_events: Event[];
}

export interface MetricPoint {
  at: string;
  cpu_percent: number | null;
  load1?: number | null;
  mem_used: number | null;
  mem_total?: number | null;
  disk_used: number | null;
  disk_total?: number | null;
  net_rx: number | null;
  net_tx: number | null;
  net_rx_delta?: number | null;
  net_tx_delta?: number | null;
  uptime?: number | null;
  online_users: number | null;
  tcp_conns?: number | null;
}

export interface MetricsResponse {
  window: "hour" | "day" | "week";
  resolution: "raw" | "hourly";
  points: MetricPoint[];
}

export interface TrafficDay {
  day: string;
  uplink: number;
  downlink: number;
  total: number;
}

export interface Branding {
  app_name: string;
  logo_url: string;
  support_url: string;
  message: string;
  accent_color: string;
  android_url: string;
  ios_url: string;
  windows_url: string;
  macos_url: string;
  linux_url: string;
  instructions_html: string;
}

export interface Domains {
  panel_url: string;
  sub_base_url: string;
  agent_endpoint: string;
}

export interface UserDefaults {
  traffic_limit_bytes: number;
  valid_days: number;
  devices_limit: number;
  group_ids: number[];
}

export interface SubscriptionSettings {
  update_interval_hours: number;
  rate_limit_per_minute: number;
  cache_seconds: number;
  include_offline_nodes: boolean;
}

export interface Settings {
  branding: Branding;
  domains: Domains;
  user_defaults: UserDefaults;
  subscription: SubscriptionSettings;
  ca_fingerprint: string;
}

export interface ProtocolMeta {
  value: Protocol;
  label: string;
  networks: string[];
  securities: Security[];
}

export interface CarrierMeta {
  value: string;
  label: string;
  needs: string[];
  note: string;
}

export interface ShadowsocksMethodMeta {
  value: string;
  protocol: string;
  multiuser: boolean;
  key_is_base64: boolean;
  key_bytes?: number;
}

export interface Meta {
  protocols: ProtocolMeta[];
  flux_carriers: CarrierMeta[];
  shadowsocks_methods: ShadowsocksMethodMeta[];
  finalmask_udp: string[];
  finalmask_tcp: string[];
  user_statuses: UserStatus[];
  node_statuses: NodeStatus[];
  reset_strategies: string[];
  flux_modes: string[];
}

export interface RealityKeys {
  private_key: string;
  public_key: string;
  short_ids: string[];
}
