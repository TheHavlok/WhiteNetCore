-- WhiteNet panel: initial schema.
--
-- Conventions used throughout:
--   * surrogate BIGINT keys for joins, plus a public CHAR(36) uuid on the
--     rows that leak into URLs, subscriptions or client configs;
--   * every secret is VARBINARY and holds AES-256-GCM ciphertext produced
--     with the master key from the configuration, never plaintext;
--   * timestamps are DATETIME(3) in UTC - the application never relies on the
--     server's time zone;
--   * JSON columns hold validated, protocol-specific knobs. They are
--     deliberately schemaless so a new Xray or OpenFlux option does not need
--     a migration.

-- ---------------------------------------------------------------------------
-- Admins and panel access
-- ---------------------------------------------------------------------------

CREATE TABLE admins (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username        VARCHAR(64)     NOT NULL,
    password_hash   VARCHAR(255)    NOT NULL,          -- argon2id
    -- TOTP shared secret, encrypted. NULL until 2FA is enrolled.
    totp_secret     VARBINARY(512)  NULL,
    totp_enabled    TINYINT(1)      NOT NULL DEFAULT 0,
    -- Roles are not enforced yet; the column exists so adding them later is
    -- not a migration of live accounts.
    role            VARCHAR(32)     NOT NULL DEFAULT 'admin',
    is_active       TINYINT(1)      NOT NULL DEFAULT 1,
    -- Brute-force protection state.
    failed_logins   INT UNSIGNED    NOT NULL DEFAULT 0,
    locked_until    DATETIME(3)     NULL,
    last_login_at   DATETIME(3)     NULL,
    last_login_ip   VARCHAR(45)     NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_admins_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Opaque session tokens for the admin UI. Only the hash is stored so a dump
-- of this table cannot be replayed.
CREATE TABLE admin_sessions (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    admin_id        BIGINT UNSIGNED NOT NULL,
    token_hash      BINARY(32)      NOT NULL,
    user_agent      VARCHAR(255)    NULL,
    ip              VARCHAR(45)     NULL,
    expires_at      DATETIME(3)     NOT NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_admin_sessions_token (token_hash),
    KEY idx_admin_sessions_admin (admin_id),
    KEY idx_admin_sessions_expires (expires_at),
    CONSTRAINT fk_admin_sessions_admin FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Who changed what. Separate from `events` on purpose: that table is about
-- the fleet, this one is about accountability and is never pruned by the
-- metrics retention job.
CREATE TABLE admin_audit (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    at              DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    admin_id        BIGINT UNSIGNED NULL,               -- NULL for system actions
    admin_username  VARCHAR(64)     NULL,               -- denormalised, survives deletion
    action          VARCHAR(64)     NOT NULL,           -- user.create, node.restart, ...
    object_type     VARCHAR(32)     NULL,
    object_id       VARCHAR(64)     NULL,
    ip              VARCHAR(45)     NULL,
    details         JSON            NULL,
    PRIMARY KEY (id),
    KEY idx_admin_audit_at (at),
    KEY idx_admin_audit_admin (admin_id, at),
    KEY idx_admin_audit_object (object_type, object_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Panel-wide configuration: branding, domains, defaults for new users.
-- A key/value table rather than columns because these are read as a whole,
-- edited rarely, and grow by one key at a time.
CREATE TABLE settings (
    k               VARCHAR(128)    NOT NULL,
    v               JSON            NOT NULL,
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (k)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Nodes
-- ---------------------------------------------------------------------------

CREATE TABLE node_groups (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uuid            CHAR(36)        NOT NULL,
    name            VARCHAR(64)     NOT NULL,
    description     VARCHAR(255)    NULL,
    sort_order      INT             NOT NULL DEFAULT 0,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_node_groups_uuid (uuid),
    UNIQUE KEY uq_node_groups_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE nodes (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uuid            CHAR(36)        NOT NULL,
    name            VARCHAR(128)    NOT NULL,
    -- The address clients dial. Kept apart from whatever the agent reports:
    -- a node behind a proxy or with a vanity domain must not be overwritten
    -- by autodiscovery.
    address         VARCHAR(255)    NOT NULL DEFAULT '',
    country_code    CHAR(2)         NULL,
    -- Shown in the client's server list; falls back to name.
    display_name    VARCHAR(128)    NULL,
    notes           TEXT            NULL,

    -- enabled is the admin's intent; status is observed reality.
    enabled         TINYINT(1)      NOT NULL DEFAULT 1,
    status          ENUM('online','offline','degraded') NOT NULL DEFAULT 'offline',
    status_reason   VARCHAR(255)    NULL,
    last_seen_at    DATETIME(3)     NULL,
    connected_at    DATETIME(3)     NULL,

    -- Desired-state bookkeeping. config_version is bumped by Main on every
    -- change that affects this node; applied_version is what the agent
    -- confirmed. They differ exactly while a node is out of date.
    config_version  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    applied_version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    apply_error     VARCHAR(512)    NULL,

    agent_version   VARCHAR(64)     NULL,
    xray_version    VARCHAR(64)     NULL,
    wndns_version   VARCHAR(64)     NULL,
    openflux_version VARCHAR(64)    NULL,

    hostname        VARCHAR(255)    NULL,
    os              VARCHAR(64)     NULL,
    arch            VARCHAR(32)     NULL,
    cpu_cores       INT UNSIGNED    NULL,
    mem_total_bytes BIGINT UNSIGNED NULL,
    online_users    INT UNSIGNED    NOT NULL DEFAULT 0,

    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_nodes_uuid (uuid),
    KEY idx_nodes_status (status),
    KEY idx_nodes_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A node may sit in several groups ("Europe" and "Premium" at once), so this
-- is a join table rather than a column on nodes.
CREATE TABLE node_group_members (
    node_id         BIGINT UNSIGNED NOT NULL,
    group_id        BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (node_id, group_id),
    KEY idx_ngm_group (group_id),
    CONSTRAINT fk_ngm_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    CONSTRAINT fk_ngm_group FOREIGN KEY (group_id) REFERENCES node_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One-time enrolment tokens handed out by "Add node". Only the hash is
-- stored; the plaintext exists only inside the install command shown once.
CREATE TABLE node_tokens (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_hash      BINARY(32)      NOT NULL,
    -- The node row the token enrols. Created up front so the admin can
    -- configure a node before its agent ever connects.
    node_id         BIGINT UNSIGNED NOT NULL,
    created_by      BIGINT UNSIGNED NULL,
    expires_at      DATETIME(3)     NOT NULL,
    used_at         DATETIME(3)     NULL,
    used_ip         VARCHAR(45)     NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_node_tokens_hash (token_hash),
    KEY idx_node_tokens_node (node_id),
    CONSTRAINT fk_node_tokens_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    CONSTRAINT fk_node_tokens_admin FOREIGN KEY (created_by) REFERENCES admins (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Client certificates issued to agents. Kept so a node can be de-authorised
-- without waiting for expiry, and so the panel can warn before one lapses.
CREATE TABLE node_certs (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    node_id         BIGINT UNSIGNED NOT NULL,
    serial          VARCHAR(64)     NOT NULL,
    fingerprint     BINARY(32)      NOT NULL,
    cert_pem        MEDIUMTEXT      NOT NULL,
    not_before      DATETIME(3)     NOT NULL,
    not_after       DATETIME(3)     NOT NULL,
    revoked_at      DATETIME(3)     NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_node_certs_serial (serial),
    KEY idx_node_certs_node (node_id),
    KEY idx_node_certs_fp (fingerprint),
    CONSTRAINT fk_node_certs_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Main's own CA, so a restart does not orphan every issued certificate.
CREATE TABLE ca_keys (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name            VARCHAR(32)     NOT NULL,           -- 'node-ca'
    cert_pem        MEDIUMTEXT      NOT NULL,
    key_pem         VARBINARY(8192) NOT NULL,           -- encrypted
    not_after       DATETIME(3)     NOT NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_ca_keys_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Inbounds: templates and per-node instances
-- ---------------------------------------------------------------------------

-- A template is the reusable half: protocol, transport and the parameters
-- that are the same everywhere. It is applied to nodes or whole groups.
CREATE TABLE inbound_templates (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uuid            CHAR(36)        NOT NULL,
    name            VARCHAR(128)    NOT NULL,
    protocol        ENUM('vless','vmess','trojan','shadowsocks','shadowsocks2022','hysteria2','wndns') NOT NULL,
    -- Xray streamSettings.network: raw, xhttp, ws, grpc, httpupgrade, kcp.
    -- Empty for wndns, which has no Xray transport.
    network         VARCHAR(32)     NOT NULL DEFAULT '',
    security        ENUM('none','tls','reality') NOT NULL DEFAULT 'none',
    listen_port     INT UNSIGNED    NULL,               -- per-node override allowed
    params          JSON            NOT NULL,
    secrets         VARBINARY(8192) NULL,               -- encrypted JSON object
    enabled         TINYINT(1)      NOT NULL DEFAULT 1,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_inbound_templates_uuid (uuid),
    UNIQUE KEY uq_inbound_templates_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Where a template applies. Group targets are expanded when a node joins or
-- leaves the group, which is what makes "apply to a group" keep working for
-- nodes added later.
CREATE TABLE inbound_template_targets (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    template_id     BIGINT UNSIGNED NOT NULL,
    target_kind     ENUM('node','group') NOT NULL,
    node_id         BIGINT UNSIGNED NULL,
    group_id        BIGINT UNSIGNED NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_itt_node (template_id, node_id),
    UNIQUE KEY uq_itt_group (template_id, group_id),
    CONSTRAINT fk_itt_template FOREIGN KEY (template_id) REFERENCES inbound_templates (id) ON DELETE CASCADE,
    CONSTRAINT fk_itt_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    CONSTRAINT fk_itt_group FOREIGN KEY (group_id) REFERENCES node_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The concrete inbound on one node. Three shapes live here:
--   template_id IS NULL                      - a one-off inbound;
--   template_id set, overrides empty         - a plain template instance;
--   template_id set, overrides non-empty     - a template with this node's
--                                              port/SNI/dest changed.
-- The effective configuration is template.params merged with overrides, which
-- is computed on Main and shipped to the agent already resolved.
CREATE TABLE node_inbounds (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    node_id         BIGINT UNSIGNED NOT NULL,
    template_id     BIGINT UNSIGNED NULL,
    -- The Xray tag. Traffic statistics are keyed by it, so it is immutable
    -- for the life of the row.
    tag             VARCHAR(64)     NOT NULL,
    protocol        ENUM('vless','vmess','trojan','shadowsocks','shadowsocks2022','hysteria2','wndns') NOT NULL,
    network         VARCHAR(32)     NOT NULL DEFAULT '',
    security        ENUM('none','tls','reality') NOT NULL DEFAULT 'none',
    listen_address  VARCHAR(64)     NOT NULL DEFAULT '',
    listen_port     INT UNSIGNED    NOT NULL,
    overrides       JSON            NULL,
    params          JSON            NOT NULL,           -- effective, merged
    secrets         VARBINARY(8192) NULL,               -- encrypted JSON object
    -- For wndns: the tag of the Xray inbound every tunnelled stream is
    -- forwarded to. This chain is what gives the DNS protocol per-user auth
    -- and traffic accounting.
    forward_to_tag  VARCHAR(64)     NULL,
    -- Whether this inbound is advertised in subscriptions. An inbound can be
    -- live but hidden, e.g. the internal target of a DNS tunnel.
    published       TINYINT(1)      NOT NULL DEFAULT 1,
    enabled         TINYINT(1)      NOT NULL DEFAULT 1,
    sort_order      INT             NOT NULL DEFAULT 0,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_node_inbounds_tag (node_id, tag),
    UNIQUE KEY uq_node_inbounds_port (node_id, listen_address, listen_port),
    KEY idx_node_inbounds_node (node_id),
    KEY idx_node_inbounds_template (template_id),
    CONSTRAINT fk_node_inbounds_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    CONSTRAINT fk_node_inbounds_template FOREIGN KEY (template_id) REFERENCES inbound_templates (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The rendered desired state, one row per version. Keeping the snapshot makes
-- a reconnect a single read instead of a full re-render, and makes "what did
-- we actually send that node" answerable after the fact.
CREATE TABLE node_desired_state (
    node_id         BIGINT UNSIGNED NOT NULL,
    version         BIGINT UNSIGNED NOT NULL,
    -- The NodeState protobuf, encrypted because it carries every user secret
    -- and every Reality private key for that node.
    payload         LONGBLOB        NOT NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (node_id, version),
    CONSTRAINT fk_nds_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- OpenFlux
-- ---------------------------------------------------------------------------

-- The exit process on one node. One row per node because OpenFlux has a
-- single exit role per host, unlike Xray's many inbounds.
CREATE TABLE node_openflux (
    node_id         BIGINT UNSIGNED NOT NULL,
    enabled         TINYINT(1)      NOT NULL DEFAULT 0,
    -- l3 needs Linux and root and is the fast path; l4 is the portable one.
    mode            ENUM('l3','l4') NOT NULL DEFAULT 'l4',
    params          JSON            NULL,               -- local_ip, share_host, ...
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (node_id),
    CONSTRAINT fk_node_openflux_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One channel is one carrier rendezvous plus its key. OpenFlux allows exactly
-- one client per session, so a channel is a unit of capacity: the pool of
-- channels on a node is how many users can be connected over OpenFlux at
-- once, and leases hand them out.
CREATE TABLE openflux_channels (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uuid            CHAR(36)        NOT NULL,
    node_id         BIGINT UNSIGNED NOT NULL,
    name            VARCHAR(128)    NOT NULL,
    -- yandex, vyandex, boards, oneme, cupsonline, mailru, direct, phpbox.
    transport       VARCHAR(32)     NOT NULL,
    -- Document URL, room, or listen address for `direct`.
    url             VARCHAR(1024)   NOT NULL DEFAULT '',
    params          JSON            NULL,               -- non-secret extras
    -- AES-256-GCM key and KDF context, encrypted. Rotating the key is how a
    -- lease is revoked: the running session stops decrypting.
    encryption_key  VARBINARY(512)  NULL,
    session_context VARCHAR(255)    NULL,
    -- Credentials some carriers need (Yandex cookies, MAX token/uid).
    credentials     VARBINARY(8192) NULL,               -- encrypted JSON object
    enabled         TINYINT(1)      NOT NULL DEFAULT 1,
    -- Reported by the agent: whether a session is live on this channel now.
    session_active  TINYINT(1)      NOT NULL DEFAULT 0,
    last_error      VARCHAR(512)    NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_openflux_channels_uuid (uuid),
    KEY idx_openflux_channels_node (node_id, enabled),
    CONSTRAINT fk_openflux_channels_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A lease is a channel held by one user for a bounded time, renewed while the
-- client keeps using it. The unique key on channel_id for live rows is what
-- enforces "one client per channel" at the database level rather than in
-- application logic.
CREATE TABLE openflux_leases (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    channel_id      BIGINT UNSIGNED NOT NULL,
    user_id         BIGINT UNSIGNED NOT NULL,
    device_id       BIGINT UNSIGNED NULL,
    -- 1 while held, NULL once released. NULLs do not collide in a UNIQUE
    -- index, so (channel_id, active) permits any number of released rows and
    -- exactly one live one - a partial unique index, which MariaDB has no
    -- other way to express.
    active          TINYINT(1)      NULL,
    acquired_at     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    renewed_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at      DATETIME(3)     NOT NULL,
    released_at     DATETIME(3)     NULL,
    release_reason  VARCHAR(64)     NULL,               -- expired, released, revoked
    PRIMARY KEY (id),
    UNIQUE KEY uq_openflux_leases_live (channel_id, active),
    KEY idx_openflux_leases_user (user_id, active),
    KEY idx_openflux_leases_expires (expires_at),
    CONSTRAINT fk_openflux_leases_channel FOREIGN KEY (channel_id) REFERENCES openflux_channels (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uuid            CHAR(36)        NOT NULL,
    name            VARCHAR(128)    NOT NULL,
    comment         VARCHAR(512)    NULL,

    -- Subscription token. Stored in the clear because the panel must display
    -- the link and its QR code; it is a bearer credential and reissuing it
    -- simply replaces this value.
    sub_token       VARCHAR(64)     NOT NULL,
    sub_token_issued_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    -- Protocol credentials. One identity per user, reused across every node
    -- and inbound, so a user's config does not change when nodes come and go.
    vless_uuid      CHAR(36)        NOT NULL,
    password        VARBINARY(512)  NOT NULL,           -- Trojan + Hysteria2
    ss_password     VARBINARY(512)  NOT NULL,           -- Shadowsocks / 2022

    expires_at      DATETIME(3)     NULL,               -- NULL = never
    traffic_limit   BIGINT UNSIGNED NOT NULL DEFAULT 0, -- 0 = unlimited
    traffic_used    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    devices_limit   INT UNSIGNED    NOT NULL DEFAULT 0, -- 0 = unlimited

    -- Scheduled resets are not implemented yet; the columns exist so turning
    -- them on later does not touch live rows.
    reset_strategy  ENUM('manual','daily','weekly','monthly') NOT NULL DEFAULT 'manual',
    next_reset_at   DATETIME(3)     NULL,
    last_reset_at   DATETIME(3)     NULL,

    -- disabled is the admin's intent; expired and limited are derived and
    -- written by the enforcement job so the list can be filtered on them.
    status          ENUM('active','disabled','expired','limited') NOT NULL DEFAULT 'active',

    last_sub_fetch_at DATETIME(3)   NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_uuid (uuid),
    UNIQUE KEY uq_users_sub_token (sub_token),
    UNIQUE KEY uq_users_vless_uuid (vless_uuid),
    KEY idx_users_status (status),
    KEY idx_users_expires (expires_at),
    KEY idx_users_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Which node groups a user may use. No rows means no access.
CREATE TABLE user_group_members (
    user_id         BIGINT UNSIGNED NOT NULL,
    group_id        BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, group_id),
    KEY idx_ugm_group (group_id),
    CONSTRAINT fk_ugm_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_ugm_group FOREIGN KEY (group_id) REFERENCES node_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Devices seen on the subscription endpoint, identified by the X-HWID header.
-- The row is the device-limit ledger: a new HWID past the limit is refused.
CREATE TABLE user_devices (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         BIGINT UNSIGNED NOT NULL,
    hwid            VARCHAR(128)    NOT NULL,
    model           VARCHAR(128)    NULL,
    platform        VARCHAR(32)     NULL,
    app_version     VARCHAR(32)     NULL,
    first_seen_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_ip         VARCHAR(45)     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_devices (user_id, hwid),
    KEY idx_user_devices_seen (user_id, last_seen_at),
    CONSTRAINT fk_user_devices_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-user, per-node daily traffic. Daily buckets, because the charts are
-- hour/day/week and a row per report would grow without bound.
-- users.traffic_used carries the running total that limits are checked
-- against, so the hot path never aggregates this table.
CREATE TABLE user_traffic_daily (
    user_id         BIGINT UNSIGNED NOT NULL,
    node_id         BIGINT UNSIGNED NOT NULL,
    day             DATE            NOT NULL,
    uplink_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    downlink_bytes  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (user_id, node_id, day),
    KEY idx_utd_day (day),
    KEY idx_utd_node_day (node_id, day),
    CONSTRAINT fk_utd_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_utd_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Idempotency ledger for traffic reports. An agent that retries after a
-- dropped connection resends the same batch_id, and the insert fails, which
-- is what keeps totals from being double counted.
CREATE TABLE traffic_batches (
    node_id         BIGINT UNSIGNED NOT NULL,
    batch_id        CHAR(36)        NOT NULL,
    received_at     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (node_id, batch_id),
    KEY idx_traffic_batches_received (received_at),
    CONSTRAINT fk_traffic_batches_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Metrics and events
-- ---------------------------------------------------------------------------

-- Raw samples, kept for the hour and day views and pruned by retention.
CREATE TABLE node_metrics (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    node_id         BIGINT UNSIGNED NOT NULL,
    at              DATETIME(3)     NOT NULL,
    cpu_percent     FLOAT           NULL,
    load1           FLOAT           NULL,
    mem_used_bytes  BIGINT UNSIGNED NULL,
    mem_total_bytes BIGINT UNSIGNED NULL,
    disk_used_bytes BIGINT UNSIGNED NULL,
    disk_total_bytes BIGINT UNSIGNED NULL,
    -- Absolute counters as reported; rates are computed on read. A lost
    -- report then shows as a gap instead of a wrong total.
    net_rx_bytes    BIGINT UNSIGNED NULL,
    net_tx_bytes    BIGINT UNSIGNED NULL,
    uptime_seconds  BIGINT UNSIGNED NULL,
    online_users    INT UNSIGNED    NULL,
    tcp_connections INT UNSIGNED    NULL,
    PRIMARY KEY (id),
    KEY idx_node_metrics_node_at (node_id, at),
    KEY idx_node_metrics_at (at),
    CONSTRAINT fk_node_metrics_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Hourly rollup, so the week view does not scan raw samples.
CREATE TABLE node_metrics_hourly (
    node_id         BIGINT UNSIGNED NOT NULL,
    hour            DATETIME        NOT NULL,
    samples         INT UNSIGNED    NOT NULL DEFAULT 0,
    cpu_percent_avg FLOAT           NULL,
    cpu_percent_max FLOAT           NULL,
    mem_used_avg    BIGINT UNSIGNED NULL,
    disk_used_max   BIGINT UNSIGNED NULL,
    net_rx_delta    BIGINT UNSIGNED NULL,
    net_tx_delta    BIGINT UNSIGNED NULL,
    online_users_avg FLOAT          NULL,
    online_users_max INT UNSIGNED   NULL,
    PRIMARY KEY (node_id, hour),
    KEY idx_nmh_hour (hour),
    CONSTRAINT fk_nmh_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The fleet journal: node connects and disconnects, core crashes and
-- restarts, failed state applies, lease churn.
CREATE TABLE events (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    at              DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    severity        ENUM('info','warning','error') NOT NULL DEFAULT 'info',
    type            VARCHAR(64)     NOT NULL,
    core            ENUM('xray','wndns','openflux') NULL,
    node_id         BIGINT UNSIGNED NULL,
    user_id         BIGINT UNSIGNED NULL,
    message         VARCHAR(1024)   NOT NULL,
    details         JSON            NULL,
    PRIMARY KEY (id),
    KEY idx_events_at (at),
    KEY idx_events_node_at (node_id, at),
    KEY idx_events_type_at (type, at),
    KEY idx_events_severity_at (severity, at),
    CONSTRAINT fk_events_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE SET NULL,
    CONSTRAINT fk_events_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
