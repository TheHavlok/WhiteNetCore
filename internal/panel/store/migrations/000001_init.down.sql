-- Reverse of 000001_init. Dropped children first so the foreign keys go
-- quietly, in the opposite order of creation.
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS node_metrics_hourly;
DROP TABLE IF EXISTS node_metrics;
DROP TABLE IF EXISTS traffic_batches;
DROP TABLE IF EXISTS user_traffic_daily;
DROP TABLE IF EXISTS user_devices;
DROP TABLE IF EXISTS user_group_members;
DROP TABLE IF EXISTS openflux_leases;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS openflux_channels;
DROP TABLE IF EXISTS node_openflux;
DROP TABLE IF EXISTS node_desired_state;
DROP TABLE IF EXISTS node_inbounds;
DROP TABLE IF EXISTS inbound_template_targets;
DROP TABLE IF EXISTS inbound_templates;
DROP TABLE IF EXISTS ca_keys;
DROP TABLE IF EXISTS node_certs;
DROP TABLE IF EXISTS node_tokens;
DROP TABLE IF EXISTS node_group_members;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS node_groups;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS admin_audit;
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS admins;
