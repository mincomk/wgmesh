-- wgmesh coordinator schema, revision 1.
--
-- Every table here is the design document's data model, table for table.
-- The coordinator is the only writer: relays and devices report through the
-- HTTP surface and never touch the database directly.

CREATE TABLE networks (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  cidr TEXT NOT NULL,
  mtu INTEGER NOT NULL DEFAULT 1420,
  relay_policy TEXT NOT NULL DEFAULT 'any',
  created_at INTEGER NOT NULL
);

CREATE TABLE join_tokens (
  id INTEGER PRIMARY KEY,
  network_id INTEGER NOT NULL REFERENCES networks(id),
  kind TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE,
  max_uses INTEGER NOT NULL DEFAULT 1,
  uses INTEGER NOT NULL DEFAULT 0,
  auto_approve INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE devices (
  id INTEGER PRIMARY KEY,
  network_id INTEGER NOT NULL REFERENCES networks(id),
  name TEXT NOT NULL,
  wg_pubkey BLOB NOT NULL,
  api_pubkey BLOB NOT NULL UNIQUE,
  tunnel_ip TEXT NOT NULL,
  state TEXT NOT NULL,
  last_seen_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE (network_id, tunnel_ip),
  UNIQUE (network_id, wg_pubkey)
);

CREATE TABLE relays (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  api_pubkey BLOB NOT NULL UNIQUE,
  state TEXT NOT NULL,
  endpoint_host TEXT NOT NULL,
  port_range TEXT NOT NULL,
  region TEXT,
  provider TEXT,
  operator TEXT,
  last_heartbeat_at INTEGER,
  agent_version TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE relay_networks (
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  network_id INTEGER NOT NULL REFERENCES networks(id),
  PRIMARY KEY (relay_id, network_id)
);

CREATE TABLE relay_slots (
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  device_id INTEGER NOT NULL REFERENCES devices(id),
  udp_port INTEGER NOT NULL,
  PRIMARY KEY (relay_id, device_id),
  UNIQUE (relay_id, udp_port)
);

CREATE TABLE pair_assignments (
  device_a INTEGER NOT NULL REFERENCES devices(id),
  device_b INTEGER NOT NULL REFERENCES devices(id),
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  assigned_at INTEGER NOT NULL,
  PRIMARY KEY (device_a, device_b)
);

CREATE TABLE relay_observations (
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  device_id INTEGER NOT NULL REFERENCES devices(id),
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  seen_at INTEGER NOT NULL,
  PRIMARY KEY (relay_id, device_id)
);

CREATE TABLE relay_traffic (
  relay_id INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  rx_bytes INTEGER NOT NULL,
  tx_bytes INTEGER NOT NULL,
  period_start INTEGER NOT NULL,
  PRIMARY KEY (relay_id, device_id, period_start)
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  network_id INTEGER,
  device_id INTEGER,
  relay_id INTEGER,
  detail TEXT
);

CREATE INDEX devices_by_network_state ON devices (network_id, state);
CREATE INDEX relays_by_state ON relays (state);
CREATE INDEX audit_log_by_ts ON audit_log (ts);
