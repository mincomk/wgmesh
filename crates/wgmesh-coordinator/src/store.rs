use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use wgmesh_app::coordinator::PortError;
use wgmesh_app::coordinator::ports::{
    AuditEntry, Device, DeviceState, Directory, Network, NewDevice, NewJoinToken, NewNetwork,
    NewRelay, Placement, Relay, RelayState, Reports, TokenGrant, TokenKind, TokenStore,
};
use wgmesh_core::{DeviceId, Endpoint, Millis, PublicKey, RelayId};

/// Every table the coordinator owns, behind the ports the usecases know.
///
/// One connection pool serves all four ports: they are four views of one
/// database, and splitting them would buy a transaction boundary that is not
/// there.
pub struct Sqlite {
    pool: SqlitePool,
}

type DeviceRow = (i64, i64, String, Vec<u8>, Vec<u8>, String, String, String);
type RelayRow = (
    i64,
    String,
    Vec<u8>,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    i64,
);
type NetworkRow = (i64, String, String, i64, String);
type AuditRow = (
    i64,
    i64,
    String,
    String,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

impl Sqlite {
    /// Open the database, creating it when the URL says `mode=rwc`.
    ///
    /// WAL keeps a reader from blocking the writer, and a busy timeout lets the
    /// pool's connections queue instead of failing when they collide — which
    /// matters because two devices may spend the same join token at once.
    pub async fn open(url: &str, max_connections: u32) -> Result<Self, PortError> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(|error| PortError::fatal(format!("bad database url: {error}")))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(10))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await
            .map_err(storage)?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), PortError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|error| PortError::fatal(format!("migration failed: {error}")))
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn storage(error: sqlx::Error) -> PortError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return PortError::fatal(database.message().to_string());
        }
    }
    PortError::fatal(error.to_string())
}

fn blob(key: &PublicKey) -> Vec<u8> {
    key.as_bytes().to_vec()
}

fn key(bytes: &[u8]) -> Option<PublicKey> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}

fn to_device(row: DeviceRow) -> Result<Device, PortError> {
    Ok(Device {
        id: DeviceId(row.0 as u32),
        network_id: row.1 as u32,
        name: row.2,
        wg_pubkey: key(&row.3).ok_or_else(|| PortError::fatal("wg_pubkey torn"))?,
        api_pubkey: key(&row.4).ok_or_else(|| PortError::fatal("api_pubkey torn"))?,
        tunnel_ip: row.5,
        state: DeviceState::parse(&row.6)
            .ok_or_else(|| PortError::fatal(format!("unknown device state {}", row.6)))?,
        advertised: wgmesh_proto::bands::decode(&row.7),
    })
}

fn to_relay(row: RelayRow) -> Result<Relay, PortError> {
    Ok(Relay {
        id: RelayId(row.0 as u16),
        name: row.1,
        api_pubkey: key(&row.2).ok_or_else(|| PortError::fatal("relay key torn"))?,
        state: RelayState::parse(&row.3)
            .ok_or_else(|| PortError::fatal(format!("unknown relay state {}", row.3)))?,
        endpoint_host: row.4,
        port_range: row.5,
        region: row.6,
        provider: row.7,
        operator: row.8,
        last_heartbeat_at: row.9.map(|value| Millis::from_millis(value as u64)),
        agent_version: row.10,
        draining: row.11 != 0,
    })
}

fn to_network(row: NetworkRow) -> Network {
    Network {
        id: row.0 as u32,
        name: row.1,
        cidr: row.2,
        mtu: row.3 as u32,
        relay_policy: row.4,
    }
}

const DEVICE_COLUMNS: &str =
    "id, network_id, name, wg_pubkey, api_pubkey, tunnel_ip, state, advertised";
const RELAY_COLUMNS: &str = "id, name, api_pubkey, state, endpoint_host, port_range, region, \
     provider, operator, last_heartbeat_at, agent_version, draining";

#[async_trait::async_trait]
impl TokenStore for Sqlite {
    async fn insert_join_token(&self, token: &NewJoinToken) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO join_tokens (network_id, kind, token_hash, max_uses, auto_approve, \
             expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(token.network_id))
        .bind(token.kind.as_str())
        .bind(token.token_hash.to_vec())
        .bind(i64::from(token.max_uses))
        .bind(i64::from(token.auto_approve))
        .bind(token.expires_at.0 as i64)
        .bind(&token.created_by)
        .bind(token.created_at.0 as i64)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn consume_join_token(
        &self,
        hash: &[u8; 32],
        kind: TokenKind,
        at: Millis,
    ) -> Result<Option<TokenGrant>, PortError> {
        // One statement, one row count, one winner. The reference to `uses`
        // in the predicate and in the assignment is what makes concurrent
        // spenders safe: the row lock is taken before it is read.
        let row: Option<(i64, String, i64)> = sqlx::query_as(
            "UPDATE join_tokens SET uses = uses + 1 \
             WHERE token_hash = ? AND kind = ? AND revoked_at IS NULL \
               AND expires_at > ? AND uses < max_uses \
             RETURNING network_id, kind, auto_approve",
        )
        .bind(hash.to_vec())
        .bind(kind.as_str())
        .bind(at.0 as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;

        let Some((network_id, kind, auto_approve)) = row else {
            return Ok(None);
        };
        let Some(kind) = TokenKind::parse(&kind) else {
            return Ok(None);
        };
        Ok(Some(TokenGrant {
            network_id: network_id as u32,
            kind,
            auto_approve: auto_approve != 0,
        }))
    }

    async fn revoke_join_token(&self, hash: &[u8; 32], at: Millis) -> Result<bool, PortError> {
        let result = sqlx::query(
            "UPDATE join_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(at.0 as i64)
        .bind(hash.to_vec())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait::async_trait]
impl Directory for Sqlite {
    async fn insert_network(&self, spec: &NewNetwork) -> Result<Network, PortError> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO networks (name, cidr, mtu, relay_policy, created_at) \
             VALUES (?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&spec.name)
        .bind(&spec.cidr)
        .bind(i64::from(spec.mtu))
        .bind(&spec.relay_policy)
        .bind(spec.created_at.0 as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(storage)?;
        Ok(Network {
            id: id as u32,
            name: spec.name.clone(),
            cidr: spec.cidr.clone(),
            mtu: spec.mtu,
            relay_policy: spec.relay_policy.clone(),
        })
    }

    async fn network_by_name(&self, name: &str) -> Result<Option<Network>, PortError> {
        let row: Option<NetworkRow> =
            sqlx::query_as("SELECT id, name, cidr, mtu, relay_policy FROM networks WHERE name = ?")
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage)?;
        Ok(row.map(to_network))
    }

    async fn network_by_id(&self, id: u32) -> Result<Option<Network>, PortError> {
        let row: Option<NetworkRow> =
            sqlx::query_as("SELECT id, name, cidr, mtu, relay_policy FROM networks WHERE id = ?")
                .bind(i64::from(id))
                .fetch_optional(&self.pool)
                .await
                .map_err(storage)?;
        Ok(row.map(to_network))
    }

    async fn networks(&self) -> Result<Vec<Network>, PortError> {
        let rows: Vec<NetworkRow> =
            sqlx::query_as("SELECT id, name, cidr, mtu, relay_policy FROM networks ORDER BY id")
                .fetch_all(&self.pool)
                .await
                .map_err(storage)?;
        Ok(rows.into_iter().map(to_network).collect())
    }

    async fn insert_device(&self, spec: &NewDevice) -> Result<Device, PortError> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO devices (network_id, name, wg_pubkey, api_pubkey, tunnel_ip, state, \
             advertised, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(i64::from(spec.network_id))
        .bind(&spec.name)
        .bind(blob(&spec.wg_pubkey))
        .bind(blob(&spec.api_pubkey))
        .bind(&spec.tunnel_ip)
        .bind(spec.state.as_str())
        .bind(wgmesh_proto::bands::encode(&spec.advertised))
        .bind(spec.created_at.0 as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(storage)?;

        Ok(Device {
            id: DeviceId(id as u32),
            network_id: spec.network_id,
            name: spec.name.clone(),
            wg_pubkey: spec.wg_pubkey,
            api_pubkey: spec.api_pubkey,
            tunnel_ip: spec.tunnel_ip.clone(),
            state: spec.state,
            advertised: spec.advertised.clone(),
        })
    }

    async fn device_by_id(&self, id: DeviceId) -> Result<Option<Device>, PortError> {
        let row: Option<DeviceRow> = sqlx::query_as(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE id = ?"
        ))
        .bind(i64::from(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(to_device).transpose()
    }

    async fn device_by_api_pubkey(&self, public: &PublicKey) -> Result<Option<Device>, PortError> {
        let row: Option<DeviceRow> = sqlx::query_as(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE api_pubkey = ?"
        ))
        .bind(blob(public))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(to_device).transpose()
    }

    async fn device_by_name(
        &self,
        network_id: u32,
        name: &str,
    ) -> Result<Option<Device>, PortError> {
        let row: Option<DeviceRow> = sqlx::query_as(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE network_id = ? AND name = ?"
        ))
        .bind(i64::from(network_id))
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(to_device).transpose()
    }

    async fn devices_of(&self, network_id: u32) -> Result<Vec<Device>, PortError> {
        let rows: Vec<DeviceRow> = sqlx::query_as(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE network_id = ? ORDER BY id"
        ))
        .bind(i64::from(network_id))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(to_device).collect()
    }

    async fn set_device_state(&self, id: DeviceId, state: DeviceState) -> Result<(), PortError> {
        sqlx::query("UPDATE devices SET state = ? WHERE id = ?")
            .bind(state.as_str())
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn set_device_wg_pubkey(&self, id: DeviceId, key: &PublicKey) -> Result<(), PortError> {
        sqlx::query("UPDATE devices SET wg_pubkey = ? WHERE id = ?")
            .bind(blob(key))
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn set_device_advertised(&self, id: DeviceId, list: &[String]) -> Result<(), PortError> {
        sqlx::query("UPDATE devices SET advertised = ? WHERE id = ?")
            .bind(wgmesh_proto::bands::encode(list))
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn touch_device(&self, id: DeviceId, at: Millis) -> Result<(), PortError> {
        sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
            .bind(at.0 as i64)
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn insert_relay(&self, spec: &NewRelay) -> Result<Relay, PortError> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO relays (name, api_pubkey, state, endpoint_host, port_range, region, \
             provider, operator, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&spec.name)
        .bind(blob(&spec.api_pubkey))
        .bind(spec.state.as_str())
        .bind(&spec.endpoint_host)
        .bind(&spec.port_range)
        .bind(spec.region.as_deref())
        .bind(spec.provider.as_deref())
        .bind(spec.operator.as_deref())
        .bind(spec.created_at.0 as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(storage)?;

        Ok(Relay {
            id: RelayId(id as u16),
            name: spec.name.clone(),
            api_pubkey: spec.api_pubkey,
            state: spec.state,
            endpoint_host: spec.endpoint_host.clone(),
            port_range: spec.port_range.clone(),
            region: spec.region.clone(),
            provider: spec.provider.clone(),
            operator: spec.operator.clone(),
            last_heartbeat_at: None,
            agent_version: None,
            draining: false,
        })
    }

    async fn relay_by_id(&self, id: RelayId) -> Result<Option<Relay>, PortError> {
        let row: Option<RelayRow> =
            sqlx::query_as(&format!("SELECT {RELAY_COLUMNS} FROM relays WHERE id = ?"))
                .bind(i64::from(id.0))
                .fetch_optional(&self.pool)
                .await
                .map_err(storage)?;
        row.map(to_relay).transpose()
    }

    async fn relay_by_name(&self, name: &str) -> Result<Option<Relay>, PortError> {
        let row: Option<RelayRow> = sqlx::query_as(&format!(
            "SELECT {RELAY_COLUMNS} FROM relays WHERE name = ?"
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(to_relay).transpose()
    }

    async fn relay_by_api_pubkey(&self, public: &PublicKey) -> Result<Option<Relay>, PortError> {
        let row: Option<RelayRow> = sqlx::query_as(&format!(
            "SELECT {RELAY_COLUMNS} FROM relays WHERE api_pubkey = ?"
        ))
        .bind(blob(public))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(to_relay).transpose()
    }

    async fn relays_of(&self, network_id: u32) -> Result<Vec<Relay>, PortError> {
        let rows: Vec<RelayRow> = sqlx::query_as(&format!(
            "SELECT {} FROM relays r JOIN relay_networks rn ON rn.relay_id = r.id \
             WHERE rn.network_id = ? ORDER BY r.id",
            RELAY_COLUMNS
                .split(", ")
                .map(|column| format!("r.{column}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .bind(i64::from(network_id))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(to_relay).collect()
    }

    async fn link_relay_network(&self, relay: RelayId, network_id: u32) -> Result<(), PortError> {
        sqlx::query("INSERT OR IGNORE INTO relay_networks (relay_id, network_id) VALUES (?, ?)")
            .bind(i64::from(relay.0))
            .bind(i64::from(network_id))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn set_relay_state(&self, id: RelayId, state: RelayState) -> Result<(), PortError> {
        sqlx::query("UPDATE relays SET state = ? WHERE id = ?")
            .bind(state.as_str())
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn set_relay_draining(&self, id: RelayId, draining: bool) -> Result<(), PortError> {
        sqlx::query("UPDATE relays SET draining = ? WHERE id = ?")
            .bind(i64::from(draining))
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn record_heartbeat(
        &self,
        id: RelayId,
        at: Millis,
        agent_version: Option<&str>,
    ) -> Result<(), PortError> {
        sqlx::query("UPDATE relays SET last_heartbeat_at = ?, agent_version = ? WHERE id = ?")
            .bind(at.0 as i64)
            .bind(agent_version)
            .bind(i64::from(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Placement for Sqlite {
    async fn assign_slot(
        &self,
        relay: RelayId,
        device: DeviceId,
        port: u16,
    ) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO relay_slots (relay_id, device_id, udp_port) VALUES (?, ?, ?) \
             ON CONFLICT (relay_id, device_id) DO UPDATE SET udp_port = excluded.udp_port",
        )
        .bind(i64::from(relay.0))
        .bind(i64::from(device.0))
        .bind(i64::from(port))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn slot_for(&self, relay: RelayId, device: DeviceId) -> Result<Option<u16>, PortError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT udp_port FROM relay_slots WHERE relay_id = ? AND device_id = ?")
                .bind(i64::from(relay.0))
                .bind(i64::from(device.0))
                .fetch_optional(&self.pool)
                .await
                .map_err(storage)?;
        Ok(row.map(|(port,)| port as u16))
    }

    async fn slots_of(&self, relay: RelayId) -> Result<Vec<(DeviceId, u16)>, PortError> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT device_id, udp_port FROM relay_slots WHERE relay_id = ? ORDER BY device_id",
        )
        .bind(i64::from(relay.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        Ok(rows
            .into_iter()
            .map(|(device, port)| (DeviceId(device as u32), port as u16))
            .collect())
    }

    async fn assign_pair(
        &self,
        device_a: DeviceId,
        device_b: DeviceId,
        relay: RelayId,
        at: Millis,
    ) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO pair_assignments (device_a, device_b, relay_id, assigned_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (device_a, device_b) DO UPDATE SET relay_id = excluded.relay_id, \
             assigned_at = excluded.assigned_at",
        )
        .bind(i64::from(device_a.0))
        .bind(i64::from(device_b.0))
        .bind(i64::from(relay.0))
        .bind(at.0 as i64)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn relay_for_pair(
        &self,
        device_a: DeviceId,
        device_b: DeviceId,
    ) -> Result<Option<RelayId>, PortError> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT relay_id FROM pair_assignments WHERE device_a = ? AND device_b = ?",
        )
        .bind(i64::from(device_a.0))
        .bind(i64::from(device_b.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        Ok(row.map(|(relay,)| RelayId(relay as u16)))
    }

    async fn pairs_of(&self, relay: RelayId) -> Result<Vec<(DeviceId, DeviceId)>, PortError> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT device_a, device_b FROM pair_assignments WHERE relay_id = ? ORDER BY device_a, device_b",
        )
        .bind(i64::from(relay.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        Ok(rows
            .into_iter()
            .map(|(left, right)| (DeviceId(left as u32), DeviceId(right as u32)))
            .collect())
    }
}

#[async_trait::async_trait]
impl Reports for Sqlite {
    async fn record_observation(
        &self,
        relay: RelayId,
        device: DeviceId,
        endpoint: Endpoint,
        at: Millis,
    ) -> Result<(), PortError> {
        let address: SocketAddr = endpoint.addr();
        sqlx::query(
            "INSERT INTO relay_observations (relay_id, device_id, ip, port, seen_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (relay_id, device_id) DO UPDATE SET ip = excluded.ip, \
             port = excluded.port, seen_at = excluded.seen_at",
        )
        .bind(i64::from(relay.0))
        .bind(i64::from(device.0))
        .bind(address.ip().to_string())
        .bind(i64::from(address.port()))
        .bind(at.0 as i64)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn observation(
        &self,
        relay: RelayId,
        device: DeviceId,
    ) -> Result<Option<(Endpoint, Millis)>, PortError> {
        let row: Option<(String, i64, i64)> = sqlx::query_as(
            "SELECT ip, port, seen_at FROM relay_observations WHERE relay_id = ? AND device_id = ?",
        )
        .bind(i64::from(relay.0))
        .bind(i64::from(device.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;

        let Some((ip, port, seen_at)) = row else {
            return Ok(None);
        };
        let address: SocketAddr = format!("{ip}:{port}")
            .parse()
            .map_err(|_| PortError::fatal("observation address unreadable"))?;
        Ok(Some((
            Endpoint::new(address),
            Millis::from_millis(seen_at as u64),
        )))
    }

    async fn record_traffic(
        &self,
        relay: RelayId,
        device: DeviceId,
        rx_bytes: u64,
        tx_bytes: u64,
        period_start: Millis,
    ) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO relay_traffic (relay_id, device_id, rx_bytes, tx_bytes, period_start) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (relay_id, device_id, period_start) DO UPDATE SET \
             rx_bytes = excluded.rx_bytes, tx_bytes = excluded.tx_bytes",
        )
        .bind(i64::from(relay.0))
        .bind(i64::from(device.0))
        .bind(rx_bytes as i64)
        .bind(tx_bytes as i64)
        .bind(period_start.0 as i64)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn audit(&self, entry: &AuditEntry) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO audit_log (ts, actor, action, network_id, device_id, relay_id, detail) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.at.0 as i64)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(entry.network_id.map(i64::from))
        .bind(entry.device_id.map(|id| i64::from(id.0)))
        .bind(entry.relay_id.map(|id| i64::from(id.0)))
        .bind(entry.detail.as_deref())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn recent_audit(&self, limit: u32) -> Result<Vec<AuditEntry>, PortError> {
        let rows: Vec<AuditRow> = sqlx::query_as(
            "SELECT ts, id, actor, action, network_id, device_id, relay_id, detail FROM audit_log \
             ORDER BY id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        Ok(rows
            .into_iter()
            .map(|row| AuditEntry {
                at: Millis::from_millis(row.0 as u64),
                actor: row.2,
                action: row.3,
                network_id: row.4.map(|value| value as u32),
                device_id: row.5.map(|value| DeviceId(value as u32)),
                relay_id: row.6.map(|value| RelayId(value as u16)),
                detail: row.7,
            })
            .collect())
    }
}

impl Sqlite {
    /// A cheap number that changes whenever the configuration a node can see
    /// changes: how many devices there are, how many of each state, how many
    /// relays, pairs and networks.
    ///
    /// It is deliberately a read of the *configuration* rather than a counter
    /// the daemon keeps in memory. `wgmeshd approve` and `wgmeshd device revoke`
    /// are separate processes writing this same database, so an in-process
    /// broadcast would be blind to the changes an operator makes by hand — and
    /// those are exactly the changes a node must learn about quickly.
    pub async fn config_version(&self) -> Result<u64, PortError> {
        let (devices, pending, active, revoked, relays, pairs, networks): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM devices), \
                    (SELECT COUNT(*) FROM devices WHERE state = ?1), \
                    (SELECT COUNT(*) FROM devices WHERE state = ?2), \
                    (SELECT COUNT(*) FROM devices WHERE state = ?3), \
                    (SELECT COUNT(*) FROM relays), \
                    (SELECT COUNT(*) FROM pair_assignments), \
                    (SELECT COUNT(*) FROM networks)",
        )
        .bind(DeviceState::Pending.as_str())
        .bind(DeviceState::Active.as_str())
        .bind(DeviceState::Revoked.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(storage)?;

        // FNV-1a over the tuple: a change in any field changes the number, and
        // the exact value never leaves the coordinator.
        let mut version: u64 = 0xcbf2_9ce4_8422_2325;
        for field in [devices, pending, active, revoked, relays, pairs, networks] {
            for byte in field.to_le_bytes() {
                version ^= u64::from(byte);
                version = version.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        Ok(version)
    }
}
