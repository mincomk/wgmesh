use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use crate::auth::{Credential, DeviceState};

#[derive(Debug)]
pub enum StoreError {
    Sql(sqlx::Error),
    Migrate(sqlx::migrate::MigrateError),
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sql(error)
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sql(error) => write!(f, "database error: {error}"),
            Self::Migrate(error) => write!(f, "migration error: {error}"),
        }
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: i64,
    pub device_key: String,
    pub network_id: i64,
    pub name: String,
    pub wg_pubkey: Vec<u8>,
    pub api_pubkey: Vec<u8>,
    pub tunnel_ip: String,
    pub state: DeviceState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRow {
    pub id: i64,
    pub name: String,
    pub cidr: String,
    pub mtu: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedToken {
    pub network_id: i64,
    pub kind: String,
    pub auto_approve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub device_id: Option<i64>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct NewDevice {
    pub device_key: String,
    pub network_id: i64,
    pub name: String,
    pub wg_pubkey: Vec<u8>,
    pub api_pubkey: Vec<u8>,
    pub tunnel_ip: String,
    pub state: DeviceState,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

fn device_from_row(row: &sqlx::sqlite::SqliteRow) -> StoreResult<DeviceRow> {
    let state: String = row.try_get("state")?;
    Ok(DeviceRow {
        id: row.try_get("id")?,
        device_key: row.try_get("device_key")?,
        network_id: row.try_get("network_id")?,
        name: row.try_get("name")?,
        wg_pubkey: row.try_get("wg_pubkey")?,
        api_pubkey: row.try_get("api_pubkey")?,
        tunnel_ip: row.try_get("tunnel_ip")?,
        state: DeviceState::parse(&state).unwrap_or(DeviceState::Pending),
    })
}

const DEVICE_COLUMNS: &str = "id, device_key, network_id, name, wg_pubkey, api_pubkey, tunnel_ip, state";

impl Store {
    // A SQLite in-memory database lives exactly as long as its pool, and a single
    // connection is what makes every query in a test see the same one.
    pub async fn open_in_memory() -> StoreResult<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        Self::migrated(pool).await
    }

    pub async fn open_file(path: &str) -> StoreResult<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(&format!("sqlite:{path}?mode=rwc"))
            .await?;
        Self::migrated(pool).await
    }

    async fn migrated(pool: SqlitePool) -> StoreResult<Self> {
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(StoreError::Migrate)?;
        Ok(Self { pool })
    }

    // Tunnel addresses are handed out in order inside the network's IPv4 band,
    // skipping the ones already taken. Every address carries a prefix length,
    // because that is what the core's `Allowed` speaks.
    pub async fn next_tunnel_ip(&self, network_id: i64) -> StoreResult<String> {
        let row = sqlx::query("SELECT cidr FROM networks WHERE id = ?")
            .bind(network_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;
        let cidr: String = row.try_get("cidr")?;
        let base = cidr.split('/').next().unwrap_or("10.77.0.0");
        let octets: Vec<&str> = base.split('.').collect();
        let prefix = if octets.len() == 4 {
            format!("{}.{}.{}.", octets[0], octets[1], octets[2])
        } else {
            String::from("10.77.0.")
        };
        let rows = sqlx::query("SELECT tunnel_ip FROM devices WHERE network_id = ?")
            .bind(network_id)
            .fetch_all(&self.pool)
            .await?;
        let mut taken = Vec::with_capacity(rows.len());
        for row in &rows {
            let ip: String = row.try_get("tunnel_ip")?;
            taken.push(ip.split('/').next().unwrap_or("").to_owned());
        }
        let mut host: u32 = 2;
        loop {
            let candidate = format!("{prefix}{host}");
            if !taken.contains(&candidate) {
                return Ok(format!("{candidate}/32"));
            }
            host += 1;
            if host > 65_534 {
                return Err(StoreError::Sql(sqlx::Error::Protocol(String::from(
                    "the tunnel band has no free address left",
                ))));
            }
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn create_network(
        &self,
        name: &str,
        cidr: &str,
        mtu: i64,
        now: i64,
    ) -> StoreResult<i64> {
        let row = sqlx::query("INSERT INTO networks (name, cidr, mtu, created_at) VALUES (?, ?, ?, ?) RETURNING id")
            .bind(name)
            .bind(cidr)
            .bind(mtu)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("id")?)
    }

    pub async fn network(&self, network_id: i64) -> StoreResult<Option<NetworkRow>> {
        let row = sqlx::query("SELECT id, name, cidr, mtu FROM networks WHERE id = ?")
            .bind(network_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(NetworkRow {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                cidr: row.try_get("cidr")?,
                mtu: row.try_get("mtu")?,
            })
        })
        .transpose()
    }

    // The token itself never reaches the database: only its SHA-256 does, so a
    // dump of this table cannot be turned back into a usable token.
    pub async fn create_join_token(
        &self,
        network_id: i64,
        kind: &str,
        token: &str,
        max_uses: i64,
        auto_approve: bool,
        expires_at: i64,
        created_by: &str,
        now: i64,
    ) -> StoreResult<()> {
        let hash = wgmesh_proto::signed::sha256_hex(token.as_bytes());
        sqlx::query(
            "INSERT INTO join_tokens (network_id, kind, token_hash, max_uses, auto_approve, expires_at, created_by, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(network_id)
        .bind(kind)
        .bind(hash.as_bytes().to_vec())
        .bind(max_uses)
        .bind(i64::from(auto_approve))
        .bind(expires_at)
        .bind(created_by)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_join_token(&self, token: &str, now: i64) -> StoreResult<bool> {
        let hash = wgmesh_proto::signed::sha256_hex(token.as_bytes());
        let done = sqlx::query("UPDATE join_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(hash.as_bytes().to_vec())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    // One statement, so two callers racing a single-use token cannot both win.
    pub async fn redeem_join_token(
        &self,
        token: &str,
        now: i64,
    ) -> StoreResult<Option<RedeemedToken>> {
        let hash = wgmesh_proto::signed::sha256_hex(token.as_bytes());
        let row = sqlx::query(
            "UPDATE join_tokens SET uses = uses + 1
              WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? AND uses < max_uses
             RETURNING network_id, kind, auto_approve",
        )
        .bind(hash.as_bytes().to_vec())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let auto_approve: i64 = row.try_get("auto_approve")?;
            Ok(RedeemedToken {
                network_id: row.try_get("network_id")?,
                kind: row.try_get("kind")?,
                auto_approve: auto_approve != 0,
            })
        })
        .transpose()
    }

    pub async fn insert_device(&self, device: &NewDevice) -> StoreResult<i64> {
        let row = sqlx::query(
            "INSERT INTO devices (device_key, network_id, name, wg_pubkey, api_pubkey, tunnel_ip, state, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&device.device_key)
        .bind(device.network_id)
        .bind(&device.name)
        .bind(&device.wg_pubkey)
        .bind(&device.api_pubkey)
        .bind(&device.tunnel_ip)
        .bind(device.state.as_str())
        .bind(device.created_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("id")?)
    }

    pub async fn device(&self, device_key: &str) -> StoreResult<Option<DeviceRow>> {
        let row = sqlx::query(&format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE device_key = ?"))
            .bind(device_key)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(device_from_row).transpose()
    }

    pub async fn credential(&self, device_key: &str) -> StoreResult<Option<Credential>> {
        let row = sqlx::query("SELECT device_key, api_pubkey, state FROM devices WHERE device_key = ?")
            .bind(device_key)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let state: String = row.try_get("state")?;
            let api_pubkey: Vec<u8> = row.try_get("api_pubkey")?;
            let api_pubkey: [u8; 32] = api_pubkey
                .try_into()
                .map_err(|_| sqlx::Error::Decode("api_pubkey is not 32 bytes".into()))?;
            Ok(Credential {
                device_id: row.try_get("device_key")?,
                api_pubkey,
                state: DeviceState::parse(&state).unwrap_or(DeviceState::Pending),
            })
        })
        .transpose()
    }

    pub async fn devices_in_state(
        &self,
        network_id: i64,
        state: DeviceState,
    ) -> StoreResult<Vec<DeviceRow>> {
        let rows = sqlx::query(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE network_id = ? AND state = ? ORDER BY id"
        ))
        .bind(network_id)
        .bind(state.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(device_from_row).collect()
    }

    pub async fn set_device_state(
        &self,
        device_key: &str,
        state: DeviceState,
        now: i64,
    ) -> StoreResult<bool> {
        let done = sqlx::query("UPDATE devices SET state = ?, last_seen_at = ? WHERE device_key = ?")
            .bind(state.as_str())
            .bind(now)
            .bind(device_key)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn touch_device(&self, device_key: &str, now: i64) -> StoreResult<()> {
        sqlx::query("UPDATE devices SET last_seen_at = ? WHERE device_key = ?")
            .bind(now)
            .bind(device_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rotate_wg_key(
        &self,
        device_key: &str,
        wg_pubkey: &[u8],
        now: i64,
    ) -> StoreResult<bool> {
        let done = sqlx::query("UPDATE devices SET wg_pubkey = ?, last_seen_at = ? WHERE device_key = ? AND state = 'active'")
            .bind(wg_pubkey)
            .bind(now)
            .bind(device_key)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn record_audit(&self, entry: &AuditEntry) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO audit_log (ts, actor, action, device_id, detail) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(entry.ts)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(entry.device_id)
        .bind(&entry.detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn audit_entries(&self) -> StoreResult<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT ts, actor, action, device_id, detail FROM audit_log ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(AuditEntry {
                    ts: row.try_get("ts")?,
                    actor: row.try_get("actor")?,
                    action: row.try_get("action")?,
                    device_id: row.try_get("device_id")?,
                    detail: row.try_get("detail")?,
                })
            })
            .collect()
    }

    pub async fn tables(&self) -> StoreResult<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|row| Ok(row.try_get("name")?)).collect()
    }

    pub async fn columns(&self, table: &str) -> StoreResult<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM pragma_table_info(?)")
            .bind(table)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|row| Ok(row.try_get("name")?)).collect()
    }

    // The stored join-token column, exposed so a test can prove that what is on
    // disk is a hash and not the token.
    pub async fn join_token_hashes(&self) -> StoreResult<Vec<String>> {
        let rows = sqlx::query("SELECT token_hash FROM join_tokens")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let hash: Vec<u8> = row.try_get("token_hash")?;
                Ok(String::from_utf8_lossy(&hash).into_owned())
            })
            .collect()
    }
}
