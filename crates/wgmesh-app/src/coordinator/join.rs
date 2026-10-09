use wgmesh_ports::Clock;
use wgmesh_ports::coordinator::{
    AuditEntry, DeviceState, Directory, NewDevice, Placement, Reports, TokenKind, TokenStore,
};

use super::config::{peer_views, relay_slots};
use super::net::{host_prefix, next_free_host};
use super::placement::{ensure_slots, pair_with_network};
use super::types::{JoinError, JoinOutcome, JoinPolicy, JoinRequest, PlacePolicy};

/// Admit a device against a join token.
///
/// The token is spent before anything else happens, in one atomic step, so two
/// devices racing on the same single-use token cannot both get in. Everything
/// that follows — address allocation, the device row, its slots — is only
/// reached by the one that won.
pub struct JoinDevice<'a> {
    pub tokens: &'a dyn TokenStore,
    pub directory: &'a dyn Directory,
    pub placement: &'a dyn Placement,
    pub reports: &'a dyn Reports,
    pub clock: &'a dyn Clock,
    pub policy: JoinPolicy,
    /// How a pair's relay is judged still reachable, so a join cannot keep a
    /// pair on a relay that has gone quiet.
    pub place_policy: PlacePolicy,
}

impl JoinDevice<'_> {
    pub async fn execute(&self, request: JoinRequest) -> Result<JoinOutcome, JoinError> {
        let now = self.clock.now();

        // A token that did not survive decoding is refused exactly like one
        // that was spent, so nothing distinguishes the two from outside.
        let Some(hash) = request.token_hash else {
            return Err(JoinError::TokenRefused);
        };
        let grant = self
            .tokens
            .consume_join_token(&hash, TokenKind::Device, now)
            .await?
            .ok_or(JoinError::TokenRefused)?;

        let network = self
            .directory
            .network_by_id(grant.network_id)
            .await?
            .ok_or(JoinError::NetworkUnknown(grant.network_id))?;

        let existing = self.directory.devices_of(network.id).await?;
        if existing.len() as u32 >= self.policy.max_devices_per_network {
            return Err(JoinError::NetworkFull {
                limit: self.policy.max_devices_per_network,
            });
        }
        if existing.iter().any(|device| device.name == request.name) {
            return Err(JoinError::Duplicate("name"));
        }
        if existing
            .iter()
            .any(|device| device.api_pubkey == request.api_pubkey)
        {
            return Err(JoinError::Duplicate("api_pubkey"));
        }

        let taken: Vec<String> = existing
            .iter()
            .map(|device| device.tunnel_ip.clone())
            .collect();
        let address = next_free_host(&network.cidr, &taken, self.policy.reserved_hosts)
            .ok_or(JoinError::AddressExhausted)?;

        let mut advertised = vec![host_prefix(&address)];
        for band in &request.advertised {
            if !advertised.contains(band) {
                advertised.push(band.clone());
            }
        }

        let state = if grant.auto_approve && self.policy.allow_auto_approve {
            DeviceState::Active
        } else {
            DeviceState::Pending
        };

        let device = self
            .directory
            .insert_device(&NewDevice {
                network_id: network.id,
                name: request.name,
                wg_pubkey: request.wg_pubkey,
                api_pubkey: request.api_pubkey,
                tunnel_ip: address,
                state,
                advertised,
                created_at: now,
            })
            .await?;

        if device.state == DeviceState::Active {
            ensure_slots(self.directory, self.placement, &device)
                .await
                .map_err(map_placement)?;
            pair_with_network(
                self.directory,
                self.placement,
                self.clock,
                self.place_policy,
                &device,
            )
            .await
            .map_err(map_placement)?;
        }

        self.reports
            .audit(&AuditEntry {
                at: now,
                actor: format!("device:{}", device.name),
                action: "device.join".to_string(),
                network_id: Some(network.id),
                device_id: Some(device.id),
                relay_id: None,
                detail: Some(format!("state={}", device.state.as_str())),
            })
            .await?;

        let peers = peer_views(self.directory, self.placement, &device).await?;
        let relay_pool = relay_slots(self.directory, self.placement, &device).await?;

        Ok(JoinOutcome {
            device_id: device.id,
            state: device.state,
            network,
            tunnel_ip: device.tunnel_ip,
            peers,
            relay_pool,
        })
    }
}

fn map_placement(error: super::types::PlaceError) -> JoinError {
    match error {
        super::types::PlaceError::Store(inner) => JoinError::Store(inner),
        other => JoinError::Placement(other),
    }
}
