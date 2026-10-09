use wgmesh_core::DeviceId;
use wgmesh_ports::Clock;
use wgmesh_ports::coordinator::{AuditEntry, Device, DeviceState, Directory, Placement, Reports};

use super::placement::{ensure_slots, pair_with_network};
use super::types::{ApproveError, PlaceError, PlacePolicy};

/// Move a device from `pending` to `active`, and give it its slots and its
/// pairs.
///
/// A device admitted by a token that does not auto-approve sits in `pending`
/// until this runs: it is in no peer list, holds no slot, and is paired with
/// nobody, so a leaked token costs an operator one command, not a mesh member.
pub struct ApproveDevice<'a> {
    pub directory: &'a dyn Directory,
    pub placement: &'a dyn Placement,
    pub reports: &'a dyn Reports,
    pub clock: &'a dyn Clock,
    pub policy: PlacePolicy,
}

impl ApproveDevice<'_> {
    pub async fn execute(&self, actor: &str, device: DeviceId) -> Result<Device, ApproveError> {
        let record = self
            .directory
            .device_by_id(device)
            .await?
            .ok_or(ApproveError::UnknownDevice(device))?;

        if record.state == DeviceState::Revoked {
            return Err(ApproveError::NotApprovable(record.state));
        }

        if record.state == DeviceState::Pending {
            self.directory
                .set_device_state(device, DeviceState::Active)
                .await?;
            self.reports
                .audit(&AuditEntry {
                    at: self.clock.now(),
                    actor: actor.to_string(),
                    action: "device.approve".to_string(),
                    network_id: Some(record.network_id),
                    device_id: Some(device),
                    relay_id: None,
                    detail: None,
                })
                .await?;
        }

        let updated = self
            .directory
            .device_by_id(device)
            .await?
            .ok_or(ApproveError::UnknownDevice(device))?;

        // Idempotent: approving an already-active device repairs placement
        // rather than failing.
        ensure_slots(self.directory, self.placement, &updated)
            .await
            .map_err(map_placement)?;
        pair_with_network(
            self.directory,
            self.placement,
            self.clock,
            self.policy,
            &updated,
        )
        .await
        .map_err(map_placement)?;

        self.directory
            .device_by_id(device)
            .await?
            .ok_or(ApproveError::UnknownDevice(device))
    }

    /// Take a device out of the mesh. The next synchronisation drops it from
    /// every peer list, which is what actually revokes it: WireGuard has no
    /// session cancellation, so the list is the ACL.
    pub async fn revoke(&self, actor: &str, device: DeviceId) -> Result<(), ApproveError> {
        let record = self
            .directory
            .device_by_id(device)
            .await?
            .ok_or(ApproveError::UnknownDevice(device))?;
        self.directory
            .set_device_state(device, DeviceState::Revoked)
            .await?;
        self.reports
            .audit(&AuditEntry {
                at: self.clock.now(),
                actor: actor.to_string(),
                action: "device.revoke".to_string(),
                network_id: Some(record.network_id),
                device_id: Some(device),
                relay_id: None,
                detail: None,
            })
            .await?;
        Ok(())
    }
}

fn map_placement(error: PlaceError) -> ApproveError {
    match error {
        PlaceError::Store(inner) => ApproveError::Store(inner),
        other => ApproveError::Placement(other),
    }
}
