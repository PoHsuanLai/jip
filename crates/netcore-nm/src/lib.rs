//! NetworkManager backend for netcore.
//!
//! Provides two things the netlink backend can't:
//! 1. **Profiles** — the NM-managed connection name, autoconnect flag, and
//!    type string. Consumed by [`profiles_by_iface`] so the netlink
//!    backend's connections can be enriched.
//! 2. **Write actions** — prefer/reconnect/forget/set_autoconnect, exposed
//!    via the [`Actions`](netcore::traits::Actions) trait.
//!
//! Runs sync like the other backends: builds a tokio `current_thread`
//! runtime per call (~1ms). NM D-Bus calls complete in single-digit ms
//! on a warm bus, so there's no point keeping the connection around.
//!
//! When NM isn't on the bus, [`NmBackend::new`] returns `None` and the
//! CLI runs without profile info or write actions — the tool degrades,
//! it doesn't fail.

use std::collections::HashMap;

use netcore::connection::{ConnectionId, Profile};
use netcore::traits::Actions;
use netcore::{Error, Result};

mod dbus;

/// Present only when NM is reachable on the system bus at construction.
/// Holds no persistent state — each call opens a fresh D-Bus connection.
pub struct NmBackend {
    _private: (),
}

impl NmBackend {
    /// Returns `Some` iff NetworkManager is registered on the system bus.
    pub fn new() -> Option<Self> {
        if block_on(dbus::is_available()) {
            Some(Self { _private: () })
        } else {
            None
        }
    }

    /// Snapshot of NM profiles keyed by the interface name they bind to.
    ///
    /// Profiles without `connection.interface-name` (e.g. VPN configs that
    /// match any device) are skipped — the netlink backend resolves by
    /// iface name, so there's nothing to attach them to.
    pub fn profiles_by_iface(&self) -> Result<HashMap<String, Profile>> {
        block_on(dbus::list_profiles_by_iface())
    }
}

impl Actions for NmBackend {
    fn prefer(&self, id: &ConnectionId) -> Result<()> {
        block_on(dbus::activate_connection(&id.0))
    }

    fn forget(&self, id: &ConnectionId) -> Result<()> {
        block_on(dbus::delete_connection(&id.0))
    }

    fn reconnect(&self, id: &ConnectionId) -> Result<()> {
        // Deactivate (if active) then activate. NM doesn't expose a single
        // "bounce" verb — deactivate+activate is the idiomatic way.
        let name = &id.0;
        // Ignore deactivate errors: the profile may not be active right now.
        let _ = block_on(dbus::deactivate_connection(name));
        block_on(dbus::activate_connection(name))
    }

    fn set_autoconnect(&self, id: &ConnectionId, on: bool) -> Result<()> {
        block_on(dbus::set_autoconnect(&id.0, on))
    }
}

fn block_on<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build tokio current_thread")
        .block_on(fut)
}

// Re-export so the CLI can import one name.
pub fn backend_error(msg: impl Into<String>) -> Error { Error::Backend(msg.into()) }

#[cfg(test)]
mod live_tests {
    //! These tests require NetworkManager on the system bus. Each test
    //! gracefully no-ops when NM isn't available so CI / non-NM boxes
    //! don't spuriously fail.

    use super::*;

    #[test]
    fn probe_returns_some_when_nm_is_running() {
        let Some(b) = NmBackend::new() else {
            eprintln!("skipping: NetworkManager not on system bus");
            return;
        };
        // Smoke test: list profiles. Zero is valid (fresh install).
        let profiles = b.profiles_by_iface().expect("list profiles");
        eprintln!("got {} profile(s) bound to an iface", profiles.len());
    }

    #[test]
    fn profiles_carry_expected_fields() {
        let Some(b) = NmBackend::new() else { return };
        let profiles = b.profiles_by_iface().expect("list profiles");
        for (iface, p) in &profiles {
            assert!(!iface.is_empty());
            assert!(!p.name.is_empty(), "profile with empty name on {iface}");
            assert!(!p.kind.is_empty(), "profile with empty kind on {iface}");
        }
    }
}
