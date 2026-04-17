//! Pure-Rust nftables netlink client.
//!
//! Reads nftables tables, chains, and rules directly from the kernel via
//! `NETLINK_NETFILTER` — no `nft` binary required, no C FFI.
//!
//! # Usage
//!
//! ```no_run
//! use nftables_netlink::NftNetlinkHandle;
//!
//! let h = NftNetlinkHandle::open().unwrap();
//! let chains = h.dump_chains().unwrap();
//! let rules  = h.dump_rules().unwrap();
//! ```

pub mod codec;
pub mod constants;
pub mod error;
pub mod objects;
pub mod ops;

pub use error::NftError;
pub use objects::{ChainPolicy, Expr, NftChain, NftHook, NftRule, NftTable, PortMatch, RuleVerdict};

/// Handle to the nftables netlink socket.
///
/// `open()` does not require `CAP_NET_ADMIN` on Linux 5.2+ for read-only dump
/// operations. On older kernels or when capabilities are missing, `open()`
/// returns [`NftError::MissingCapability`].
pub struct NftNetlinkHandle;

impl NftNetlinkHandle {
    /// Open the `NETLINK_NETFILTER` socket and return a handle.
    pub fn open() -> Result<Self, NftError> {
        // Probe by attempting to open the socket. The actual socket is opened
        // per-operation to avoid holding an fd open indefinitely.
        let _probe = netlink_sys::Socket::new(constants::NETLINK_NETFILTER)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::EPERM) {
                    NftError::MissingCapability
                } else {
                    NftError::Socket(e)
                }
            })?;
        Ok(Self)
    }

    /// List all nftables tables.
    pub fn dump_tables(&self) -> Result<Vec<NftTable>, NftError> {
        ops::dump::dump_tables()
    }

    /// List all nftables chains across all tables.
    pub fn dump_chains(&self) -> Result<Vec<NftChain>, NftError> {
        ops::dump::dump_chains()
    }

    /// List all nftables rules across all chains, with decoded expressions.
    pub fn dump_rules(&self) -> Result<Vec<NftRule>, NftError> {
        ops::dump::dump_rules()
    }
}
