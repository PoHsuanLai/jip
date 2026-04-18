//! Domain types and capability traits for `jip`.
//!
//! Users of this crate get a coherent view of a Linux host's network: L1 kernel
//! primitives (`Link`, `Addr`, `Route`, `Neighbor`, `Socket`), L2 domain concepts
//! (`Connection`, `Service`, `Path`, `Flow`), L3 judgments (`Finding`, `Health`),
//! and L4 capability traits that backends implement.
//!
//! There is no I/O in this crate. Backends live in sibling crates.

pub mod connection;
pub mod diag;
pub mod dns;
pub mod link;
pub mod path;
pub mod process;
pub mod service;
pub mod traits;

#[cfg(any(test, feature = "fixture"))]
pub mod fixture;

pub use connection::*;
pub use diag::*;
pub use dns::*;
pub use link::*;
pub use path::*;
pub use process::*;
pub use service::*;
pub use traits::*;

/// Crate-wide error type. Backends wrap their own errors in `Error::Backend`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from a backend (netlink, D-Bus, shell-out, etc.).
    #[error("backend: {0}")]
    Backend(String),
    /// The requested operation is not supported on this platform or by the
    /// current backend.
    #[error("unsupported on this platform or by this backend: {0}")]
    Unsupported(&'static str),
    /// The operation requires a capability (e.g. `CAP_NET_RAW`) that is absent.
    #[error("missing capability: {0}")]
    MissingCapability(&'static str),
    /// A parsing failure (e.g. malformed JSON from `nft`, unexpected kernel
    /// attribute layout).
    #[error("parse error: {0}")]
    Parse(String),
    /// A requested resource (interface, route, DNS answer, etc.) was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// Wrapped `std::io::Error`.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `Result<T, Error>` throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
