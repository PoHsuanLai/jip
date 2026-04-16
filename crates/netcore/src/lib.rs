//! Domain types and capability traits for `jip`.
//!
//! Users of this crate get a coherent view of a Linux host's network: L1 kernel
//! primitives (`Link`, `Addr`, `Route`, `Neighbor`, `Socket`), L2 domain concepts
//! (`Connection`, `Service`, `Path`, `Flow`), L3 judgments (`Finding`, `Health`),
//! and L4 capability traits that backends implement.
//!
//! There is no I/O in this crate. Backends live in sibling crates.

pub mod link;
pub mod connection;
pub mod service;
pub mod path;
pub mod dns;
pub mod process;
pub mod diag;
pub mod traits;

#[cfg(any(test, feature = "fixture"))]
pub mod fixture;

pub use link::*;
pub use connection::*;
pub use service::*;
pub use path::*;
pub use dns::*;
pub use process::*;
pub use diag::*;
pub use traits::*;

/// Crate-wide error type. Backends wrap their own errors in `Error::Backend`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("backend: {0}")]
    Backend(String),
    #[error("unsupported on this platform or by this backend: {0}")]
    Unsupported(&'static str),
    #[error("missing capability: {0}")]
    MissingCapability(&'static str),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
