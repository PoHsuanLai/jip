//! Process ownership for sockets.
//!
//! The three-way distinction between "we know", "the kernel denied us", and
//! "truly anonymous" matters: running `ss` without root hides the owners of
//! sockets belonging to other users, and we want to surface that as one
//! diagnostic rather than N question marks in a table.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub comm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessInfo {
    Known(ProcessRef),
    /// We aren't privileged enough to read this socket's owner. Emit one
    /// aggregate finding, not one per row.
    PermissionDenied,
    /// Kernel-owned or the namespace's PID is foreign.
    Anonymous,
}
