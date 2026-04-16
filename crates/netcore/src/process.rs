//! Process ownership for sockets.
//!
//! The three-way distinction between "we know", "the kernel denied us", and
//! "truly anonymous" matters: running `ss` without root hides the owners of
//! sockets belonging to other users, and we want to surface that as one
//! diagnostic rather than N question marks in a table.

use serde::{Deserialize, Serialize};

/// A reference to a specific process by PID and command name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRef {
    /// Kernel process ID.
    pub pid: u32,
    /// Short command name from `/proc/<pid>/comm`.
    pub comm: String,
}

/// Process ownership for a socket — three-way split so the diagnostician
/// can surface permission failures as one aggregate finding rather than N
/// question marks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessInfo {
    /// We successfully resolved the owning process.
    Known(ProcessRef),
    /// We aren't privileged enough to read this socket's owner. Emit one
    /// aggregate finding, not one per row.
    PermissionDenied,
    /// Kernel-owned or the namespace's PID is foreign.
    Anonymous,
}
