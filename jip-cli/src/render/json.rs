//! JSON pass-through for every view.

use netcore::connection::Connection;
use netcore::diag::Health;
use netcore::path::Path;

/// Serialize the connection list and quick-check health as a JSON object to
/// stdout.
pub fn overview(conns: &[Connection], health: &Health) -> anyhow::Result<()> {
    let v = serde_json::json!({
        "connections": conns,
        "health": health,
    });
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// Serialize a [`Health`] value as JSON to stdout.
pub fn health(health: &Health) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(health)?);
    Ok(())
}

/// Serialize a [`Path`] value as JSON to stdout.
pub fn path(path: &Path) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(path)?);
    Ok(())
}
