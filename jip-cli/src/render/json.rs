//! JSON pass-through for every view.

use netcore::connection::Connection;
use netcore::diag::Health;
use netcore::path::Path;

pub fn overview(conns: &[Connection], health: &Health) -> anyhow::Result<()> {
    let v = serde_json::json!({
        "connections": conns,
        "health": health,
    });
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub fn health(health: &Health) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(health)?);
    Ok(())
}

pub fn path(path: &Path) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(path)?);
    Ok(())
}
