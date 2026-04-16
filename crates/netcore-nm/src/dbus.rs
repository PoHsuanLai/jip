//! Low-level NetworkManager D-Bus calls.
//!
//! Hand-rolled zbus against `org.freedesktop.NetworkManager`. We stay
//! close to the wire so that missing properties degrade (log/ignore)
//! instead of failing the whole backend.
//!
//! Method signatures (from `NetworkManager.xml`):
//! - Settings.ListConnections()                  → ao
//! - Settings.Connection.GetSettings()           → a{sa{sv}}
//! - Settings.Connection.Update(settings)        → –
//! - Settings.Connection.Delete()                → –
//! - NetworkManager.ActivateConnection(c,d,sp)   → o   (conn, device, specific_obj)
//! - NetworkManager.DeactivateConnection(active) → –

use std::collections::HashMap;

use zbus::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use netcore::connection::Profile;
use netcore::{Error, Result};

const NM_BUS: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_IFACE: &str = "org.freedesktop.NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const NM_SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
const NM_CONN_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const NM_ACTIVE_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";

/// NM's settings "dict of dicts" wire type. Outer key is the settings
/// group (`"connection"`, `"ipv4"`, `"802-3-ethernet"`, ...); inner is
/// `"key" -> Variant`.
type SettingsMap = HashMap<String, HashMap<String, OwnedValue>>;

pub async fn is_available() -> bool {
    let Ok(conn) = Connection::system().await else { return false; };
    let reply: zbus::Result<bool> = conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "NameHasOwner",
            &NM_BUS,
        )
        .await
        .and_then(|m| m.body().deserialize());
    reply.unwrap_or(false)
}

/// Walk every profile NM knows about and bucket by the interface name it
/// binds to. Profiles with no `connection.interface-name` are skipped —
/// the CLI uses iface name as the join key.
pub async fn list_profiles_by_iface() -> Result<HashMap<String, Profile>> {
    let conn = bus().await?;
    let paths = list_connections(&conn).await?;
    let mut out = HashMap::with_capacity(paths.len());
    for path in paths {
        // Each profile read is independent; one broken profile shouldn't
        // hide the rest.
        match get_settings(&conn, &path).await {
            Ok(s) => {
                if let Some((iface, profile)) = profile_from_settings(&s) {
                    out.insert(iface, profile);
                }
            }
            Err(_) => continue,
        }
    }
    Ok(out)
}

/// NM's `Settings.AddAndActivateConnection` variant, but for an already
/// existing profile: call `ActivateConnection(conn, "/", "/")`.
pub async fn activate_connection(name_or_uuid: &str) -> Result<()> {
    let conn = bus().await?;
    let path = resolve_connection_path(&conn, name_or_uuid).await?;
    // device "/" and specific_obj "/" = "pick the best device for this profile"
    let root = OwnedObjectPath::try_from("/").unwrap();
    let reply = conn
        .call_method(
            Some(NM_BUS),
            NM_PATH,
            Some(NM_IFACE),
            "ActivateConnection",
            &(&path, &root, &root),
        )
        .await
        .map_err(|e| Error::Backend(format!("ActivateConnection: {e}")))?;
    let _: OwnedObjectPath = reply
        .body()
        .deserialize()
        .map_err(|e| Error::Backend(format!("ActivateConnection decode: {e}")))?;
    Ok(())
}

pub async fn deactivate_connection(name_or_uuid: &str) -> Result<()> {
    let conn = bus().await?;
    // DeactivateConnection takes the *active* connection path, not the
    // settings path. Walk ActiveConnections, find the one whose id/uuid
    // matches, deactivate that object.
    let actives: Vec<OwnedObjectPath> = get_property(&conn, NM_PATH, NM_IFACE, "ActiveConnections")
        .await
        .unwrap_or_default();
    for act in actives {
        let id = get_property::<String>(&conn, act.as_str(), NM_ACTIVE_IFACE, "Id")
            .await
            .unwrap_or_default();
        let uuid = get_property::<String>(&conn, act.as_str(), NM_ACTIVE_IFACE, "Uuid")
            .await
            .unwrap_or_default();
        if id == name_or_uuid || uuid == name_or_uuid {
            conn.call_method(
                Some(NM_BUS),
                NM_PATH,
                Some(NM_IFACE),
                "DeactivateConnection",
                &act,
            )
            .await
            .map_err(|e| Error::Backend(format!("DeactivateConnection: {e}")))?;
            return Ok(());
        }
    }
    Err(Error::NotFound(format!("no active connection named {name_or_uuid}")))
}

pub async fn delete_connection(name_or_uuid: &str) -> Result<()> {
    let conn = bus().await?;
    let path = resolve_connection_path(&conn, name_or_uuid).await?;
    conn.call_method(
        Some(NM_BUS),
        path.as_str(),
        Some(NM_CONN_IFACE),
        "Delete",
        &(),
    )
    .await
    .map_err(|e| Error::Backend(format!("Connection.Delete: {e}")))?;
    Ok(())
}

pub async fn set_autoconnect(name_or_uuid: &str, on: bool) -> Result<()> {
    let conn = bus().await?;
    let path = resolve_connection_path(&conn, name_or_uuid).await?;
    let mut settings = get_settings(&conn, &path).await?;
    let group = settings.entry("connection".into()).or_default();
    // NM elides defaults: the absence of the autoconnect key means true.
    // Overwriting with an explicit boolean is always correct.
    let v = Value::new(on)
        .try_to_owned()
        .map_err(|e| Error::Backend(format!("autoconnect variant: {e}")))?;
    group.insert("autoconnect".into(), v);
    // Strip keys NM treats as read-only so Update doesn't reject the call.
    strip_readonly(&mut settings);
    conn.call_method(
        Some(NM_BUS),
        path.as_str(),
        Some(NM_CONN_IFACE),
        "Update",
        &settings,
    )
    .await
    .map_err(|e| Error::Backend(format!("Connection.Update: {e}")))?;
    Ok(())
}

// --- helpers ---------------------------------------------------------

async fn bus() -> Result<Connection> {
    Connection::system()
        .await
        .map_err(|e| Error::Backend(format!("dbus system bus: {e}")))
}

async fn list_connections(conn: &Connection) -> Result<Vec<OwnedObjectPath>> {
    let reply = conn
        .call_method(
            Some(NM_BUS),
            NM_SETTINGS_PATH,
            Some(NM_SETTINGS_IFACE),
            "ListConnections",
            &(),
        )
        .await
        .map_err(|e| Error::Backend(format!("ListConnections: {e}")))?;
    reply
        .body()
        .deserialize::<Vec<OwnedObjectPath>>()
        .map_err(|e| Error::Backend(format!("ListConnections decode: {e}")))
}

async fn get_settings(conn: &Connection, path: &OwnedObjectPath) -> Result<SettingsMap> {
    let reply = conn
        .call_method(
            Some(NM_BUS),
            path.as_str(),
            Some(NM_CONN_IFACE),
            "GetSettings",
            &(),
        )
        .await
        .map_err(|e| Error::Backend(format!("GetSettings: {e}")))?;
    reply
        .body()
        .deserialize::<SettingsMap>()
        .map_err(|e| Error::Backend(format!("GetSettings decode: {e}")))
}

fn profile_from_settings(s: &SettingsMap) -> Option<(String, Profile)> {
    let c = s.get("connection")?;
    let name = as_string(c.get("id")?)?;
    let kind = as_string(c.get("type")?)?;
    let iface = as_string(c.get("interface-name")?)?;
    // NM omits `autoconnect` from the wire when it's the default (true).
    let autoconnect = c
        .get("autoconnect")
        .and_then(as_bool)
        .unwrap_or(true);
    Some((iface, Profile { name, autoconnect, kind }))
}

fn as_string(v: &OwnedValue) -> Option<String> {
    <&str>::try_from(v).ok().map(str::to_owned)
}

fn as_bool(v: &OwnedValue) -> Option<bool> {
    bool::try_from(v).ok()
}

/// Find a profile object path by either `connection.id` or `connection.uuid`.
/// Prefers `id` match (human-readable) so callers can pass "Wired connection 1".
async fn resolve_connection_path(
    conn: &Connection,
    name_or_uuid: &str,
) -> Result<OwnedObjectPath> {
    // Fast path: UUID lookup is a single dedicated call.
    if looks_like_uuid(name_or_uuid) {
        let reply = conn
            .call_method(
                Some(NM_BUS),
                NM_SETTINGS_PATH,
                Some(NM_SETTINGS_IFACE),
                "GetConnectionByUuid",
                &name_or_uuid,
            )
            .await;
        if let Ok(m) = reply {
            if let Ok(p) = m.body().deserialize::<OwnedObjectPath>() {
                return Ok(p);
            }
        }
    }
    // Otherwise scan by id.
    for path in list_connections(conn).await? {
        if let Ok(s) = get_settings(conn, &path).await {
            if let Some(c) = s.get("connection") {
                let id = c.get("id").and_then(as_string).unwrap_or_default();
                let uuid = c.get("uuid").and_then(as_string).unwrap_or_default();
                if id == name_or_uuid || uuid == name_or_uuid {
                    return Ok(path);
                }
            }
        }
    }
    Err(Error::NotFound(format!("no NM connection named {name_or_uuid}")))
}

fn looks_like_uuid(s: &str) -> bool {
    // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx — 36 chars with 4 hyphens.
    s.len() == 36 && s.matches('-').count() == 4
}

/// NM's `Settings.Connection.Update` is picky about certain read-only
/// timestamp/history fields. Drop them before writing back.
fn strip_readonly(s: &mut SettingsMap) {
    if let Some(c) = s.get_mut("connection") {
        c.remove("timestamp");
        c.remove("read-only");
    }
}

async fn get_property<T>(
    conn: &Connection,
    path: &str,
    iface: &str,
    name: &str,
) -> Result<T>
where
    T: TryFrom<OwnedValue>,
{
    let reply = conn
        .call_method(
            Some(NM_BUS),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(iface, name),
        )
        .await
        .map_err(|e| Error::Backend(format!("Properties.Get {iface}.{name}: {e}")))?;
    let variant: OwnedValue = reply
        .body()
        .deserialize()
        .map_err(|e| Error::Backend(format!("Properties.Get decode: {e}")))?;
    T::try_from(variant)
        .map_err(|_| Error::Backend(format!("Properties.Get {iface}.{name} type mismatch")))
}
