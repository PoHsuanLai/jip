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

use netcore::connection::{AccessPoint, Profile, WifiSecurity, WifiSignal};
use netcore::{Error, Result};

const NM_BUS: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_IFACE: &str = "org.freedesktop.NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const NM_SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
const NM_CONN_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const NM_ACTIVE_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const NM_DEVICE_IFACE: &str = "org.freedesktop.NetworkManager.Device";
const NM_WIRELESS_IFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const NM_AP_IFACE: &str = "org.freedesktop.NetworkManager.AccessPoint";

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
    let active_uuids = active_connection_uuids(&conn).await;
    let mut out = HashMap::with_capacity(paths.len());
    for path in paths {
        match get_settings(&conn, &path).await {
            Ok(s) => {
                if let Some(mut profile) = profile_from_settings_full(&s) {
                    if let Some(ref iface) = profile.iface.clone() {
                        profile.active = active_uuids.contains(&profile.uuid);
                        out.insert(iface.clone(), profile);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    Ok(out)
}

/// Return all NM profiles regardless of whether they have a bound interface.
/// Includes VPN, bridge, and unbound profiles.
pub async fn list_all_profiles() -> Result<Vec<Profile>> {
    let conn = bus().await?;
    let paths = list_connections(&conn).await?;
    let active_uuids = active_connection_uuids(&conn).await;
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        match get_settings(&conn, &path).await {
            Ok(s) => {
                if let Some(mut profile) = profile_from_settings_full(&s) {
                    profile.active = active_uuids.contains(&profile.uuid);
                    out.push(profile);
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

/// Return all access points visible to all wireless devices NM manages.
/// Uses NM's cached scan results — no root required, no new scan triggered.
/// Each AP is deduplicated by BSSID; the strongest signal wins when the
/// same BSSID appears on multiple interfaces.
pub async fn scan_access_points() -> Result<Vec<AccessPoint>> {
    let conn = bus().await?;

    // Get all devices NM knows about.
    let devices: Vec<OwnedObjectPath> =
        get_property(&conn, NM_PATH, NM_IFACE, "Devices")
            .await
            .unwrap_or_default();

    // Collect the active AP path per wireless device so we can mark in_use.
    // Key: AP object path string; value: true = currently associated.
    let mut active_ap_paths = std::collections::HashSet::new();

    // Collect AP paths from each wireless device.
    let mut ap_paths: Vec<(OwnedObjectPath, bool)> = Vec::new();

    for dev in &devices {
        // Check if this device is a wireless device (DeviceType == 2).
        let dev_type: u32 = get_property(&conn, dev.as_str(), NM_DEVICE_IFACE, "DeviceType")
            .await
            .unwrap_or(0);
        if dev_type != 2 {
            continue;
        }

        // Record the active AP for this device.
        if let Ok(active_ap) =
            get_property::<OwnedObjectPath>(&conn, dev.as_str(), NM_WIRELESS_IFACE, "ActiveAccessPoint")
                .await
        {
            if active_ap.as_str() != "/" {
                active_ap_paths.insert(active_ap.as_str().to_string());
            }
        }

        // GetAccessPoints returns all APs in the cached scan table.
        let aps: Vec<OwnedObjectPath> = match conn
            .call_method(
                Some(NM_BUS),
                dev.as_str(),
                Some(NM_WIRELESS_IFACE),
                "GetAllAccessPoints",
                &(),
            )
            .await
            .and_then(|m| m.body().deserialize())
        {
            Ok(v) => v,
            Err(_) => continue,
        };

        for ap in aps {
            let in_use = active_ap_paths.contains(ap.as_str());
            ap_paths.push((ap, in_use));
        }
    }

    // Deduplicate by BSSID, keeping strongest signal.
    let mut by_bssid: std::collections::HashMap<String, AccessPoint> =
        std::collections::HashMap::new();

    for (path, in_use) in ap_paths {
        if let Some(ap) = read_access_point(&conn, &path, in_use).await {
            let entry = by_bssid.entry(ap.bssid.clone()).or_insert_with(|| ap.clone());
            if ap.signal.rssi_dbm > entry.signal.rssi_dbm {
                *entry = ap;
            }
        }
    }

    let mut aps: Vec<AccessPoint> = by_bssid.into_values().collect();
    // Sort: in-use first, then by signal strength descending.
    aps.sort_by_key(|a| (!a.in_use, -(a.signal.rssi_dbm)));
    Ok(aps)
}

async fn read_access_point(
    conn: &Connection,
    path: &OwnedObjectPath,
    in_use: bool,
) -> Option<AccessPoint> {
    let ssid_bytes: Vec<u8> =
        get_property(conn, path.as_str(), NM_AP_IFACE, "Ssid")
            .await
            .unwrap_or_default();
    let ssid = String::from_utf8_lossy(&ssid_bytes).into_owned();
    let bssid: String =
        get_property(conn, path.as_str(), NM_AP_IFACE, "HwAddress")
            .await
            .unwrap_or_default();
    let strength: u8 =
        get_property(conn, path.as_str(), NM_AP_IFACE, "Strength")
            .await
            .unwrap_or(0);
    let frequency_mhz: u32 =
        get_property(conn, path.as_str(), NM_AP_IFACE, "Frequency")
            .await
            .unwrap_or(0);
    let max_bitrate_kbps: u32 =
        get_property(conn, path.as_str(), NM_AP_IFACE, "MaxBitrate")
            .await
            .unwrap_or(0);
    let wpa_flags: u32 =
        get_property(conn, path.as_str(), NM_AP_IFACE, "WpaFlags")
            .await
            .unwrap_or(0);
    let rsn_flags: u32 =
        get_property(conn, path.as_str(), NM_AP_IFACE, "RsnFlags")
            .await
            .unwrap_or(0);
    let ap_flags: u32 =
        get_property(conn, path.as_str(), NM_AP_IFACE, "Flags")
            .await
            .unwrap_or(0);

    // NM Strength is 0–100; convert to approximate dBm (-90 to -30).
    let rssi_dbm = strength_to_dbm(strength);
    let rate_mbps = if max_bitrate_kbps > 0 { Some(max_bitrate_kbps / 1000) } else { None };

    let security = decode_security(ap_flags, wpa_flags, rsn_flags);

    Some(AccessPoint {
        ssid,
        bssid,
        signal: WifiSignal { rssi_dbm, quality_pct: Some(strength), rate_mbps },
        frequency_mhz,
        security,
        in_use,
    })
}

/// Convert NM's 0–100 strength percentage to approximate dBm.
/// Mapping: 100 → -30 dBm, 0 → -90 dBm.
fn strength_to_dbm(strength: u8) -> i32 {
    let s = strength.min(100) as i32;
    -90 + (s * 60 / 100)
}

/// Decode NM's AP flags + WPA/RSN flags into a WifiSecurity variant.
///
/// ap_flags bit 0 = NM_802_11_AP_FLAGS_PRIVACY (any encryption)
/// rsn_flags bit 9 = NM_802_11_AP_SEC_KEY_MGMT_SAE (WPA3-Personal)
/// rsn_flags bit 5 = NM_802_11_AP_SEC_KEY_MGMT_802_1X (WPA2/WPA3-Enterprise)
/// rsn_flags bit 4 = NM_802_11_AP_SEC_KEY_MGMT_PSK (WPA2-Personal)
/// wpa_flags bit 4 = NM_802_11_AP_SEC_KEY_MGMT_PSK (WPA1-Personal)
fn decode_security(ap_flags: u32, wpa_flags: u32, rsn_flags: u32) -> WifiSecurity {
    let privacy = ap_flags & 0x1 != 0;
    let rsn_sae = rsn_flags & (1 << 9) != 0;           // WPA3-Personal (SAE)
    let rsn_eap = rsn_flags & (1 << 5) != 0;           // WPA2/WPA3-Enterprise (802.1X)
    let rsn_psk = rsn_flags & (1 << 4) != 0;           // WPA2-Personal (PSK)
    let wpa_eap = wpa_flags & (1 << 5) != 0;           // WPA1-Enterprise
    let wpa_psk = wpa_flags & (1 << 4) != 0;           // WPA1-Personal

    if rsn_sae && rsn_eap {
        WifiSecurity::Wpa3Enterprise
    } else if rsn_sae {
        WifiSecurity::Wpa3Personal
    } else if rsn_eap || wpa_eap {
        WifiSecurity::Wpa2Enterprise
    } else if rsn_psk {
        WifiSecurity::Wpa2Personal
    } else if wpa_psk {
        // WPA1-only; rare on modern networks
        WifiSecurity::Other("wpa".into())
    } else if privacy {
        WifiSecurity::Wep
    } else {
        WifiSecurity::Open
    }
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

fn profile_from_settings_full(s: &SettingsMap) -> Option<Profile> {
    let c = s.get("connection")?;
    let name = as_string(c.get("id")?)?;
    let uuid = as_string(c.get("uuid")?).unwrap_or_default();
    let kind = as_string(c.get("type")?)?;
    let iface = c.get("interface-name").and_then(as_string);
    let autoconnect = c.get("autoconnect").and_then(as_bool).unwrap_or(true);
    Some(Profile { name, uuid, autoconnect, kind, iface, active: false })
}

/// Collect UUIDs of all currently active NM connections.
async fn active_connection_uuids(conn: &Connection) -> std::collections::HashSet<String> {
    let actives: Vec<OwnedObjectPath> =
        get_property(conn, NM_PATH, NM_IFACE, "ActiveConnections")
            .await
            .unwrap_or_default();
    let mut uuids = std::collections::HashSet::with_capacity(actives.len());
    for act in actives {
        if let Ok(uuid) =
            get_property::<String>(conn, act.as_str(), NM_ACTIVE_IFACE, "Uuid").await
        {
            uuids.insert(uuid);
        }
    }
    uuids
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
