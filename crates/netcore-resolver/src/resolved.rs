//! systemd-resolved D-Bus client.
//!
//! Hand-rolled zbus proxies for `org.freedesktop.resolve1` — the generated
//! macros add a lot of noise for the handful of calls we need.
//!
//! Relevant interface (from `systemd-resolved(8)` and `resolved/dbus-manager.c`):
//! - Manager.ResolveHostname(ifindex: i, name: s, family: i, flags: t)
//!   -> addresses: a(iiay), canonical: s, flags: t
//! - Manager.DNSStubListener : s (property; "yes"/"no"/"udp"/"tcp")
//! - Manager.CurrentDNSServerEx (property) : (iiayqs)   [idx, family, bytes, port, name]
//! - Manager.GetLink(ifindex: i) -> object_path  (link-specific object)
//! - Link.DNSEx (property) : a(iayqs)
//!
//! We convert all byte-array addresses via `ip_from_family_bytes`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

use netcore::Error;
use netcore::Result as NcResult;
use netcore::connection::Family;
use netcore::dns::{DnsAnswer, DnsError, DnsResolution, DnsSource};

const BUS_NAME: &str = "org.freedesktop.resolve1";
const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";
const LINK_IFACE: &str = "org.freedesktop.resolve1.Link";

const AF_UNSPEC: i32 = 0;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

/// systemd-resolved ResolveHostname flags. Values from
/// `systemd/src/resolve/resolved-def.h` (v256+). Only the ones we surface.
const SD_RESOLVED_AUTHENTICATED: u64 = 1 << 9;
const SD_RESOLVED_FROM_CACHE: u64 = 1 << 20;

/// (ifindex, family, addr_bytes) — the signature of one entry in a
/// resolved ResolveHostname reply. Aliased to keep clippy off our back.
type ResolvedAddr = (i32, i32, Vec<u8>);

pub async fn is_available() -> bool {
    let Ok(conn) = Connection::system().await else {
        return false;
    };
    // NameHasOwner is the cheapest liveness check.
    let reply: zbus::Result<bool> = conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "NameHasOwner",
            &BUS_NAME,
        )
        .await
        .and_then(|m| m.body().deserialize());
    reply.unwrap_or(false)
}

pub async fn resolve_hostname(name: &str) -> NcResult<DnsResolution> {
    let conn = Connection::system()
        .await
        .map_err(|e| Error::Backend(format!("dbus system bus: {e}")))?;
    let start = Instant::now();
    let reply = conn
        .call_method(
            Some(BUS_NAME),
            MANAGER_PATH,
            Some(MANAGER_IFACE),
            "ResolveHostname",
            &(0i32, name, AF_UNSPEC, 0u64),
        )
        .await;
    let took = start.elapsed();
    match reply {
        Ok(msg) => {
            // Signature: a(iiay) s t
            let body: (Vec<ResolvedAddr>, String, u64) = msg
                .body()
                .deserialize()
                .map_err(|e| Error::Backend(format!("resolve reply decode: {e}")))?;
            let (raws, _canonical, flags) = body;
            let answers: Vec<DnsAnswer> = raws
                .into_iter()
                .filter_map(|(_ifindex, family, bytes)| {
                    let ip = ip_from_family_bytes(family, &bytes)?;
                    Some(DnsAnswer {
                        family: if matches!(ip, IpAddr::V4(_)) {
                            Family::V4
                        } else {
                            Family::V6
                        },
                        ip,
                        ttl: None,
                    })
                })
                .collect();
            let upstream_used = current_upstream(&conn).await.ok().flatten();
            let stub = stub_address_inner(&conn).await.ok().flatten();
            let via = stub.map(DnsSource::Stub).unwrap_or(DnsSource::Libc);
            Ok(DnsResolution {
                queried: name.into(),
                via,
                upstream_used,
                answers,
                took,
                cached: flags & SD_RESOLVED_FROM_CACHE != 0,
                authenticated: flags & SD_RESOLVED_AUTHENTICATED != 0,
                error: None,
            })
        }
        Err(e) => {
            let err = classify_resolved_error(&e);
            // If it's a transport error, propagate as Backend so lib.rs
            // knows to fall back to libc. Otherwise it's a query-level
            // error (NXDOMAIN etc.) and we return a successful DnsResolution
            // that happens to carry an error.
            if is_transport(&e) {
                return Err(Error::Backend(format!("resolve: {e}")));
            }
            Ok(DnsResolution {
                queried: name.into(),
                via: DnsSource::Stub("127.0.0.53".parse().unwrap()),
                upstream_used: current_upstream(&conn).await.ok().flatten(),
                answers: vec![],
                took,
                cached: false,
                authenticated: false,
                error: Some(err),
            })
        }
    }
}

pub async fn stub_address() -> NcResult<Option<IpAddr>> {
    let conn = Connection::system()
        .await
        .map_err(|e| Error::Backend(format!("dbus system bus: {e}")))?;
    stub_address_inner(&conn).await
}

async fn stub_address_inner(conn: &Connection) -> NcResult<Option<IpAddr>> {
    let listener: String = get_property(
        conn,
        BUS_NAME,
        MANAGER_PATH,
        MANAGER_IFACE,
        "DNSStubListener",
    )
    .await
    .unwrap_or_else(|_| "no".into());
    if listener == "no" {
        Ok(None)
    } else {
        Ok(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))))
    }
}

async fn current_upstream(conn: &Connection) -> NcResult<Option<IpAddr>> {
    // CurrentDNSServerEx : (iiayqs) or CurrentDNSServer : (iiay). Try both.
    if let Ok(v) = get_property::<(i32, i32, Vec<u8>, u16, String)>(
        conn,
        BUS_NAME,
        MANAGER_PATH,
        MANAGER_IFACE,
        "CurrentDNSServerEx",
    )
    .await
    {
        return Ok(ip_from_family_bytes(v.1, &v.2));
    }
    if let Ok(v) = get_property::<(i32, i32, Vec<u8>)>(
        conn,
        BUS_NAME,
        MANAGER_PATH,
        MANAGER_IFACE,
        "CurrentDNSServer",
    )
    .await
    {
        return Ok(ip_from_family_bytes(v.1, &v.2));
    }
    Ok(None)
}

pub async fn servers_for_link(link_name: &str) -> NcResult<Vec<IpAddr>> {
    let ifindex =
        ifindex_for(link_name).ok_or_else(|| Error::NotFound(format!("link {link_name}")))?;
    let conn = Connection::system()
        .await
        .map_err(|e| Error::Backend(format!("dbus system bus: {e}")))?;
    let reply = conn
        .call_method(
            Some(BUS_NAME),
            MANAGER_PATH,
            Some(MANAGER_IFACE),
            "GetLink",
            &(ifindex as i32),
        )
        .await
        .map_err(|e| Error::Backend(format!("GetLink {link_name}: {e}")))?;
    let path: OwnedObjectPath = reply
        .body()
        .deserialize()
        .map_err(|e| Error::Backend(format!("GetLink decode: {e}")))?;
    // Prefer DNSEx; fall back to DNS.
    if let Ok(v) = get_property::<Vec<(i32, Vec<u8>, u16, String)>>(
        &conn,
        BUS_NAME,
        path.as_str(),
        LINK_IFACE,
        "DNSEx",
    )
    .await
    {
        return Ok(v
            .into_iter()
            .filter_map(|(family, bytes, _, _)| ip_from_family_bytes(family, &bytes))
            .collect());
    }
    if let Ok(v) =
        get_property::<Vec<(i32, Vec<u8>)>>(&conn, BUS_NAME, path.as_str(), LINK_IFACE, "DNS").await
    {
        return Ok(v
            .into_iter()
            .filter_map(|(family, bytes)| ip_from_family_bytes(family, &bytes))
            .collect());
    }
    Ok(vec![])
}

/// Read a single property via `org.freedesktop.DBus.Properties.Get`.
async fn get_property<T>(
    conn: &Connection,
    bus: &str,
    path: &str,
    iface: &str,
    name: &str,
) -> NcResult<T>
where
    T: TryFrom<zbus::zvariant::OwnedValue>,
{
    let reply = conn
        .call_method(
            Some(bus),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(iface, name),
        )
        .await
        .map_err(|e| Error::Backend(format!("Properties.Get {iface}.{name}: {e}")))?;
    let variant: zbus::zvariant::OwnedValue = reply
        .body()
        .deserialize()
        .map_err(|e| Error::Backend(format!("Properties.Get decode: {e}")))?;
    T::try_from(variant)
        .map_err(|_| Error::Backend(format!("Properties.Get {iface}.{name} type mismatch")))
}

fn ifindex_for(name: &str) -> Option<u32> {
    let link = std::fs::read_link(format!("/sys/class/net/{name}/ifindex")).ok();
    if let Some(p) = link {
        // some kernels give a symlink; most have a plain file
        return p.to_str()?.trim().parse().ok();
    }
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")).ok()?;
    s.trim().parse().ok()
}

fn ip_from_family_bytes(family: i32, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET if bytes.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 if bytes.len() == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

fn is_transport(e: &zbus::Error) -> bool {
    matches!(
        e,
        zbus::Error::Address(_) | zbus::Error::InputOutput(_) | zbus::Error::Handshake(_)
    )
}

fn classify_resolved_error(e: &zbus::Error) -> DnsError {
    let msg = e.to_string();
    let lm = msg.to_ascii_lowercase();
    if lm.contains("no such") || lm.contains("nxdomain") || lm.contains("does not exist") {
        DnsError::NxDomain
    } else if lm.contains("timed out") || lm.contains("timeout") {
        DnsError::Timeout
    } else if lm.contains("servfail") || lm.contains("server failure") {
        DnsError::ServFail
    } else {
        DnsError::Other(msg)
    }
}

// Silence unused-import warnings on rare paths.
#[allow(dead_code)]
fn _touch(_: Duration) {}
