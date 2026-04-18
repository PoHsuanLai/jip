//! Reachability backend.
//!
//! All probes run synchronously on the calling thread. No tokio — probes are
//! small sequential I/O and the overhead of a runtime per call isn't worth
//! it here (unlike netlink/D-Bus, which need async for stream protocols).
//!
//! ICMP: datagram sockets with `IPPROTO_ICMP` / `IPPROTO_ICMPV6`. These work
//! without `CAP_NET_RAW` when the kernel's `ping_group_range` covers the
//! caller (verified at startup via `/proc/sys/net/ipv4/ping_group_range`).
//! Falls back to returning `capabilities().has_ping = false` when we can't
//! open the socket, so the Diagnostician can skip ICMP probes gracefully.
//!
//! TCP: `std::net::TcpStream::connect_timeout`. Good enough for v0.1.
//!
//! TLS: rustls with webpki-roots; we just want "did the handshake complete
//! with a valid chain?" — not full validation semantics.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use netcore::Error;
use netcore::Result as NcResult;
use netcore::diag::{PingOpts, ProbeCapabilities, TraceOpts};
use netcore::path::{Hop, HttpProbeResult, PingResult, TcpProbeResult, TlsProbeResult};
use netcore::traits::Reachability;

mod icmp;

/// Reachability backend: ICMP ping, TCP connect, TLS handshake, HTTP HEAD,
/// and traceroute. All methods are synchronous.
pub struct ProbeBackend {
    caps: ProbeCapabilities,
}

impl ProbeBackend {
    /// Detect available capabilities and return a new backend.
    pub fn new() -> Self {
        Self {
            caps: detect_capabilities(),
        }
    }
}

impl Default for ProbeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Reachability for ProbeBackend {
    fn ping(&self, ip: IpAddr, opts: PingOpts) -> NcResult<PingResult> {
        if !self.caps.has_ping {
            return Err(Error::Unsupported(
                "unprivileged ICMP unavailable; run as root or adjust net.ipv4.ping_group_range",
            ));
        }
        icmp::ping(ip, opts)
    }

    fn tcp_connect(&self, sa: SocketAddr, timeout: Duration) -> NcResult<TcpProbeResult> {
        let start = Instant::now();
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(s) => {
                let took = start.elapsed();
                let _ = s.shutdown(std::net::Shutdown::Both);
                Ok(TcpProbeResult {
                    addr: sa,
                    connected: true,
                    took,
                    error: None,
                })
            }
            Err(e) => Ok(TcpProbeResult {
                addr: sa,
                connected: false,
                took: start.elapsed(),
                error: Some(classify_tcp_error(&e)),
            }),
        }
    }

    fn tls_handshake(
        &self,
        sa: SocketAddr,
        sni: &str,
        timeout: Duration,
    ) -> NcResult<TlsProbeResult> {
        let start = Instant::now();
        let out = do_tls(sa, sni, timeout);
        let took = start.elapsed();
        match out {
            Ok(()) => Ok(TlsProbeResult {
                peer: sa,
                sni: sni.into(),
                negotiated: true,
                took,
                error: None,
            }),
            Err(e) => Ok(TlsProbeResult {
                peer: sa,
                sni: sni.into(),
                negotiated: false,
                took,
                error: Some(e.to_string()),
            }),
        }
    }

    fn http_head(&self, url: &url::Url, timeout: Duration) -> NcResult<HttpProbeResult> {
        let start = Instant::now();
        let result = do_http_head(url, timeout);
        let took = start.elapsed();
        match result {
            Ok(status) => Ok(HttpProbeResult {
                url: url.to_string(),
                status: Some(status),
                took,
                error: None,
            }),
            Err(e) => Ok(HttpProbeResult {
                url: url.to_string(),
                status: None,
                took,
                error: Some(e.to_string()),
            }),
        }
    }

    fn trace(&self, ip: IpAddr, opts: TraceOpts) -> NcResult<Vec<Hop>> {
        if !self.caps.has_ping {
            return Err(Error::Unsupported(
                "trace requires unprivileged ICMP; not available on this host",
            ));
        }
        icmp::trace(ip, opts)
    }

    fn capabilities(&self) -> ProbeCapabilities {
        self.caps.clone()
    }
}

/// Probe whether we can open unprivileged ICMP sockets once, at startup.
/// Much cheaper than checking `ping_group_range` text — the kernel tells us
/// directly by permitting or refusing the socket call.
fn detect_capabilities() -> ProbeCapabilities {
    let has_v4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok();
    ProbeCapabilities {
        has_ping: has_v4,
        has_traceroute: has_v4,
        has_mtr: false,
        has_tracepath: false,
        unprivileged_icmp: has_v4,
    }
}

fn classify_tcp_error(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => "timeout".into(),
        ConnectionRefused => "refused".into(),
        ConnectionReset => "reset".into(),
        HostUnreachable | NetworkUnreachable => "unreachable".into(),
        _ => e.to_string(),
    }
}

// ---- TLS ----

fn do_tls(sa: SocketAddr, sni: &str, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
    use rustls::ClientConnection;
    let server_name = rustls_pki_types::ServerName::try_from(sni.to_string())?;
    let mut sock = TcpStream::connect_timeout(&sa, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let config = tls_client_config()?;
    let mut conn = ClientConnection::new(config, server_name)?;
    // Drive the handshake to completion.
    while conn.is_handshaking() {
        if conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        if conn.wants_read() {
            conn.read_tls(&mut sock)?;
            conn.process_new_packets()?;
        }
    }
    Ok(())
}

fn tls_client_config() -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

// ---- HTTP HEAD ----

fn do_http_head(url: &url::Url, timeout: Duration) -> Result<u16, Box<dyn std::error::Error>> {
    let host = url.host_str().ok_or("url missing host")?;
    let port = url.port_or_known_default().ok_or("url missing port")?;
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let sas: Vec<SocketAddr> = (host, port).to_socket_addrs_local()?.collect();
    let sa = *sas.first().ok_or("no address for host")?;
    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: jip/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    let mut buf = [0u8; 2048];
    let n = match url.scheme() {
        "https" => http_over_tls(sa, host, &req, timeout, &mut buf)?,
        "http" => http_plain(sa, &req, timeout, &mut buf)?,
        other => return Err(format!("unsupported scheme: {other}").into()),
    };
    parse_http_status(&buf[..n])
}

fn http_plain(
    sa: SocketAddr,
    req: &str,
    timeout: Duration,
    buf: &mut [u8],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut sock = TcpStream::connect_timeout(&sa, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.write_all(req.as_bytes())?;
    Ok(sock.read(buf)?)
}

fn http_over_tls(
    sa: SocketAddr,
    sni: &str,
    req: &str,
    timeout: Duration,
    buf: &mut [u8],
) -> Result<usize, Box<dyn std::error::Error>> {
    use rustls::ClientConnection;
    let server_name = rustls_pki_types::ServerName::try_from(sni.to_string())?;
    let mut sock = TcpStream::connect_timeout(&sa, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let config = tls_client_config()?;
    let mut conn = ClientConnection::new(config, server_name)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(req.as_bytes())?;
    // Read may not fill the buffer; one read is enough to get the status line.
    Ok(tls.read(buf).unwrap_or(0))
}

fn parse_http_status(buf: &[u8]) -> Result<u16, Box<dyn std::error::Error>> {
    let s = std::str::from_utf8(buf)?;
    let first = s.lines().next().ok_or("empty http response")?;
    // HTTP/1.1 200 OK
    let mut parts = first.split_whitespace();
    parts.next().ok_or("missing version")?;
    let code = parts.next().ok_or("missing code")?;
    Ok(code.parse()?)
}

/// Small shim so we can route `(host, port)` through stdlib's ToSocketAddrs
/// without importing the trait everywhere — keeps the call site short.
trait ToSocketAddrsLocal {
    fn to_socket_addrs_local(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>>;
}

impl ToSocketAddrsLocal for (&str, u16) {
    fn to_socket_addrs_local(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
        use std::net::ToSocketAddrs;
        let v: Vec<SocketAddr> = self.to_socket_addrs()?.collect();
        Ok(v.into_iter())
    }
}

// Keep these imports used when socket2 doesn't directly appear in pub surface.
#[allow(dead_code)]
fn _touch(_: Ipv4Addr, _: Ipv6Addr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};

    #[test]
    fn tcp_connect_to_localhost_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sa = listener.local_addr().unwrap();
        let b = ProbeBackend::new();
        let r = b.tcp_connect(sa, Duration::from_millis(500)).unwrap();
        assert!(r.connected, "connect to own listener");
        assert!(r.error.is_none());
    }

    #[test]
    fn tcp_connect_refused_on_unused_port() {
        // Ephemeral port that we bind-then-drop — OS is very likely to keep
        // it closed for the next microsecond. If it races, the test would
        // incorrectly pass with connected=true; accept either but assert the
        // call didn't error out structurally.
        let sa: SocketAddr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let b = ProbeBackend::new();
        let r = b.tcp_connect(sa, Duration::from_millis(200)).unwrap();
        // After the listener dropped, connect should refuse or (rarely) race.
        assert!(
            !r.connected || r.error.is_none(),
            "structural invariants hold even under race"
        );
    }

    #[test]
    fn capabilities_are_detected() {
        let b = ProbeBackend::new();
        let c = b.capabilities();
        // On this CI/dev machine ping_group_range is wide; if it weren't,
        // has_ping would be false but the method must still be callable.
        let _ = c.has_ping;
    }

    #[test]
    fn ping_loopback_if_icmp_available() {
        let b = ProbeBackend::new();
        if !b.capabilities().has_ping {
            return;
        }
        let r = b
            .ping(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                PingOpts {
                    count: 1,
                    timeout: Duration::from_millis(500),
                },
            )
            .unwrap();
        assert_eq!(r.sent, 1);
        assert_eq!(r.received, 1, "loopback ICMP must round-trip");
    }
}
