//! Unprivileged ICMP via `IPPROTO_ICMP` / `IPPROTO_ICMPV6` datagram sockets.
//!
//! ## How trace works without CAP_NET_RAW
//!
//! A datagram ICMP socket only gets echo replies addressed to it as normal
//! datagrams (kernel identifies them by the ID it rewrote into the echo
//! request on send). ICMP *error* replies — Time Exceeded, Destination
//! Unreachable — aren't addressed to the socket's ID, so the kernel puts
//! them on the *error queue* instead. We opt in with `IP_RECVERR` and read
//! them via `recvmsg(MSG_ERRQUEUE)`; the ancillary data carries a
//! `sock_extended_err` followed by the offender's sockaddr.
//!
//! For each TTL we `poll()` for `POLLIN | POLLERR` and handle whichever
//! fires: `POLLIN` = echo reply (we reached the target), `POLLERR` =
//! router/host error (a trace hop or final unreachable).
//!
//! The same mechanism gives accurate ping RTTs without needing raw sockets.

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use netcore::Error;
use netcore::Result as NcResult;
use netcore::diag::{PingOpts, TraceOpts};
use netcore::path::{Hop, PingResult};

// ---- public entry points ----

pub fn ping(ip: IpAddr, opts: PingOpts) -> NcResult<PingResult> {
    let sock = open_icmp_socket(ip)?;
    set_recverr(&sock, ip)?;

    let mut sent = 0u32;
    let mut received = 0u32;
    let mut rtts = Vec::<Duration>::new();

    for seq in 0..opts.count {
        sent += 1;
        let echo = build_echo(seq as u16, ip.is_ipv6());
        let start = Instant::now();
        let dest = SockAddr::from(SocketAddr::new(ip, 0));
        if sock.send_to(&echo, &dest).is_err() {
            continue;
        }
        match wait_for_icmp(&sock, seq as u16, opts.timeout) {
            Ok(IcmpOutcome::EchoReply { from, .. }) if from == ip => {
                received += 1;
                rtts.push(start.elapsed());
            }
            Ok(IcmpOutcome::EchoReply { .. }) => { /* stray reply */ }
            Ok(IcmpOutcome::Error { .. }) => { /* unreachable / TTL exceeded */ }
            Err(_) => { /* timeout */ }
        }
    }

    Ok(PingResult {
        sent,
        received,
        rtt_min: rtts.iter().min().copied(),
        rtt_avg: if rtts.is_empty() {
            None
        } else {
            Some(Duration::from_nanos(
                (rtts.iter().map(|d| d.as_nanos()).sum::<u128>() / rtts.len() as u128) as u64,
            ))
        },
        rtt_max: rtts.iter().max().copied(),
    })
}

pub fn trace(ip: IpAddr, opts: TraceOpts) -> NcResult<Vec<Hop>> {
    let sock = open_icmp_socket(ip)?;
    set_recverr(&sock, ip)?;

    let mut hops = Vec::with_capacity(opts.max_hops as usize);
    for ttl in 1..=opts.max_hops {
        set_ttl(&sock, ip, ttl as u32)?;
        let echo = build_echo(ttl as u16, ip.is_ipv6());
        let start = Instant::now();
        let dest = SockAddr::from(SocketAddr::new(ip, 0));
        let _ = sock.send_to(&echo, &dest);
        match wait_for_icmp(&sock, ttl as u16, opts.timeout_per_hop) {
            Ok(IcmpOutcome::EchoReply { from, .. }) => {
                hops.push(Hop { ttl, ip: Some(from), rtt: Some(start.elapsed()), hostname: None });
                break;
            }
            Ok(IcmpOutcome::Error { router, done, .. }) => {
                hops.push(Hop { ttl, ip: Some(router), rtt: Some(start.elapsed()), hostname: None });
                if done { break; }
            }
            Err(_) => {
                hops.push(Hop { ttl, ip: None, rtt: None, hostname: None });
            }
        }
    }
    Ok(hops)
}

// ---- socket setup ----

fn open_icmp_socket(ip: IpAddr) -> NcResult<Socket> {
    let (domain, proto) = match ip {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };
    let s = Socket::new(domain, Type::DGRAM, Some(proto)).map_err(|e| {
        Error::Backend(format!(
            "open ICMP socket (need unprivileged ICMP; check net.ipv4.ping_group_range): {e}"
        ))
    })?;
    s.set_nonblocking(true).map_err(|e| Error::Backend(format!("set_nonblocking: {e}")))?;
    Ok(s)
}

fn set_recverr(sock: &Socket, ip: IpAddr) -> NcResult<()> {
    let fd = sock.as_raw_fd();
    let on: libc::c_int = 1;
    let (level, name) = match ip {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_RECVERR),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_RECVERR),
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &on as *const _ as *const libc::c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::Backend(format!(
            "setsockopt IP_RECVERR: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_ttl(sock: &Socket, ip: IpAddr, ttl: u32) -> NcResult<()> {
    match ip {
        IpAddr::V4(_) => sock.set_ttl_v4(ttl),
        IpAddr::V6(_) => sock.set_unicast_hops_v6(ttl),
    }
    .map_err(|e| Error::Backend(format!("set ttl: {e}")))
}

// ---- ICMP echo construction ----

fn build_echo(seq: u16, v6: bool) -> Vec<u8> {
    // type, code, checksum(0), identifier(0 — kernel rewrites), seq, 8 bytes payload
    let ty: u8 = if v6 { 128 } else { 8 };
    let mut p = vec![ty, 0, 0, 0, 0, 0, (seq >> 8) as u8, (seq & 0xff) as u8];
    // Payload: arbitrary marker so we can identify our packets if needed.
    p.extend_from_slice(b"jip-icmp");
    // For v4 the kernel computes the checksum for us on IPPROTO_ICMP dgram
    // sockets. For v6 (IPPROTO_ICMPV6) the kernel also fills in the
    // checksum when it's left zero. Leave it zero.
    p
}

// ---- waiting and parsing ----

enum IcmpOutcome {
    EchoReply { from: IpAddr, #[allow(dead_code)] seq: u16 },
    Error {
        router: IpAddr,
        #[allow(dead_code)] ee_type: u8,
        #[allow(dead_code)] ee_code: u8,
        done: bool,
    },
}

fn wait_for_icmp(sock: &Socket, _seq: u16, timeout: Duration) -> NcResult<IcmpOutcome> {
    let fd = sock.as_raw_fd();
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Backend("icmp timeout".into()));
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN | libc::POLLERR, revents: 0 };
        let ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(Error::Backend(format!("poll: {e}")));
        }
        if rc == 0 {
            return Err(Error::Backend("icmp timeout".into()));
        }
        // Drain error queue first — router/host replies live there.
        if pfd.revents & libc::POLLERR != 0 {
            if let Some(out) = recv_error_queue(sock)? {
                return Ok(out);
            }
        }
        if pfd.revents & libc::POLLIN != 0 {
            if let Some(out) = recv_normal(sock)? {
                return Ok(out);
            }
        }
    }
}

fn recv_normal(sock: &Socket) -> NcResult<Option<IcmpOutcome>> {
    let mut buf: [MaybeUninit<u8>; 1500] = [MaybeUninit::uninit(); 1500];
    match sock.recv_from(&mut buf) {
        Ok((n, addr)) => {
            let bytes: Vec<u8> = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
            let Some(sa) = addr.as_socket() else { return Ok(None) };
            // First byte is ICMP type on both v4 (IPPROTO_ICMP strips IP hdr
            // for dgram sockets) and v6.
            if bytes.is_empty() { return Ok(None); }
            let ty = bytes[0];
            // Echo Reply: v4 type=0, v6 type=129. Seq is at offset 6..8.
            if (ty == 0 || ty == 129) && bytes.len() >= 8 {
                let seq = ((bytes[6] as u16) << 8) | bytes[7] as u16;
                return Ok(Some(IcmpOutcome::EchoReply { from: sa.ip(), seq }));
            }
            Ok(None)
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(Error::Backend(format!("icmp recv: {e}"))),
    }
}

/// Read one message from the error queue. Returns the parsed outcome, or
/// `None` if the queue was empty / we couldn't extract an offender address.
fn recv_error_queue(sock: &Socket) -> NcResult<Option<IcmpOutcome>> {
    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 1500];
    let mut control = [0u8; 512];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    // msg_name holds the ICMP source of the *original* packet echoed back
    // inside the ICMP error. We read it but the real router address comes
    // from the cmsg offender.
    let mut name_storage = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = name_storage.as_mut_ptr() as *mut _;
    msg.msg_namelen = name_storage.len() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut _;
    msg.msg_controllen = control.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock { return Ok(None); }
        return Err(Error::Backend(format!("recvmsg(ERRQUEUE): {e}")));
    }

    // Walk cmsgs looking for IP_RECVERR / IPV6_RECVERR.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        let is_v4 = level == libc::IPPROTO_IP && ty == libc::IP_RECVERR;
        let is_v6 = level == libc::IPPROTO_IPV6 && ty == libc::IPV6_RECVERR;
        if is_v4 || is_v6 {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let ee: SockExtendedErr = unsafe { std::ptr::read_unaligned(data_ptr as *const _) };
            let off_ptr = unsafe { data_ptr.add(mem::size_of::<SockExtendedErr>()) };
            let router: IpAddr = if is_v4 {
                let sa: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(off_ptr as *const _) };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
            } else {
                let sa: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(off_ptr as *const _) };
                IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
            };
            // Time Exceeded: v4 type=11, v6 type=3. Dest-unreach: v4=3, v6=1.
            let done = match (is_v4, ee.ee_type) {
                (true, 3) | (false, 1) => true,  // unreachable — stop trace
                _ => false,
            };
            // For echo reply arriving via error queue (rare), recognise and
            // surface as EchoReply so caller sees target reached.
            let reached = ee.ee_errno == 0;
            if reached {
                return Ok(Some(IcmpOutcome::EchoReply { from: router, seq: 0 }));
            }
            return Ok(Some(IcmpOutcome::Error {
                router,
                ee_type: ee.ee_type,
                ee_code: ee.ee_code,
                done,
            }));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(None)
}

/// Mirror of `struct sock_extended_err` from `<linux/errqueue.h>`.
/// Stable ABI; 16 bytes. We read this with `read_unaligned` from the cmsg
/// payload, so the repr matters.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
}
