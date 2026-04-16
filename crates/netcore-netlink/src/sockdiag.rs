//! Socket enumeration via `NETLINK_SOCK_DIAG`.
//!
//! Returns every TCP and UDP socket currently known to the kernel in both
//! IPv4 and IPv6. Listens get mapped to `Service`, established to `Flow`,
//! everything else stays as raw `Socket` in `InventoryRaw::sockets`.
//!
//! Process ownership is resolved by walking `/proc/*/fd/*` and matching
//! the inode we got from the kernel against the socket symlink's target.
//! When we can't read a `/proc/<pid>/fd` directory (another user's
//! process), we mark the socket `PermissionDenied` rather than hiding it.
//! The CLI then emits one aggregate finding instead of N missing owners.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP},
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket as NlSocket, SocketAddr as NlSocketAddr};

// TCP state numeric codes. `TCP_*` constants in `netlink_packet_sock_diag`
// come in as `u8`, and `InetResponseHeader::state` is a `u8`, so we use the
// raw values inline — cheaper than `_ as u8` every arm.
const STATE_ESTABLISHED: u8 = 1;
const STATE_SYN_SENT: u8 = 2;
const STATE_SYN_RECV: u8 = 3;
const STATE_FIN_WAIT1: u8 = 4;
const STATE_FIN_WAIT2: u8 = 5;
const STATE_TIME_WAIT: u8 = 6;
const STATE_CLOSE: u8 = 7;
const STATE_CLOSE_WAIT: u8 = 8;
const STATE_LAST_ACK: u8 = 9;
const STATE_LISTEN: u8 = 10;
const STATE_CLOSING: u8 = 11;

use netcore::link::{L4Proto, Socket, TcpState};
use netcore::process::{ProcessInfo, ProcessRef};
use netcore::{Error, Result};

/// Dump TCP + UDP, IPv4 + IPv6. Four separate request/response cycles.
pub fn dump_all() -> Result<Vec<Socket>> {
    let inode_to_proc = build_inode_index();
    let mut out = Vec::with_capacity(128);
    for family in [AF_INET, AF_INET6] {
        for (proto, states) in [
            (IPPROTO_TCP, StateFlags::all()),
            (IPPROTO_UDP, StateFlags::all()),
        ] {
            let entries = dump_family_proto(family, proto, states)?;
            for header in entries {
                out.push(header_to_socket(&header, proto, &inode_to_proc));
            }
        }
    }
    Ok(out)
}

fn dump_family_proto(
    family: u8,
    protocol: u8,
    states: StateFlags,
) -> Result<Vec<netlink_packet_sock_diag::inet::InetResponseHeader>> {
    let mut socket = NlSocket::new(NETLINK_SOCK_DIAG)
        .map_err(|e| Error::Backend(format!("sock_diag socket: {e}")))?;
    socket
        .bind_auto()
        .map_err(|e| Error::Backend(format!("sock_diag bind: {e}")))?;
    socket
        .connect(&NlSocketAddr::new(0, 0))
        .map_err(|e| Error::Backend(format!("sock_diag connect: {e}")))?;

    let req = InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::empty(),
        states,
        socket_id: if family == AF_INET { SocketId::new_v4() } else { SocketId::new_v6() },
    };

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(header, SockDiagMessage::InetRequest(req).into());
    packet.finalize();
    let mut buf = vec![0u8; packet.header.length as usize];
    packet.serialize(&mut buf);

    socket
        .send(&buf, 0)
        .map_err(|e| Error::Backend(format!("sock_diag send: {e}")))?;

    let mut headers = Vec::with_capacity(32);
    let mut recv_buf = vec![0u8; 8192];
    'outer: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| Error::Backend(format!("sock_diag recv: {e}")))?;
        let mut offset = 0;
        while offset < n {
            let slice = &recv_buf[offset..n];
            let msg = <NetlinkMessage<SockDiagMessage>>::deserialize(slice).map_err(|e| {
                Error::Backend(format!("sock_diag parse: {e}"))
            })?;
            let len = msg.header.length as usize;
            match msg.payload {
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(r)) => {
                    headers.push(r.header);
                }
                NetlinkPayload::Done(_) => break 'outer,
                NetlinkPayload::Error(e) => {
                    return Err(Error::Backend(format!("sock_diag kernel err: {:?}", e)));
                }
                _ => {}
            }
            if len == 0 { break; }
            offset += len;
        }
    }
    Ok(headers)
}

fn header_to_socket(
    h: &netlink_packet_sock_diag::inet::InetResponseHeader,
    protocol: u8,
    index: &InodeIndex,
) -> Socket {
    let proto = if protocol == IPPROTO_TCP { L4Proto::Tcp } else { L4Proto::Udp };
    let local = SocketAddr::new(h.socket_id.source_address, h.socket_id.source_port);
    let remote_ip = h.socket_id.destination_address;
    let remote_is_zero = match remote_ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };
    let remote = if remote_is_zero && h.socket_id.destination_port == 0 {
        None
    } else {
        Some(SocketAddr::new(remote_ip, h.socket_id.destination_port))
    };
    let state = tcp_state_from(h.state);
    let process = match index {
        InodeIndex::Full(map) => map
            .get(&h.inode)
            .cloned()
            .map(ProcessInfo::Known)
            .unwrap_or(ProcessInfo::Anonymous),
        InodeIndex::Partial(map) => map
            .get(&h.inode)
            .cloned()
            .map(ProcessInfo::Known)
            .unwrap_or(ProcessInfo::PermissionDenied),
    };
    Socket {
        proto,
        local,
        remote,
        state,
        process,
        bound_iface: None,
    }
}

fn tcp_state_from(s: u8) -> TcpState {
    match s {
        STATE_ESTABLISHED => TcpState::Established,
        STATE_SYN_SENT => TcpState::SynSent,
        STATE_SYN_RECV => TcpState::SynRecv,
        STATE_FIN_WAIT1 => TcpState::FinWait1,
        STATE_FIN_WAIT2 => TcpState::FinWait2,
        STATE_TIME_WAIT => TcpState::TimeWait,
        STATE_CLOSE => TcpState::Close,
        STATE_CLOSE_WAIT => TcpState::CloseWait,
        STATE_LAST_ACK => TcpState::LastAck,
        STATE_LISTEN => TcpState::Listen,
        STATE_CLOSING => TcpState::Closing,
        // UDP "sockets" have state=7 (TCP_CLOSE); the caller distinguishes
        // UDP from TCP by protocol before mapping to Service/Flow.
        _ => TcpState::Unknown,
    }
}

enum InodeIndex {
    /// We walked every `/proc/*/fd` successfully.
    Full(HashMap<u32, ProcessRef>),
    /// We hit at least one EACCES; map contains what we did see.
    Partial(HashMap<u32, ProcessRef>),
}

/// Walk `/proc/*/fd/*` once, looking for `socket:[inode]` symlinks.
/// Returns a single index covering every socket inode we could resolve,
/// plus a flag telling us whether any directory denied access.
fn build_inode_index() -> InodeIndex {
    let mut map = HashMap::with_capacity(128);
    let mut permission_denied = false;
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return InodeIndex::Partial(map);
    };
    for entry in proc_entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };

        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let fd_dir = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                permission_denied = true;
                continue;
            }
            Err(_) => continue,
        };
        for fd in fd_dir.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if let Some(s) = target.to_str() {
                    if let Some(rest) = s.strip_prefix("socket:[") {
                        if let Some(num) = rest.strip_suffix(']') {
                            if let Ok(inode) = num.parse::<u32>() {
                                map.entry(inode).or_insert_with(|| ProcessRef {
                                    pid,
                                    comm: comm.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    if permission_denied { InodeIndex::Partial(map) } else { InodeIndex::Full(map) }
}
