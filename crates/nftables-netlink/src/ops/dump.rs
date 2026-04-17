//! Synchronous netlink dump operations for nftables objects.
//!
//! The send/recv loop mirrors `netcore-netlink/src/sockdiag.rs::dump_family_proto`.
//! Key differences:
//!   - Protocol: `NETLINK_NETFILTER` (12) instead of `NETLINK_SOCK_DIAG` (4)
//!   - Message payload starts with a 4-byte `nfgenmsg` header before attrs
//!   - Attribute decoding uses our custom `nfattr` TLV iterator, not
//!     `netlink-packet-*` high-level types

use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR};
use netlink_sys::{Socket as NlSocket, SocketAddr as NlSocketAddr};

use crate::codec::attr::AttrIter;
use crate::constants::*;
use crate::error::NftError;
use crate::objects::chain::{ChainPolicy, NftChain, NftHook};
use crate::objects::expr::decode_rule_exprs;
use crate::objects::rule::NftRule;
use crate::objects::table::NftTable;

// ── Low-level send/recv ──────────────────────────────────────────────────────

fn open_socket() -> Result<NlSocket, NftError> {
    let mut sock = NlSocket::new(NETLINK_NETFILTER)
        .map_err(|e| {
            if let Some(os) = e.raw_os_error() {
                if os == libc::EPERM {
                    return NftError::MissingCapability;
                }
            }
            NftError::Socket(e)
        })?;
    sock.bind_auto()
        .map_err(NftError::Socket)?;
    sock.connect(&NlSocketAddr::new(0, 0))
        .map_err(NftError::Socket)?;
    Ok(sock)
}

/// Build a DUMP request message for the given nftables message type.
/// Layout: nlmsghdr (16 bytes) + nfgenmsg (4 bytes).
fn build_dump_request(msg_type: u16, seq: u32) -> Vec<u8> {
    // Total length: nlmsghdr (16) + nfgenmsg (4) = 20
    let total_len: u32 = 20;
    let mut buf = Vec::with_capacity(20);

    // nlmsghdr
    buf.extend_from_slice(&total_len.to_ne_bytes());   // nlmsg_len
    buf.extend_from_slice(&nft_msg_type(msg_type).to_ne_bytes()); // nlmsg_type
    let flags: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    buf.extend_from_slice(&flags.to_ne_bytes());        // nlmsg_flags
    buf.extend_from_slice(&seq.to_ne_bytes());          // nlmsg_seq
    buf.extend_from_slice(&0u32.to_ne_bytes());         // nlmsg_pid

    // nfgenmsg: family=AF_UNSPEC(0), version=NFNETLINK_V0(0), res_id=0 (big-endian)
    buf.push(0); // nfgen_family = AF_UNSPEC
    buf.push(NFNETLINK_V0);
    buf.extend_from_slice(&0u16.to_be_bytes()); // res_id

    buf
}

/// Read one complete multi-part reply. Calls `on_msg` for each inner message
/// body (the bytes after the `nfgenmsg` header). Stops on `NLMSG_DONE`.
fn recv_dump<F>(sock: &NlSocket, mut on_msg: F) -> Result<(), NftError>
where
    F: FnMut(u8, &[u8]) -> Result<(), NftError>,
{
    let mut recv_buf = vec![0u8; 65536];
    'outer: loop {
        let n = sock
            .recv(&mut recv_buf, 0)
            .map_err(NftError::Recv)?;

        let mut offset = 0usize;
        while offset + 16 <= n {
            // Parse nlmsghdr manually (avoid pulling in the full netlink-packet
            // serialisation layer for something this simple).
            let hdr_bytes = &recv_buf[offset..offset + 16];
            let msg_len = u32::from_ne_bytes(hdr_bytes[0..4].try_into().unwrap()) as usize;
            let msg_type = u16::from_ne_bytes(hdr_bytes[4..6].try_into().unwrap());

            if msg_len < 16 || offset + msg_len > n {
                break;
            }

            match msg_type {
                NLMSG_DONE => break 'outer,
                NLMSG_ERROR => {
                    // Error struct: i32 errno immediately after header.
                    let errno_bytes = &recv_buf[offset + 16..offset + 20];
                    let errno = i32::from_ne_bytes(errno_bytes.try_into().unwrap());
                    if errno != 0 {
                        return Err(NftError::KernelError(-errno));
                    }
                    break 'outer;
                }
                _ => {
                    // Inner payload starts after nlmsghdr (16 bytes) + nfgenmsg (4 bytes).
                    if offset + 20 <= n {
                        let family = recv_buf[offset + 16]; // nfgen_family
                        let body = &recv_buf[offset + 20..offset + msg_len];
                        on_msg(family, body)?;
                    }
                }
            }

            // Advance to next message (aligned to 4 bytes).
            let padded = (msg_len + 3) & !3;
            offset += padded;
        }
    }
    Ok(())
}

// ── Public dump functions ────────────────────────────────────────────────────

/// List all nftables tables.
pub fn dump_tables() -> Result<Vec<NftTable>, NftError> {
    let sock = open_socket()?;
    let req = build_dump_request(NFT_MSG_GETTABLE, 1);
    sock.send(&req, 0).map_err(NftError::Send)?;

    let mut tables = Vec::new();
    recv_dump(&sock, |family, body| {
        let mut name = None;
        let mut handle = 0u64;
        for a in AttrIter::new(body) {
            let a = a?;
            match a.attr_type {
                NFTA_TABLE_NAME => name = a.as_str().map(|s| s.to_string()),
                NFTA_TABLE_HANDLE => handle = a.as_be_u64().unwrap_or(0),
                _ => {}
            }
        }
        if let Some(name) = name {
            tables.push(NftTable { family, name, handle });
        }
        Ok(())
    })?;
    Ok(tables)
}

/// List all nftables chains (across all tables).
pub fn dump_chains() -> Result<Vec<NftChain>, NftError> {
    let sock = open_socket()?;
    let req = build_dump_request(NFT_MSG_GETCHAIN, 2);
    sock.send(&req, 0).map_err(NftError::Send)?;

    let mut chains = Vec::new();
    recv_dump(&sock, |_family, body| {
        let mut table = None;
        let mut name = None;
        let mut handle = 0u64;
        let mut hook: Option<NftHook> = None;
        let mut priority: Option<i32> = None;
        let mut policy = ChainPolicy::Accept;

        for a in AttrIter::new(body) {
            let a = a?;
            match a.attr_type {
                NFTA_CHAIN_TABLE => table = a.as_str().map(|s| s.to_string()),
                NFTA_CHAIN_NAME => name = a.as_str().map(|s| s.to_string()),
                NFTA_CHAIN_HANDLE => handle = a.as_be_u64().unwrap_or(0),
                NFTA_CHAIN_POLICY => {
                    policy = match a.as_be_u32() {
                        Some(0) => ChainPolicy::Drop, // NF_DROP
                        _ => ChainPolicy::Accept,
                    };
                }
                NFTA_CHAIN_HOOK => {
                    // Nested: NFTA_HOOK_HOOKNUM + NFTA_HOOK_PRIORITY
                    for inner in a.nested() {
                        let inner = inner?;
                        match inner.attr_type {
                            NFTA_HOOK_HOOKNUM => {
                                if let Some(n) = inner.as_be_u32() {
                                    hook = Some(NftHook::from_hooknum(n));
                                }
                            }
                            NFTA_HOOK_PRIORITY => {
                                priority = inner
                                    .as_be_u32()
                                    .map(|v| v as i32);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if let (Some(table), Some(name)) = (table, name) {
            chains.push(NftChain { table, name, hook, priority, policy, handle });
        }
        Ok(())
    })?;
    Ok(chains)
}

/// List all nftables rules (across all tables and chains) with decoded expressions.
pub fn dump_rules() -> Result<Vec<NftRule>, NftError> {
    let sock = open_socket()?;
    let req = build_dump_request(NFT_MSG_GETRULE, 3);
    sock.send(&req, 0).map_err(NftError::Send)?;

    let mut rules = Vec::new();
    recv_dump(&sock, |_family, body| {
        let mut table = None;
        let mut chain = None;
        let mut handle = 0u64;
        let mut exprs = Vec::new();

        for a in AttrIter::new(body) {
            let a = a?;
            match a.attr_type {
                NFTA_RULE_TABLE => table = a.as_str().map(|s| s.to_string()),
                NFTA_RULE_CHAIN => chain = a.as_str().map(|s| s.to_string()),
                NFTA_RULE_HANDLE => handle = a.as_be_u64().unwrap_or(0),
                NFTA_RULE_EXPRESSIONS => {
                    exprs = decode_rule_exprs(a.data).unwrap_or_default();
                }
                _ => {}
            }
        }

        if let (Some(table), Some(chain)) = (table, chain) {
            rules.push(NftRule { table, chain, handle, exprs });
        }
        Ok(())
    })?;
    Ok(rules)
}
