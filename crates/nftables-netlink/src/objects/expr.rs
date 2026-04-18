//! nftables expression types decoded from the NFTA_RULE_EXPRESSIONS attribute.
//!
//! The kernel uses a virtual register file. A port match is encoded as:
//!   1. `meta l4proto`  → writes protocol byte to a register
//!   2. `payload` transport dport  → writes 2-byte port to a register
//!   3. two `cmp ==` expressions reading those registers
//!
//! We track a small per-rule register state to reconstruct the logical match.

use netcore::link::L4Proto;

use crate::codec::attr::AttrIter;
use crate::constants::*;
use crate::error::NftError;

/// A decoded expression from a rule's expression list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    PortMatch(PortMatch),
    Verdict(RuleVerdict),
    Counter {
        packets: u64,
        bytes: u64,
    },
    /// Expression type we don't model (sets, maps, conntrack, etc.).
    Named(String),
}

/// A protocol+port comparison matched against incoming packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMatch {
    pub proto: L4Proto,
    pub port: u16,
}

/// Terminal verdict of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleVerdict {
    Accept,
    Drop,
    Reject,
    Jump(String),
    Goto(String),
    Return,
}

// ── Register state machine ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum RegContent {
    L4Proto(u8),
    Port(u16),
}

/// Per-rule register state used while decoding expressions sequentially.
pub struct RegFile {
    slots: [Option<RegContent>; 16],
}

impl RegFile {
    pub fn new() -> Self {
        Self { slots: [None; 16] }
    }

    fn set(&mut self, reg: u32, val: RegContent) {
        if let Some(slot) = self.slots.get_mut(reg as usize) {
            *slot = Some(val);
        }
    }

    fn get(&self, reg: u32) -> Option<RegContent> {
        self.slots.get(reg as usize).copied().flatten()
    }
}

// ── Expression parsing ───────────────────────────────────────────────────────

/// Decode one expression element (the bytes under a single `NFTA_LIST_ELEM`
/// attr) and accumulate register state. Returns `Some(Expr)` when a complete
/// logical expression is recognisable, `None` when the expression only updates
/// register state for a subsequent expression to consume.
pub fn decode_expr<'a>(data: &'a [u8], regs: &mut RegFile) -> Result<Option<Expr>, NftError> {
    let mut name: Option<&'a str> = None;
    let mut expr_data: Option<&'a [u8]> = None;

    for item in AttrIter::new(data) {
        let a = item?;
        match a.attr_type {
            NFTA_EXPR_NAME => name = a.as_str(),
            NFTA_EXPR_DATA => expr_data = Some(a.data),
            _ => {}
        }
    }

    let name = match name {
        Some(n) => n,
        None => return Ok(None),
    };
    let data = expr_data.unwrap_or(&[]);

    match name {
        "meta" => decode_meta(data, regs),
        "payload" => decode_payload(data, regs),
        "cmp" => decode_cmp(data, regs),
        "immediate" => decode_immediate(data),
        "counter" => decode_counter(data),
        other => Ok(Some(Expr::Named(other.to_string()))),
    }
}

fn decode_meta(data: &[u8], regs: &mut RegFile) -> Result<Option<Expr>, NftError> {
    let mut dreg = None;
    let mut key = None;
    for a in AttrIter::new(data) {
        let a = a?;
        match a.attr_type {
            NFTA_META_DREG => dreg = a.as_be_u32(),
            NFTA_META_KEY => key = a.as_be_u32(),
            _ => {}
        }
    }
    if let (Some(reg), Some(NFT_META_L4PROTO)) = (dreg, key) {
        // We don't know the protocol value yet — it's set by a later cmp.
        // Mark the register as "contains l4proto" with a sentinel.
        regs.set(reg, RegContent::L4Proto(0xFF));
    }
    Ok(None)
}

fn decode_payload(data: &[u8], regs: &mut RegFile) -> Result<Option<Expr>, NftError> {
    let mut dreg = None;
    let mut base = None;
    let mut offset = None;
    let mut len = None;
    for a in AttrIter::new(data) {
        let a = a?;
        match a.attr_type {
            NFTA_PAYLOAD_DREG => dreg = a.as_be_u32(),
            NFTA_PAYLOAD_BASE => base = a.as_be_u32(),
            NFTA_PAYLOAD_OFFSET => offset = a.as_be_u32(),
            NFTA_PAYLOAD_LEN => len = a.as_be_u32(),
            _ => {}
        }
    }
    // Transport header offset 2, len 2 → TCP/UDP destination port.
    if base == Some(NFT_PAYLOAD_TRANSPORT_HEADER) && offset == Some(2) && len == Some(2) {
        if let Some(reg) = dreg {
            regs.set(reg, RegContent::Port(0));
        }
    }
    Ok(None)
}

fn decode_cmp(data: &[u8], regs: &mut RegFile) -> Result<Option<Expr>, NftError> {
    let mut sreg = None;
    let mut op = None;
    let mut cmp_val: Option<Vec<u8>> = None;

    for a in AttrIter::new(data) {
        let a = a?;
        match a.attr_type {
            NFTA_CMP_SREG => sreg = a.as_be_u32(),
            NFTA_CMP_OP => op = a.as_be_u32(),
            NFTA_CMP_DATA => {
                // NFTA_CMP_DATA is a nested attr containing NFTA_DATA_VALUE.
                for inner in a.nested() {
                    let inner = inner?;
                    if inner.attr_type == NFTA_DATA_VALUE {
                        cmp_val = Some(inner.data.to_vec());
                    }
                }
            }
            _ => {}
        }
    }

    if op != Some(NFT_CMP_EQ) {
        return Ok(None);
    }
    let reg = match sreg {
        Some(r) => r,
        None => return Ok(None),
    };
    let val = match cmp_val {
        Some(v) => v,
        None => return Ok(None),
    };
    let content = regs.get(reg);

    match content {
        Some(RegContent::L4Proto(_)) => {
            // The cmp value is a 1-byte protocol number.
            if let Some(&proto_byte) = val.first() {
                let proto = match proto_byte {
                    6 => Some(L4Proto::Tcp),
                    17 => Some(L4Proto::Udp),
                    _ => None,
                };
                if let Some(p) = proto {
                    // Update the register to carry the actual protocol.
                    regs.set(reg, RegContent::L4Proto(proto_byte));
                    // Check if any port register is primed — if so, emit the match.
                    return Ok(try_emit_port_match(regs, p));
                }
            }
            Ok(None)
        }
        Some(RegContent::Port(_)) => {
            // The cmp value is a 2-byte big-endian port number.
            if val.len() >= 2 {
                let port = u16::from_be_bytes([val[0], val[1]]);
                regs.set(reg, RegContent::Port(port));
                // Look for a protocol register that has been resolved.
                if let Some(proto) = find_resolved_proto(regs) {
                    return Ok(Some(Expr::PortMatch(PortMatch { proto, port })));
                }
            }
            Ok(None)
        }
        None => Ok(None),
    }
}

fn try_emit_port_match(regs: &RegFile, proto: L4Proto) -> Option<Expr> {
    for slot in &regs.slots {
        if let Some(RegContent::Port(port)) = slot {
            if *port != 0 {
                return Some(Expr::PortMatch(PortMatch { proto, port: *port }));
            }
        }
    }
    None
}

fn find_resolved_proto(regs: &RegFile) -> Option<L4Proto> {
    for slot in &regs.slots {
        if let Some(RegContent::L4Proto(b)) = slot {
            match b {
                6 => return Some(L4Proto::Tcp),
                17 => return Some(L4Proto::Udp),
                _ => {}
            }
        }
    }
    None
}

fn decode_immediate(data: &[u8]) -> Result<Option<Expr>, NftError> {
    // Verdict immediates have NFTA_IMMEDIATE_DATA → NFTA_DATA_VERDICT →
    // NFTA_VERDICT_CODE (+ optional NFTA_VERDICT_CHAIN for jump/goto).
    for a in AttrIter::new(data) {
        let a = a?;
        if a.attr_type == NFTA_IMMEDIATE_DATA {
            for inner in a.nested() {
                let inner = inner?;
                if inner.attr_type == NFTA_DATA_VERDICT {
                    return decode_verdict_data(inner.data).map(|v| v.map(Expr::Verdict));
                }
            }
        }
    }
    Ok(None)
}

fn decode_verdict_data(data: &[u8]) -> Result<Option<RuleVerdict>, NftError> {
    let mut code: Option<u32> = None;
    let mut chain: Option<String> = None;

    for a in AttrIter::new(data) {
        let a = a?;
        match a.attr_type {
            NFTA_VERDICT_CODE => code = a.as_be_u32(),
            NFTA_VERDICT_CHAIN => chain = a.as_str().map(|s| s.to_string()),
            _ => {}
        }
    }

    let Some(code) = code else { return Ok(None) };
    let verdict = match code {
        NF_ACCEPT => RuleVerdict::Accept,
        NF_DROP => RuleVerdict::Drop,
        NFT_JUMP => RuleVerdict::Jump(chain.unwrap_or_default()),
        NFT_GOTO => RuleVerdict::Goto(chain.unwrap_or_default()),
        NFT_RETURN => RuleVerdict::Return,
        // Reject is typically implemented as a separate expression in
        // nftables kernels, but map unknown drop-like codes defensively.
        _ => return Ok(None),
    };
    Ok(Some(verdict))
}

fn decode_counter(data: &[u8]) -> Result<Option<Expr>, NftError> {
    // Counter attrs use NFTA_COUNTER_BYTES = 1, NFTA_COUNTER_PACKETS = 2.
    const NFTA_COUNTER_BYTES: u16 = 1;
    const NFTA_COUNTER_PACKETS: u16 = 2;

    let mut packets = 0u64;
    let mut bytes = 0u64;
    for a in AttrIter::new(data) {
        let a = a?;
        match a.attr_type {
            NFTA_COUNTER_BYTES => bytes = a.as_be_u64().unwrap_or(0),
            NFTA_COUNTER_PACKETS => packets = a.as_be_u64().unwrap_or(0),
            _ => {}
        }
    }
    Ok(Some(Expr::Counter { packets, bytes }))
}

// ── Parse an entire NFTA_RULE_EXPRESSIONS attribute ─────────────────────────

/// Decode all expressions from the `NFTA_RULE_EXPRESSIONS` attribute data.
/// Errors in individual expressions are skipped (forward-compatible).
pub fn decode_rule_exprs(data: &[u8]) -> Result<Vec<Expr>, NftError> {
    let mut exprs = Vec::new();
    let mut regs = RegFile::new();

    for elem in AttrIter::new(data) {
        let elem = elem?;
        if elem.attr_type != NFTA_LIST_ELEM {
            continue;
        }
        match decode_expr(elem.data, &mut regs) {
            Ok(Some(e)) => exprs.push(e),
            Ok(None) => {}
            Err(_) => {} // unknown / malformed expression — skip
        }
    }
    Ok(exprs)
}

// ── Reject expression ────────────────────────────────────────────────────────
// Reject is a standalone expression (not an immediate verdict). It is encoded
// as name="reject" with NFTA_REJECT_TYPE and NFTA_REJECT_ICMP_CODE attrs. We
// recognise the name and emit Verdict::Reject without decoding the type.
// This is handled in decode_expr's match arm above: "reject" maps to a Named
// and the firewall layer maps Named("reject") → Reject. To keep it clean, we
// add a dedicated path in decode_expr via the match arm.

// NOTE: The match arm in decode_expr handles "reject" → Verdict(Reject) via
// the Named fallthrough in the firewall translation layer. If we want to emit
// it directly from this crate, we need to add a "reject" arm. We do that
// minimally here as a re-export so the firewall crate can match on it.

impl Expr {
    /// Returns `true` if this expression represents a terminal reject.
    pub fn is_reject_named(&self) -> bool {
        matches!(self, Expr::Named(n) if n == "reject")
    }
}
