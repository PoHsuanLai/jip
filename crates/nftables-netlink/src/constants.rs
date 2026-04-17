//! Wire constants from `linux/netfilter/nf_tables.h` and
//! `linux/netfilter/nfnetlink.h`. Encoded as named Rust constants so we have
//! zero C FFI dependency.

// ── Netlink protocol ────────────────────────────────────────────────────────

pub const NETLINK_NETFILTER: isize = 12;

// ── Nfnetlink subsystem / version ───────────────────────────────────────────

pub const NFNL_SUBSYS_NFTABLES: u16 = 12;
pub const NFNETLINK_V0: u8 = 0;

// ── nf_tables message types (NFT_MSG_*) ─────────────────────────────────────
// Lower 8 bits of nlmsg_type; upper 8 bits are NFNL_SUBSYS_NFTABLES.

pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_GETCHAIN: u16 = 4;
pub const NFT_MSG_DELCHAIN: u16 = 5;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_GETRULE: u16 = 7;
pub const NFT_MSG_DELRULE: u16 = 8;
pub const NFT_MSG_NEWBATCH: u16 = 14;
pub const NFT_MSG_DELBATCH: u16 = 16;

// Build the full nlmsg_type from subsystem + message.
#[inline]
pub const fn nft_msg_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

// ── Table attributes (NFTA_TABLE_*) ─────────────────────────────────────────

pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_TABLE_FLAGS: u16 = 2;
pub const NFTA_TABLE_USE: u16 = 3;
pub const NFTA_TABLE_HANDLE: u16 = 4;

// ── Chain attributes (NFTA_CHAIN_*) ─────────────────────────────────────────

pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_HANDLE: u16 = 2;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_TYPE: u16 = 7;
pub const NFTA_CHAIN_FLAGS: u16 = 9;

// ── Hook attributes (NFTA_HOOK_*) ───────────────────────────────────────────

pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;

// ── Netfilter hook numbers (NF_INET_*) ──────────────────────────────────────

pub const NF_INET_PRE_ROUTING: u32 = 0;
pub const NF_INET_LOCAL_IN: u32 = 1;
pub const NF_INET_FORWARD: u32 = 2;
pub const NF_INET_LOCAL_OUT: u32 = 3;
pub const NF_INET_POST_ROUTING: u32 = 4;

// ── Rule attributes (NFTA_RULE_*) ───────────────────────────────────────────

pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_HANDLE: u16 = 3;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_RULE_USERDATA: u16 = 6;
pub const NFTA_RULE_ID: u16 = 8;
pub const NFTA_RULE_POSITION: u16 = 7;

// ── List element (NFTA_LIST_ELEM) ───────────────────────────────────────────

pub const NFTA_LIST_ELEM: u16 = 1;

// ── Expression attributes (NFTA_EXPR_*) ─────────────────────────────────────

pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

// ── Payload expression attributes (NFTA_PAYLOAD_*) ──────────────────────────

pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;

// Payload bases.
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

// ── Meta expression attributes (NFTA_META_*) ────────────────────────────────

pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;
pub const NFTA_META_SREG: u16 = 3;

// Meta keys.
pub const NFT_META_L4PROTO: u32 = 15;

// ── Cmp expression attributes (NFTA_CMP_*) ──────────────────────────────────

pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;

// Cmp ops.
pub const NFT_CMP_EQ: u32 = 0;

// ── Data / immediate attributes (NFTA_DATA_*, NFTA_IMMEDIATE_*) ─────────────

pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;
pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

// ── Verdict attributes (NFTA_VERDICT_*) ─────────────────────────────────────

pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;

// ── Verdict codes ────────────────────────────────────────────────────────────
// Standard netfilter verdicts.
pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;
// nftables-specific continuation verdicts (stored as i32 in the kernel,
// but the wire value fits in u32 for matching purposes).
pub const NFT_CONTINUE: u32 = 0xFFFF_FFFF; // -1 as u32
pub const NFT_BREAK: u32 = 0xFFFF_FFFE;    // -2 as u32
pub const NFT_JUMP: u32 = 0xFFFF_FFFD;     // -3 as u32
pub const NFT_GOTO: u32 = 0xFFFF_FFFC;     // -4 as u32
pub const NFT_RETURN: u32 = 0xFFFF_FFFB;   // -5 as u32

// ── Register numbers ─────────────────────────────────────────────────────────

pub const NFT_REG_VERDICT: u32 = 0;
pub const NFT_REG_1: u32 = 1;
pub const NFT_REG_2: u32 = 2;
pub const NFT_REG_3: u32 = 3;
pub const NFT_REG_4: u32 = 4;
// 32-bit registers start at offset 8 from the 128-bit register base.
pub const NFT_REG32_00: u32 = 8;
pub const NFT_REG32_01: u32 = 9;
pub const NFT_REG32_02: u32 = 10;
pub const NFT_REG32_03: u32 = 11;

// ── Nfattr bit masks ─────────────────────────────────────────────────────────

/// Strip the nested / network-byte-order flag bits from nfa_type.
pub const NFA_TYPE_MASK: u16 = 0x7FFF;
pub const NFA_F_NESTED: u16 = 0x8000;
