/// An nftables chain.
#[derive(Debug, Clone)]
pub struct NftChain {
    pub table: String,
    pub name: String,
    /// `None` for non-base chains.
    pub hook: Option<NftHook>,
    pub priority: Option<i32>,
    pub policy: ChainPolicy,
    pub handle: u64,
}

/// Which netfilter hook a base chain is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftHook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    /// Any other hook number (e.g. netdev ingress).
    Other(u32),
}

impl NftHook {
    pub fn from_hooknum(n: u32) -> Self {
        match n {
            crate::constants::NF_INET_PRE_ROUTING => Self::Prerouting,
            crate::constants::NF_INET_LOCAL_IN => Self::Input,
            crate::constants::NF_INET_FORWARD => Self::Forward,
            crate::constants::NF_INET_LOCAL_OUT => Self::Output,
            crate::constants::NF_INET_POST_ROUTING => Self::Postrouting,
            other => Self::Other(other),
        }
    }
}

/// Default policy when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainPolicy {
    Accept,
    Drop,
}

impl Default for ChainPolicy {
    fn default() -> Self {
        Self::Accept
    }
}
