//! Firewall backend: nftables via native `NETLINK_NETFILTER`.
//!
//! **Why netlink?** Direct kernel communication avoids forking `nft` and the
//! `serde_json` parse round-trip. The `nftables-netlink` crate in this
//! workspace implements the wire protocol from scratch using `netlink-sys`.
//!
//! **Privilege model.** Reading the nftables ruleset via netlink does not
//! require `CAP_NET_ADMIN` on Linux 5.2+. On older kernels or when the
//! capability is missing, [`NftBackend::backend`] returns
//! [`FirewallBackend::Unknown`] and every verdict is `Unknown`.
//!
//! **Scope.** We only inspect chains hooked at `input`. Output and forward
//! don't affect inbound exposure. We match against `tcp dport` and
//! `udp dport` — simple numeric matches resolved from the kernel's register
//! model. Sets, maps, and conntrack rules are recognised but not evaluated;
//! they appear as `Expr::Named` and are skipped.

use nftables_netlink::{
    ChainPolicy, Expr, NftChain, NftHook, NftNetlinkHandle, NftRule, RuleVerdict as NlVerdict,
};

use netcore::diag::{FirewallBackend, FirewallVerdict};
use netcore::link::L4Proto;
use netcore::traits::Firewall;
use netcore::{Error, Result};

/// nftables firewall reader. Built once; the ruleset is cached per instance.
pub struct NftBackend {
    state: State,
}

enum State {
    Ready(Ruleset),
    Unavailable,
}

struct Ruleset {
    input_chains: Vec<InputChain>,
}

struct InputChain {
    name: String,
    policy: ChainPolicy,
    rules: Vec<Rule>,
}

struct Rule {
    port_match: Option<(L4Proto, u16)>,
    verdict: RuleVerdict,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuleVerdict {
    Accept,
    Drop,
    Reject,
    Other,
}

impl NftBackend {
    pub fn new() -> Self {
        let state = match load_ruleset() {
            Ok(r) => State::Ready(r),
            Err(_) => State::Unavailable,
        };
        Self { state }
    }
}

impl Default for NftBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Firewall for NftBackend {
    fn verdict_for_inbound(&self, port: u16, proto: L4Proto) -> Result<FirewallVerdict> {
        let ruleset = match &self.state {
            State::Unavailable => return Ok(FirewallVerdict::Unknown),
            State::Ready(r) => r,
        };
        if ruleset.input_chains.is_empty() {
            return Ok(FirewallVerdict::Allow);
        }
        let mut saw_drop = false;
        let mut saw_reject = false;
        for chain in &ruleset.input_chains {
            match evaluate_chain(chain, port, proto) {
                RuleVerdict::Accept => continue,
                RuleVerdict::Drop => saw_drop = true,
                RuleVerdict::Reject => saw_reject = true,
                RuleVerdict::Other => continue,
            }
        }
        Ok(if saw_reject {
            FirewallVerdict::Reject
        } else if saw_drop {
            FirewallVerdict::Drop
        } else {
            FirewallVerdict::Allow
        })
    }

    fn backend(&self) -> FirewallBackend {
        match self.state {
            State::Ready(_) => FirewallBackend::Nftables,
            State::Unavailable => FirewallBackend::Unknown,
        }
    }
}

fn evaluate_chain(chain: &InputChain, port: u16, proto: L4Proto) -> RuleVerdict {
    for rule in &chain.rules {
        let matches = match rule.port_match {
            None => true,
            Some((p, n)) => p == proto && n == port,
        };
        if !matches {
            continue;
        }
        match rule.verdict {
            RuleVerdict::Accept | RuleVerdict::Drop | RuleVerdict::Reject => return rule.verdict,
            RuleVerdict::Other => continue,
        }
    }
    match chain.policy {
        ChainPolicy::Accept => RuleVerdict::Accept,
        ChainPolicy::Drop => RuleVerdict::Drop,
    }
}

fn load_ruleset() -> Result<Ruleset> {
    let handle = NftNetlinkHandle::open().map_err(|e| Error::Backend(e.to_string()))?;
    let nl_chains = handle
        .dump_chains()
        .map_err(|e| Error::Backend(e.to_string()))?;
    let nl_rules = handle
        .dump_rules()
        .map_err(|e| Error::Backend(e.to_string()))?;
    Ok(ruleset_from_netlink(nl_chains, nl_rules))
}

fn ruleset_from_netlink(nl_chains: Vec<NftChain>, nl_rules: Vec<NftRule>) -> Ruleset {
    let mut input_chains: Vec<InputChain> = nl_chains
        .into_iter()
        .filter(|c| c.hook == Some(NftHook::Input))
        .map(|c| InputChain {
            name: c.name.clone(),
            policy: c.policy,
            rules: Vec::new(),
        })
        .collect();

    for rule in nl_rules {
        let Some(chain) = input_chains.iter_mut().find(|c| c.name == rule.chain) else {
            continue;
        };
        if let Some(r) = rule_from_exprs(&rule.exprs) {
            chain.rules.push(r);
        }
    }

    Ruleset { input_chains }
}

fn rule_from_exprs(exprs: &[Expr]) -> Option<Rule> {
    let mut port_match: Option<(L4Proto, u16)> = None;
    let mut verdict = RuleVerdict::Other;

    for expr in exprs {
        match expr {
            Expr::PortMatch(pm) => port_match = Some((pm.proto, pm.port)),
            Expr::Verdict(v) => {
                verdict = match v {
                    NlVerdict::Accept => RuleVerdict::Accept,
                    NlVerdict::Drop => RuleVerdict::Drop,
                    NlVerdict::Reject => RuleVerdict::Reject,
                    _ => RuleVerdict::Other,
                };
            }
            Expr::Named(n) if n == "reject" => verdict = RuleVerdict::Reject,
            _ => {}
        }
    }
    Some(Rule {
        port_match,
        verdict,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nftables_netlink::{Expr, NftChain, NftHook, NftRule, PortMatch, RuleVerdict as NlVerdict};

    fn make_chain(name: &str, policy: ChainPolicy) -> NftChain {
        NftChain {
            table: "filter".into(),
            name: name.into(),
            hook: Some(NftHook::Input),
            priority: Some(0),
            policy,
            handle: 1,
        }
    }

    fn make_rule(chain: &str, port_match: Option<(L4Proto, u16)>, verdict: NlVerdict) -> NftRule {
        let mut exprs: Vec<Expr> = Vec::new();
        if let Some((proto, port)) = port_match {
            exprs.push(Expr::PortMatch(PortMatch { proto, port }));
        }
        exprs.push(Expr::Verdict(verdict));
        NftRule {
            table: "filter".into(),
            chain: chain.into(),
            handle: 1,
            exprs,
        }
    }

    fn backend_from_netlink(chains: Vec<NftChain>, rules: Vec<NftRule>) -> NftBackend {
        let ruleset = ruleset_from_netlink(chains, rules);
        NftBackend {
            state: State::Ready(ruleset),
        }
    }

    fn sample_backend() -> NftBackend {
        // Mirrors the old SAMPLE JSON: input policy=drop, TCP 22+80 accept, UDP 53 reject.
        let chains = vec![
            make_chain("input", ChainPolicy::Drop),
            NftChain {
                table: "filter".into(),
                name: "forward".into(),
                hook: Some(NftHook::Forward),
                priority: Some(0),
                policy: ChainPolicy::Accept,
                handle: 2,
            },
        ];
        let rules = vec![
            make_rule("input", Some((L4Proto::Tcp, 22)), NlVerdict::Accept),
            make_rule("input", Some((L4Proto::Tcp, 80)), NlVerdict::Accept),
            make_rule("input", Some((L4Proto::Udp, 53)), NlVerdict::Reject),
        ];
        backend_from_netlink(chains, rules)
    }

    #[test]
    fn accepted_ports_return_allow() {
        let b = sample_backend();
        assert_eq!(
            b.verdict_for_inbound(22, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Allow
        );
        assert_eq!(
            b.verdict_for_inbound(80, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Allow
        );
    }

    #[test]
    fn unlisted_port_falls_back_to_chain_policy() {
        let b = sample_backend();
        assert_eq!(
            b.verdict_for_inbound(8080, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Drop
        );
    }

    #[test]
    fn reject_is_distinct_from_drop() {
        let b = sample_backend();
        assert_eq!(
            b.verdict_for_inbound(53, L4Proto::Udp).unwrap(),
            FirewallVerdict::Reject
        );
    }

    #[test]
    fn no_input_chain_means_allow() {
        let chains = vec![NftChain {
            table: "filter".into(),
            name: "forward".into(),
            hook: Some(NftHook::Forward),
            priority: Some(0),
            policy: ChainPolicy::Accept,
            handle: 1,
        }];
        let b = backend_from_netlink(chains, vec![]);
        assert_eq!(
            b.verdict_for_inbound(22, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Allow
        );
    }

    #[test]
    fn unavailable_backend_returns_unknown() {
        let b = NftBackend {
            state: State::Unavailable,
        };
        assert_eq!(b.backend(), FirewallBackend::Unknown);
        assert_eq!(
            b.verdict_for_inbound(22, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Unknown
        );
    }

    #[test]
    fn blanket_rule_without_port_match() {
        // A rule with no port match acts as a blanket verdict.
        let chains = vec![make_chain("input", ChainPolicy::Accept)];
        let rules = vec![make_rule("input", None, NlVerdict::Drop)];
        let b = backend_from_netlink(chains, rules);
        // Blanket drop rule fires for any port.
        assert_eq!(
            b.verdict_for_inbound(443, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Drop
        );
    }
}
