//! Firewall backend: nftables via `nft -j list ruleset`.
//!
//! **Why shell out?** There's no maintained Rust crate for nftables netlink
//! with JSON-equivalent parsing. `nft` itself builds the ruleset graph in
//! userspace and its JSON output is the documented stable API for tools
//! (see `libnftables-json(5)`). For a read-only CLI this is the simplest
//! correct path.
//!
//! **Privilege model.** `nft list ruleset` is root-only. When we can't
//! read it (non-root, binary missing, stale kernel), [`NftBackend::backend`]
//! returns [`FirewallBackend::Unknown`] and every verdict is `Unknown` —
//! which matches the existing "we don't know" state on every [`Service`].
//!
//! **Scope.** We only inspect chains hooked at `input`. Output and forward
//! don't affect inbound exposure. We match against `tcp dport` and
//! `udp dport` — simple numeric matches, no sets yet. A service bound to
//! an interface with policy=drop and no matching accept rule correctly
//! comes back as [`FirewallVerdict::Drop`].
//!
//! [`Service`]: netcore::service::Service

use std::process::Command;

use serde::Deserialize;

use netcore::diag::{FirewallBackend, FirewallVerdict};
use netcore::link::L4Proto;
use netcore::traits::Firewall;
use netcore::{Error, Result};

/// nftables firewall reader. Built once; the ruleset is cached per instance
/// on first call so repeated `verdict_for_inbound` lookups across many
/// services don't each fork `nft`.
pub struct NftBackend {
    state: State,
}

enum State {
    /// `nft` ran and we parsed its ruleset.
    Ready(Ruleset),
    /// `nft` refused (EPERM) or isn't installed. Every verdict is Unknown.
    Unavailable,
}

struct Ruleset {
    /// Input chains with their policy + ordered rule list.
    input_chains: Vec<InputChain>,
}

struct InputChain {
    _name: String,
    policy: ChainPolicy,
    rules: Vec<Rule>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainPolicy {
    Accept,
    Drop,
}

struct Rule {
    /// If `Some`, this rule only fires when `(proto, port)` matches.
    port_match: Option<(L4Proto, u16)>,
    verdict: RuleVerdict,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuleVerdict {
    Accept,
    Drop,
    Reject,
    /// Rule has no terminal verdict on this path (jump, counter-only, ...).
    /// We ignore these for inbound exposure purposes.
    Other,
}

impl NftBackend {
    /// Load the nftables ruleset. If `nft` is unavailable or returns an error,
    /// the backend starts in the `Unavailable` state and every verdict is
    /// `Unknown`.
    pub fn new() -> Self {
        let state = match load_ruleset() {
            Ok(r) => State::Ready(r),
            Err(_) => State::Unavailable,
        };
        Self { state }
    }
}

impl Default for NftBackend {
    fn default() -> Self { Self::new() }
}

impl Firewall for NftBackend {
    fn verdict_for_inbound(&self, port: u16, proto: L4Proto) -> Result<FirewallVerdict> {
        let ruleset = match &self.state {
            State::Unavailable => return Ok(FirewallVerdict::Unknown),
            State::Ready(r) => r,
        };
        if ruleset.input_chains.is_empty() {
            // No input hooks at all → kernel default is accept.
            return Ok(FirewallVerdict::Allow);
        }
        // A packet traverses *every* input-hooked chain, and the first
        // matching terminal verdict wins per chain. If any chain drops/
        // rejects, the packet is blocked. If all chains accept (or fall
        // through to an accept policy), the packet is allowed.
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

/// Walk a single chain looking for a terminal verdict for this (port, proto).
/// Rules with no port match act as blanket accept/drop on that chain.
fn evaluate_chain(chain: &InputChain, port: u16, proto: L4Proto) -> RuleVerdict {
    for rule in &chain.rules {
        let matches = match rule.port_match {
            None => true, // blanket rule
            Some((p, n)) => p == proto && n == port,
        };
        if !matches { continue; }
        match rule.verdict {
            RuleVerdict::Accept | RuleVerdict::Drop | RuleVerdict::Reject => return rule.verdict,
            RuleVerdict::Other => continue,
        }
    }
    // No rule fired; fall through to chain policy.
    match chain.policy {
        ChainPolicy::Accept => RuleVerdict::Accept,
        ChainPolicy::Drop => RuleVerdict::Drop,
    }
}

fn load_ruleset() -> Result<Ruleset> {
    let out = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|e| Error::Backend(format!("nft spawn: {e}")))?;
    if !out.status.success() {
        return Err(Error::Backend(format!(
            "nft list ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    parse_ruleset(&out.stdout)
}

fn parse_ruleset(bytes: &[u8]) -> Result<Ruleset> {
    let wire: NftWire = serde_json::from_slice(bytes)
        .map_err(|e| Error::Backend(format!("nft json: {e}")))?;

    // First pass: collect input-hooked chains. Second pass: attach rules.
    // Each array element is a single-key object like {"chain":{...}} or
    // {"rule":{...}}; metainfo/table/set/map are ignored.
    let mut chains: Vec<InputChain> = Vec::new();
    for obj in &wire.nftables {
        if let Some(c) = obj.get("chain") {
            if c.get("hook").and_then(|h| h.as_str()) != Some("input") { continue; }
            let Some(name) = c.get("name").and_then(|n| n.as_str()) else { continue };
            let policy = match c.get("policy").and_then(|p| p.as_str()) {
                Some("drop") => ChainPolicy::Drop,
                // Kernel default when policy is unset is accept.
                _ => ChainPolicy::Accept,
            };
            chains.push(InputChain {
                _name: name.to_string(),
                policy,
                rules: Vec::new(),
            });
        }
    }
    for obj in &wire.nftables {
        if let Some(r) = obj.get("rule") {
            let Some(chain_name) = r.get("chain").and_then(|c| c.as_str()) else { continue };
            let Some(expr) = r.get("expr").and_then(|e| e.as_array()) else { continue };
            if let Some(chain) = chains.iter_mut().find(|c| c._name == chain_name) {
                if let Some(rule) = rule_from_expr(expr) {
                    chain.rules.push(rule);
                }
            }
        }
    }
    Ok(Ruleset { input_chains: chains })
}

fn rule_from_expr(exprs: &[serde_json::Value]) -> Option<Rule> {
    // An expr is a one-key JSON object: "match", "accept", "drop",
    // "reject", "counter", "jump", etc. We only care about port matches
    // and terminal verdicts; everything else is passed over.
    let mut port_match: Option<(L4Proto, u16)> = None;
    let mut verdict = RuleVerdict::Other;
    for expr in exprs {
        let Some(obj) = expr.as_object() else { continue };
        let Some((key, val)) = obj.iter().next() else { continue };
        match key.as_str() {
            "match" => {
                if let Some(pm) = port_match_from(val) {
                    port_match = Some(pm);
                }
            }
            "accept" => verdict = RuleVerdict::Accept,
            "drop" => verdict = RuleVerdict::Drop,
            "reject" => verdict = RuleVerdict::Reject,
            _ => {}
        }
    }
    Some(Rule { port_match, verdict })
}

fn port_match_from(m: &serde_json::Value) -> Option<(L4Proto, u16)> {
    // {"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22,"op":"=="}
    let payload = m.get("left")?.get("payload")?;
    if payload.get("field")?.as_str()? != "dport" { return None; }
    let proto = match payload.get("protocol")?.as_str()? {
        "tcp" => L4Proto::Tcp,
        "udp" => L4Proto::Udp,
        _ => return None,
    };
    let port = u16::try_from(m.get("right")?.as_u64()?).ok()?;
    Some((proto, port))
}

// --- nft -j list ruleset wire types ----------------------------------
// Minimal: everything we don't model becomes `NftItem::Other` / `Expr::Other`
// so unknown features don't make parsing fail.

#[derive(Deserialize)]
struct NftWire {
    nftables: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Output of `nft -j list ruleset` on a host where input default is drop,
    // but TCP 22 and TCP 80 are accepted, and UDP 53 is rejected.
    const SAMPLE: &str = r#"{
      "nftables":[
        {"metainfo":{"version":"1.0.2","release_name":"Lester Gooch","json_schema_version":1}},
        {"table":{"family":"inet","name":"filter","handle":1}},
        {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                  "type":"filter","hook":"input","prio":0,"policy":"drop"}},
        {"chain":{"family":"inet","table":"filter","name":"forward","handle":2,
                  "type":"filter","hook":"forward","prio":0}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":10,
                 "expr":[
                   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
                   {"accept":null}
                 ]}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":11,
                 "expr":[
                   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},
                   {"accept":null}
                 ]}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":12,
                 "expr":[
                   {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},
                   {"reject":{"type":"icmpx","expr":"admin-prohibited"}}
                 ]}}
      ]
    }"#;

    fn backend_from_json(s: &str) -> NftBackend {
        let ruleset = parse_ruleset(s.as_bytes()).expect("parse sample ruleset");
        NftBackend { state: State::Ready(ruleset) }
    }

    #[test]
    fn accepted_ports_return_allow() {
        let b = backend_from_json(SAMPLE);
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
        // policy=drop, no rule for tcp/8080 → Drop
        let b = backend_from_json(SAMPLE);
        assert_eq!(
            b.verdict_for_inbound(8080, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Drop
        );
    }

    #[test]
    fn reject_is_distinct_from_drop() {
        let b = backend_from_json(SAMPLE);
        assert_eq!(
            b.verdict_for_inbound(53, L4Proto::Udp).unwrap(),
            FirewallVerdict::Reject
        );
    }

    #[test]
    fn no_input_chain_means_allow() {
        // Only a forward chain exists. Kernel default for input is accept.
        let json = r#"{"nftables":[
            {"chain":{"family":"inet","table":"filter","name":"forward",
                      "hook":"forward","prio":0}}
        ]}"#;
        let b = backend_from_json(json);
        assert_eq!(
            b.verdict_for_inbound(22, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Allow
        );
    }

    #[test]
    fn unavailable_backend_returns_unknown() {
        let b = NftBackend { state: State::Unavailable };
        assert_eq!(b.backend(), FirewallBackend::Unknown);
        assert_eq!(
            b.verdict_for_inbound(22, L4Proto::Tcp).unwrap(),
            FirewallVerdict::Unknown
        );
    }
}

