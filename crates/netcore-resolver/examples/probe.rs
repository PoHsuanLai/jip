//! `cargo run -p netcore-resolver --example probe -- github.com`
use netcore::connection::ConnectionId;
use netcore::traits::Resolver;
use netcore_resolver::ResolverBackend;

fn main() {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "github.com".into());
    let b = ResolverBackend::new();
    println!("stub = {:?}", b.stub_server());
    let r = b.resolve(&name).expect("resolve");
    println!(
        "resolve {name}: via={:?} upstream={:?} took={:?}",
        r.via, r.upstream_used, r.took
    );
    for a in &r.answers {
        println!("  {} ({:?})", a.ip, a.family);
    }
    if let Some(e) = &r.error {
        println!("  error: {:?}", e);
    }
    for link in ["eth0", "wlan0", "lo"] {
        let s = b.servers_for(&ConnectionId(link.into())).ok();
        println!("servers_for({link}) = {:?}", s);
    }
}
