use netcore_nm::NmBackend;

fn main() {
    match NmBackend::new() {
        None => println!("NetworkManager not on bus"),
        Some(b) => {
            let profiles = b.profiles_by_iface().unwrap();
            for (iface, p) in profiles {
                println!(
                    "{iface:<12} name={:<30} kind={:<20} autoconnect={}",
                    p.name, p.kind, p.autoconnect
                );
            }
        }
    }
}
