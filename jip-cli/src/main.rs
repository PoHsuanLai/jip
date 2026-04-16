#[cfg(not(target_os = "linux"))]
compile_error!("jip currently supports Linux only");

fn main() -> anyhow::Result<()> {
    println!("jip: not yet implemented");
    Ok(())
}
