//! `aether-toolbus`: the policy, budget and audit layer between the model and its tools.

#[cfg(unix)]
fn main() {
    std::process::exit(aether_toolbus::app::run(std::env::args().skip(1).collect()));
}

#[cfg(not(unix))]
fn main() {
    eprintln!("aether-toolbus needs a Unix platform (Unix domain sockets). On Windows, run it inside WSL2.");
    std::process::exit(2);
}
