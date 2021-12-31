use pkg_config;

fn main() {
    pkg_config::Config::new().probe("libpcap").unwrap();
    println!("cargo-rerun-if-changed=build.rs");
}
