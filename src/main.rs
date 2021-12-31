use std::env;

/// Agents are functions that make decisions and are run by the main function.
mod agents;
/// Control interfaces manipulate data in order to abstract away details.
mod control_interfaces;
/// Auto-generated Bindings for the pcap library.
mod pcap_c;
/// Protocol impementations.
mod protocols;
/// Some utility functions.
mod utils;

use serde_json;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: <filename> <agent> [args]");
        return;
    }

    // The method runs some agent, and stops it's execution once ctrl-C is pressed.
    tokio::select! {
    biased;
    _ = handle_args(args) => {},
    _ = tokio::signal::ctrl_c() => {}
    }

    println!("Cleaning up...")
}

async fn handle_args(args: Vec<String>) {
    match args[1].as_str() {
        // A TCP-over-ICMP tunnel.
        "icmp-tcp" => {
            if args.len() < 5 {
                eprintln!(
            "Usage: <filename> icmp-tcp <tunnel_interface> <local_interface> <configuration_file.json>"
		);
                return;
            }

            let f = match File::open(Path::new(args[4].as_str())) {
                Ok(t) => t,
                Err(_) => {
                    eprintln!("Could not open configuration file!");
                    return;
                }
            };

            let reader = BufReader::new(f);
            let tun: control_interfaces::tunnels::icmp_tcp::Tunnel =
                match serde_json::from_reader(reader) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Could not parse configuration file: {}", e);
                        return;
                    }
                };

            let proxy_runner = match tun.open_with(args[2].as_str(), args[3].as_str()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Could not open interfaces: {:?}", e);
                    return;
                }
            };

            proxy_runner.await;
        }
        // A packet sniffer.
        "sniff" => {
            if args.len() < 3 {
                eprintln!("Usage: <filename> sniff <interface> {{<bpf-filter>}}")
            }

            let mut handle = match control_interfaces::pcap::CaptureHandle::open_live(
                args[2].as_str(),
                control_interfaces::pcap::CaptureMode::Promisc,
                100,
                65535,
            ) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Could not open interface: {}", e);
                    return;
                }
            };

            if args.len() >= 4 {
                match handle.with_filter(args[3].as_str(), None) {
                    Ok(_) => {}
                    Err(control_interfaces::pcap::FilterErr::CouldNotApply) => {
                        eprintln!("Could not apply filter!");
                        return;
                    }
                    Err(control_interfaces::pcap::FilterErr::InvalidFilter) => {
                        eprintln!("Incorrect filter syntax!");
                        return;
                    }
                }
            }

            let dumper = agents::dumper::Agent::new(tokio_stream::StreamExt::filter_map(
                handle,
                |x| match x {
                    Err(_) => None,
                    Ok(p) => Some(control_interfaces::pcap::PrintableDataOwned {
                        style: control_interfaces::pcap::PrintStyle::Normal,
                        data: p.1,
                    }),
                },
            ))
            .run();

            dumper.await;
        }
        // These are the only agents currently supported.
        x => {
            eprintln!("Invalid agent type {}", x);
            return;
        }
    }
}
