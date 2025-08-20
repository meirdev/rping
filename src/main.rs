use std::thread;

use clap::Parser;
use pnet::datalink;
use rping::{args::Cli, packets::build_ipv4_packet};

fn main() {
    let args = Cli::parse();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == args.inteface)
        .next()
        .or_else(|| {
            eprintln!("Interface {} not found", args.inteface);
            std::process::exit(1);
        })
        .unwrap();

    println!("Using interface: {}", interface.name);

    let mut threads = Vec::new();

    for _ in 0..10 {
        println!("Building packet...");
        let args2 = args.clone();
        let t = thread::spawn(move || {
            build_ipv4_packet(args2).unwrap_or_else(|err| {
                eprintln!("Error building packet: {}", err);
                std::process::exit(1);
            })
        });

        threads.push(t);
    }

    for t in threads {
        if let Err(e) = t.join() {
            eprintln!("Thread panicked: {:?}", e);
        }
    }
}
