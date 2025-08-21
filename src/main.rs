use std::thread;

use clap::Parser;
use pnet::datalink;
use rping::{cli::Cli, packet::build_ipv4_packet};

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

    println!("Options: {:?}", args);

    println!("Using interface: {}", interface.name);

    if let Some(num_threads) = args.threads {
        println!("Using {} threads", num_threads);

        let mut threads = Vec::new();

        for _ in 0..num_threads {
            let args_clone = args.clone();
            let t = thread::spawn(move || {
                build_ipv4_packet(args_clone);
            });
            threads.push(t);
        }

        threads.into_iter().for_each(|t| {
            if let Err(e) = t.join() {
                eprintln!("Thread panicked: {:?}", e);
            }
        });
    } else {
        build_ipv4_packet(args);
    }
}
