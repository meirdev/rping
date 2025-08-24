use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use clap::Parser;
use log::debug;
use pnet::datalink;
use rping::cli::Cli;
use rping::packet::build_ipv4_packet;

fn main() {
    env_logger::init();

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

    debug!("Options: {:?}", args);

    println!("Using interface: {}", interface.name);

    let packets = Arc::new(AtomicU64::new(0));
    let packets_clone = packets.clone();

    ctrlc::set_handler(move || {
        println!("{} packets sent", packets_clone.load(Ordering::SeqCst));
        std::process::exit(0);
    })
    .unwrap();

    build_ipv4_packet(args, &packets);
}
