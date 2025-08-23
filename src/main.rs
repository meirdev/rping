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

    build_ipv4_packet(args);
}
