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

    build_ipv4_packet(args)
        .unwrap_or_else(|err| {
            eprintln!("Error building packet: {}", err);
            std::process::exit(1);
        });
}
