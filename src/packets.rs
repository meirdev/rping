use std::net::Ipv4Addr;

use rand::{Rng, seq::IndexedRandom};

use crate::args::{ArgIp, ArgPort, Ip, Protocol};

fn random_public_ip(rng: &mut rand::prelude::ThreadRng) -> Ipv4Addr {
    loop {
        let ip: Ipv4Addr = rng.random_range(0..=0xFFFFFFFF).into();

        if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() {
            return ip;
        }
    }
}

fn random_ip(mut rng: &mut rand::prelude::ThreadRng, arg: &Vec<ArgIp>) -> Ipv4Addr {
    if let Some(element) = arg.choose(&mut rng) {
        match element {
            ArgIp::Address(addr) => *addr,
            ArgIp::Network(network) => {
                let start = network.network();
                let end = network.broadcast();

                let ip_num: u32 = rng.random_range(start.into()..=end.into());

                Ipv4Addr::from(ip_num)
            }
        }
    } else {
        random_public_ip(&mut rng)
    }
}

fn random_port(rng: &mut rand::prelude::ThreadRng, arg: &Option<ArgPort>) -> u16 {
    match arg {
        Some(ArgPort::Single(port)) => *port,
        Some(ArgPort::Range(range)) => {
            let start = *range.start();
            let end = *range.end();
            rng.random_range(start..=end)
        }
        None => rng.random_range(0..=65535),
    }
}

pub fn build_ipv4_packet(protocol: Protocol) -> Result<(), String> {
    match protocol {
        Protocol::Tcp {
            ip,
            dst_port,
            src_port,
            fin,
            syn,
            rst,
            psh,
            ack,
            urg,
            xmas,
            ymas,
            window,
            seq,
            ack_seq,
        } => {
            let mut rng: rand::prelude::ThreadRng = rand::rng();

            let src_ip = ip
                .src_ip
                .as_ref()
                .map(|ips| random_ip(&mut rng, ips))
                .unwrap_or_else(|| random_public_ip(&mut rng));

            let dst_ip = ip
                .dst_ip
                .as_ref()
                .map(|ips| random_ip(&mut rng, ips))
                .unwrap_or_else(|| random_public_ip(&mut rng));

            println!("Source IP: {}", src_ip);
            println!("Destination IP: {}", dst_ip);

            return Ok(());
        }
        Protocol::Udp {
            ip,
            dst_port,
            src_port,
        } => return Ok(()),
    }
}
