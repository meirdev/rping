use std::net::Ipv4Addr;

use pnet::transport::TransportChannelType::Layer3;
use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{MutableIpv4Packet, checksum},
        tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum},
    },
    transport::transport_channel,
};
use rand::{Rng, seq::IndexedRandom};

use crate::args::{ArgData, ArgIp, ArgPort, Cli};

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

fn random_port(mut rng: &mut rand::prelude::ThreadRng, arg: &Vec<ArgPort>) -> u16 {
    if let Some(element) = arg.choose(&mut rng) {
        match element {
            ArgPort::Single(port) => *port,
            ArgPort::Range(range) => {
                let start = *range.start();
                let end = *range.end();
                rng.random_range(start..=end)
            }
        }
    } else {
        rng.random_range(0..=65535)
    }
}

fn random_data_size(rng: &mut rand::prelude::ThreadRng, arg: &Option<ArgData>) -> u16 {
    match arg {
        Some(ArgData::Single(data_size)) => *data_size,
        Some(ArgData::Range(range)) => {
            let start = *range.start();
            let end = *range.end();
            rng.random_range(start..=end)
        }
        None => 0,
    }
}

pub fn build_ipv4_packet(c: Cli) -> Result<(), String> {
    let mut rng: rand::prelude::ThreadRng = rand::rng();
    let mut packet = [0u8; 1500];

    let (mut tx, mut rx) = match transport_channel(100, Layer3(IpNextHeaderProtocols::Tcp)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        let data_size = random_data_size(&mut rng, &c.data);

        let src_ip = c
            .src_ip
            .as_ref()
            .map(|ips| random_ip(&mut rng, ips))
            .unwrap_or_else(|| random_public_ip(&mut rng));

        let dst_ip = c
            .dst_ip
            .as_ref()
            .map(|ips| random_ip(&mut rng, ips))
            .unwrap_or_else(|| random_public_ip(&mut rng));

        if c.tcp {
            {
                let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
                ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ip_header.set_source(src_ip);
                ip_header.set_destination(dst_ip);
                ip_header.set_version(4);
                ip_header.set_header_length(20 as u8 / 4);
                ip_header.set_total_length(20 + 20 + data_size as u16);
                ip_header.set_identification(rng.random_range(0..=65535) as u16);
                ip_header.set_ttl(c.ttl);
            }

            for i in 0..data_size {
                packet[20 + 20 + i as usize] = 'X' as u8;
            }

            let src_port = c
                .src_port
                .as_ref()
                .map(|ports| random_port(&mut rng, ports))
                .unwrap_or_else(|| rng.random_range(0..=65535));

            let dst_port = c
                .src_port
                .as_ref()
                .map(|ports| random_port(&mut rng, ports))
                .unwrap_or_else(|| rng.random_range(0..=65535));

            {
                let mut tcp_header = MutableTcpPacket::new(&mut packet[20..]).unwrap();
                tcp_header.set_source(src_port);
                tcp_header.set_destination(dst_port);
                tcp_header.set_sequence(0x9037d2b8);
                tcp_header.set_acknowledgement(0x944bb276);

                let mut flags = 0u8;
                if c.fin {
                    flags |= TcpFlags::FIN;
                }
                if c.psh {
                    flags |= TcpFlags::PSH;
                }
                if c.ack {
                    flags |= TcpFlags::ACK;
                }
                if c.rst {
                    flags |= TcpFlags::RST;
                }
                if c.syn {
                    flags |= TcpFlags::SYN;
                }
                if c.urg {
                    flags |= TcpFlags::URG;
                }
                if c.xmas {
                    flags |= TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;
                }
                if c.ymas {
                    flags |= TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG | TcpFlags::ACK;
                }

                tcp_header.set_flags(flags);
                tcp_header.set_window(c.window);
                tcp_header.set_data_offset(5);

                let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
                tcp_header.set_checksum(checksum);
            }

            let mut p = packet.split_at_mut(data_size as usize + 20 + 20).0;

            let mut ip_header = MutableIpv4Packet::new(&mut p).unwrap();
            let checksum = checksum(&ip_header.to_immutable());
            ip_header.set_checksum(checksum);

            tx.send_to(&ip_header, std::net::IpAddr::V4(dst_ip))
                .expect("Failed to send packet");
        }
    }

    return Ok(());
}
