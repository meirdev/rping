use std::thread;

use log::debug;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::udp::MutableUdpPacket;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::transport_channel;
use rand::{Rng, seq::IndexedRandom};

use crate::checksum::{tcp_ipv4_checksum, udp_ipv4_checksum};
use crate::cli::Cli;
use crate::ip::Ip;
use crate::random::{random_ipv4, random_public_ipv4};
use crate::range::Range;

const MAX_PACKET_SIZE: u16 = u16::MAX;

const IP_HEADER_SIZE: u16 = 20;
const TCP_HEADER_SIZE: u16 = 20;
const UDP_HEADER_SIZE: u16 = 8;

pub fn build_ipv4_packet(cli: Cli) {
    let proto = if cli.tcp {
        IpNextHeaderProtocols::Tcp
    } else if cli.udp {
        IpNextHeaderProtocols::Udp
    } else if let Some(proto) = cli.proto {
        IpNextHeaderProtocol(proto)
    } else {
        eprintln!("No protocol specified. Use --tcp, --udp, or --proto.");
        std::process::exit(1);
    };

    let header_size = match proto {
        IpNextHeaderProtocols::Tcp => IP_HEADER_SIZE + TCP_HEADER_SIZE,
        IpNextHeaderProtocols::Udp => IP_HEADER_SIZE + UDP_HEADER_SIZE,
        _ => IP_HEADER_SIZE,
    };

    let mut rng: rand::prelude::ThreadRng = rand::rng();

    let mut packet = [0u8; MAX_PACKET_SIZE as usize];

    let mut count = 0;

    match transport_channel(0, Layer3(proto)) {
        Ok((mut tx, _)) => loop {
            let data_size = match cli.data {
                Some(Range::Single(value)) => value,
                Some(Range::Range(ref range)) => rng.random_range(range.clone()),
                None => 0,
            };

            let src_ip = cli
                .src_ip
                .as_ref()
                .map(|ips| {
                    ips.choose(&mut rng)
                        .map(|net| match net {
                            Ip::Address(addr) => addr.clone(),
                            Ip::Network(net) => random_ipv4(&mut rng, net),
                        })
                        .unwrap()
                })
                .unwrap_or_else(|| random_public_ipv4(&mut rng));

            let dst_ip = cli
                .dst_ip
                .as_ref()
                .map(|ips| {
                    ips.choose(&mut rng)
                        .map(|net| match net {
                            Ip::Address(addr) => addr.clone(),
                            Ip::Network(net) => random_ipv4(&mut rng, net),
                        })
                        .unwrap()
                })
                .unwrap_or_else(|| random_public_ipv4(&mut rng));

            {
                let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
                ip_header.set_next_level_protocol(proto);
                ip_header.set_source(src_ip);
                ip_header.set_destination(dst_ip);
                ip_header.set_version(4);
                ip_header.set_header_length(5);
                ip_header.set_total_length(header_size + data_size as u16);

                if let Some(id) = cli.id {
                    ip_header.set_identification(id);
                } else {
                    ip_header.set_identification(rng.random());
                }

                ip_header.set_identification(rng.random());
                ip_header.set_ttl(cli.ttl);
            }

            packet.split_at_mut(header_size as usize).1.fill('X' as u8);

            if proto == IpNextHeaderProtocols::Tcp || proto == IpNextHeaderProtocols::Udp {
                let src_port = cli
                    .src_port
                    .as_ref()
                    .map(|ports| {
                        ports
                            .choose(&mut rng)
                            .map(|port| match port {
                                Range::Single(value) => *value,
                                Range::Range(range) => rng.random_range(range.clone()),
                            })
                            .unwrap()
                    })
                    .unwrap_or_else(|| rng.random());

                let dst_port = cli
                    .dst_port
                    .as_ref()
                    .map(|ports| {
                        ports
                            .choose(&mut rng)
                            .map(|port| match port {
                                Range::Single(value) => *value,
                                Range::Range(range) => rng.random_range(range.clone()),
                            })
                            .unwrap()
                    })
                    .unwrap_or_else(|| rng.random());

                if proto == IpNextHeaderProtocols::Tcp {
                    let mut tcp_header =
                        MutableTcpPacket::new(&mut packet[IP_HEADER_SIZE as usize..]).unwrap();

                    tcp_header.set_source(src_port);
                    tcp_header.set_destination(dst_port);

                    if let Some(ack_seq) = cli.ack_seq {
                        tcp_header.set_acknowledgement(ack_seq);
                    } else {
                        tcp_header.set_acknowledgement(rng.random());
                    }

                    if let Some(seq) = cli.seq {
                        tcp_header.set_sequence(seq);
                    } else {
                        tcp_header.set_sequence(rng.random());
                    }

                    let mut flags = 0u8;
                    if cli.fin {
                        flags |= TcpFlags::FIN;
                    }
                    if cli.psh {
                        flags |= TcpFlags::PSH;
                    }
                    if cli.ack {
                        flags |= TcpFlags::ACK;
                    }
                    if cli.rst {
                        flags |= TcpFlags::RST;
                    }
                    if cli.syn {
                        flags |= TcpFlags::SYN;
                    }
                    if cli.urg {
                        flags |= TcpFlags::URG;
                    }
                    if cli.xmas {
                        flags |= TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;
                    }
                    if cli.ymas {
                        flags |= TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG | TcpFlags::ACK;
                    }

                    tcp_header.set_flags(flags);
                    tcp_header.set_window(cli.window);
                    tcp_header.set_data_offset(5);

                    tcp_header.set_checksum(0);

                    let checksum = tcp_ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
                    tcp_header.set_checksum(checksum);
                } else if proto == IpNextHeaderProtocols::Udp {
                    let mut udp_header =
                        MutableUdpPacket::new(&mut packet[IP_HEADER_SIZE as usize..]).unwrap();

                    udp_header.set_source(src_port);
                    udp_header.set_destination(dst_port);

                    udp_header.set_length(UDP_HEADER_SIZE + data_size as u16);

                    udp_header.set_checksum(0);

                    let checksum = udp_ipv4_checksum(&udp_header.to_immutable(), &src_ip, &dst_ip);
                    udp_header.set_checksum(checksum);
                }
            }

            let mut tmp_packet = packet
                .split_at_mut(data_size as usize + header_size as usize)
                .0;

            let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet).unwrap();
            let checksum = checksum(&ip_header.to_immutable());
            ip_header.set_checksum(checksum);

            debug!("{:#?}", ip_header);

            tx.send_to(&ip_header, std::net::IpAddr::V4(dst_ip))
                .expect("Failed to send packet");

            if cli.flood {
                continue;
            }

            if let Some(cli_cont) = cli.count {
                count += 1;
                if count >= cli_cont {
                    break;
                }
            }

            thread::sleep(cli.interval);
        },
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    }
}
