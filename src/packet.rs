use std::thread;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum};
use pnet::packet::udp::{MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum};
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::transport_channel;
use rand::{Rng, seq::IndexedRandom};

use crate::cli::Cli;
use crate::random::{random_ipv4, random_public_ipv4, random_value};

const MAX_PACKET_SIZE: u16 = u16::MAX;

const IP_HEADER_SIZE: u16 = 20;
const TCP_HEADER_SIZE: u16 = 20;
const UDP_HEADER_SIZE: u16 = 8;

const HEADER_SIZE: u16 = IP_HEADER_SIZE + TCP_HEADER_SIZE;

pub fn build_ipv4_packet(cli: Cli) {
    let mut rng: rand::prelude::ThreadRng = rand::rng();

    let mut packet = [0u8; MAX_PACKET_SIZE as usize];

    if cli.tcp {
        match transport_channel(0, Layer3(IpNextHeaderProtocols::Tcp)) {
            Ok((mut tx, _)) => loop {
                let data_size = cli
                    .data
                    .clone()
                    .map(|i| random_value(&mut rng, i))
                    .unwrap_or(0);

                let src_ip = cli
                    .src_ip
                    .as_ref()
                    .map(|nets| {
                        nets.choose(&mut rng)
                            .map(|net| random_ipv4(&mut rng, net))
                            .unwrap()
                    })
                    .unwrap_or_else(|| random_public_ipv4(&mut rng));

                let dst_ip = cli
                    .dst_ip
                    .as_ref()
                    .map(|nets| {
                        nets.choose(&mut rng)
                            .map(|net| random_ipv4(&mut rng, net))
                            .unwrap()
                    })
                    .unwrap_or_else(|| random_public_ipv4(&mut rng));

                {
                    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
                    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                    ip_header.set_source(src_ip);
                    ip_header.set_destination(dst_ip);
                    ip_header.set_version(4);
                    ip_header.set_header_length(5);
                    ip_header.set_total_length(HEADER_SIZE + data_size as u16);
                    ip_header.set_identification(rng.random());
                    ip_header.set_ttl(cli.ttl);
                }

                for i in 0..data_size {
                    packet[HEADER_SIZE as usize + i as usize] = 'X' as u8;
                }

                let src_port = cli
                    .src_port
                    .as_ref()
                    .map(|ports| {
                        ports
                            .choose(&mut rng)
                            .map(|port| random_value(&mut rng, port.clone()))
                            .unwrap()
                    })
                    .unwrap_or_else(|| rng.random());

                let dst_port = cli
                    .dst_port
                    .as_ref()
                    .map(|ports| {
                        ports
                            .choose(&mut rng)
                            .map(|port| random_value(&mut rng, port.clone()))
                            .unwrap()
                    })
                    .unwrap_or_else(|| rng.random());

                {
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

                    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
                    tcp_header.set_checksum(checksum);
                }

                let mut tmp_packet = packet
                    .split_at_mut(data_size as usize + HEADER_SIZE as usize)
                    .0;

                let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet).unwrap();
                let checksum = checksum(&ip_header.to_immutable());
                ip_header.set_checksum(checksum);

                tx.send_to(&ip_header, std::net::IpAddr::V4(dst_ip))
                    .expect("Failed to send packet");

                if cli.flood {
                    continue;
                }

                thread::sleep(cli.interval);
            },
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        }
    } else if cli.udp {
        match transport_channel(0, Layer3(IpNextHeaderProtocols::Udp)) {
            Ok((mut tx, _)) => loop {
                let data_size = cli
                    .data
                    .clone()
                    .map(|i| random_value(&mut rng, i))
                    .unwrap_or(0);

                let src_ip = cli
                    .src_ip
                    .as_ref()
                    .map(|nets| {
                        nets.choose(&mut rng)
                            .map(|net| random_ipv4(&mut rng, net))
                            .unwrap()
                    })
                    .unwrap_or_else(|| random_public_ipv4(&mut rng));

                let dst_ip = cli
                    .dst_ip
                    .as_ref()
                    .map(|nets| {
                        nets.choose(&mut rng)
                            .map(|net| random_ipv4(&mut rng, net))
                            .unwrap()
                    })
                    .unwrap_or_else(|| random_public_ipv4(&mut rng));

                {
                    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
                    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                    ip_header.set_source(src_ip);
                    ip_header.set_destination(dst_ip);
                    ip_header.set_version(4);
                    ip_header.set_header_length(5);
                    ip_header.set_total_length(IP_HEADER_SIZE + UDP_HEADER_SIZE + data_size as u16);
                    ip_header.set_identification(rng.random());
                    ip_header.set_ttl(cli.ttl);
                }

                for i in 0..data_size {
                    packet[IP_HEADER_SIZE as usize + UDP_HEADER_SIZE as usize + i as usize] = 'X' as u8;
                }

                let src_port = cli
                    .src_port
                    .as_ref()
                    .map(|ports| {
                        ports
                            .choose(&mut rng)
                            .map(|port| random_value(&mut rng, port.clone()))
                            .unwrap()
                    })
                    .unwrap_or_else(|| rng.random());

                let dst_port = cli
                    .dst_port
                    .as_ref()
                    .map(|ports| {
                        ports
                            .choose(&mut rng)
                            .map(|port| random_value(&mut rng, port.clone()))
                            .unwrap()
                    })
                    .unwrap_or_else(|| rng.random());

                {
                    let mut udp_header =
                        MutableUdpPacket::new(&mut packet[IP_HEADER_SIZE as usize..]).unwrap();

                    udp_header.set_source(src_port);
                    udp_header.set_destination(dst_port);

                    udp_header.set_length(UDP_HEADER_SIZE + data_size as u16);

                    let checksum = udp_ipv4_checksum(&udp_header.to_immutable(), &src_ip, &dst_ip);
                    udp_header.set_checksum(checksum);
                }

                let mut tmp_packet = packet
                    .split_at_mut(data_size as usize + IP_HEADER_SIZE as usize + UDP_HEADER_SIZE as usize)
                    .0;

                let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet).unwrap();
                let checksum = checksum(&ip_header.to_immutable());
                ip_header.set_checksum(checksum);

                tx.send_to(&ip_header, std::net::IpAddr::V4(dst_ip))
                    .expect("Failed to send packet");

                if cli.flood {
                    continue;
                }

                thread::sleep(cli.interval);
            },
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        }
    } else if cli.rawip {
        let proto = cli.proto.unwrap_or_else(|| {
            eprintln!(
                "No protocol specified for raw IP mode. Use --proto to specify a protocol number."
            );
            std::process::exit(1);
        });

        match transport_channel(0, Layer3(IpNextHeaderProtocol(proto))) {
            Ok((mut tx, _)) => loop {
                let data_size = cli
                    .data
                    .clone()
                    .map(|i| random_value(&mut rng, i))
                    .unwrap_or(0);

                let src_ip = cli
                    .src_ip
                    .as_ref()
                    .map(|nets| {
                        nets.choose(&mut rng)
                            .map(|net| random_ipv4(&mut rng, net))
                            .unwrap()
                    })
                    .unwrap_or_else(|| random_public_ipv4(&mut rng));

                let dst_ip = cli
                    .dst_ip
                    .as_ref()
                    .map(|nets| {
                        nets.choose(&mut rng)
                            .map(|net| random_ipv4(&mut rng, net))
                            .unwrap()
                    })
                    .unwrap_or_else(|| random_public_ipv4(&mut rng));

                {
                    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
                    ip_header.set_next_level_protocol(IpNextHeaderProtocol(proto));
                    ip_header.set_source(src_ip);
                    ip_header.set_destination(dst_ip);
                    ip_header.set_version(4);
                    ip_header.set_header_length(5);
                    ip_header.set_total_length(IP_HEADER_SIZE + data_size as u16);
                    ip_header.set_identification(rng.random());
                    ip_header.set_ttl(cli.ttl);
                }

                for i in 0..data_size {
                    packet[IP_HEADER_SIZE as usize + i as usize] = 'X' as u8;
                }

                let mut tmp_packet = packet
                    .split_at_mut(data_size as usize + IP_HEADER_SIZE as usize)
                    .0;

                let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet).unwrap();
                let checksum = checksum(&ip_header.to_immutable());
                ip_header.set_checksum(checksum);

                tx.send_to(&ip_header, std::net::IpAddr::V4(dst_ip))
                    .expect("Failed to send packet");

                if cli.flood {
                    continue;
                }

                thread::sleep(cli.interval);
            },
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        }
    } else {
        eprintln!("No valid protocol specified. Use --tcp or --udp.");
    }
}
