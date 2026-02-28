use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::thread;

use internet_checksum::Checksum;
use log::debug;
use log::error;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv4::checksum;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::udp::MutableUdpPacket;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::transport_channel;
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpCode;
use pnet_packet::icmp::IcmpType;
use pnet_packet::icmp::MutableIcmpPacket;
use quanta::Instant;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::checksum::tcp_ipv4_checksum;
use crate::checksum::udp_ipv4_checksum;
use crate::cli::Cli;
use crate::random::random_public_ipv4;

const MAX_PACKET_SIZE: u16 = u16::MAX;

const IP_HEADER_SIZE: u16 = 20;
const TCP_HEADER_SIZE: u16 = 20;
const UDP_HEADER_SIZE: u16 = 8;
const ICMP_HEADER_SIZE: u16 = 8;

pub fn build_ipv4_packet(cli: Cli, packets: &Arc<AtomicU64>, bytes: &Arc<AtomicU64>) {
    let proto = if cli.tcp {
        IpNextHeaderProtocols::Tcp
    } else if cli.udp {
        IpNextHeaderProtocols::Udp
    } else if cli.icmp {
        IpNextHeaderProtocols::Icmp
    } else if let Some(proto) = cli.proto {
        IpNextHeaderProtocol(proto)
    } else {
        eprintln!("No protocol specified. Use --tcp, --udp, or --proto.");
        std::process::exit(1);
    };

    let header_size = match proto {
        IpNextHeaderProtocols::Tcp => IP_HEADER_SIZE + TCP_HEADER_SIZE,
        IpNextHeaderProtocols::Udp => IP_HEADER_SIZE + UDP_HEADER_SIZE,
        IpNextHeaderProtocols::Icmp => IP_HEADER_SIZE + ICMP_HEADER_SIZE, // only for ICMP echo requests!
        _ => IP_HEADER_SIZE,
    };

    let mut rng = StdRng::from_rng(&mut rand::rng());

    let mut packet = [0u8; MAX_PACKET_SIZE as usize];

    let (_, body) = packet.split_at_mut(header_size as usize);

    if let Some(fill_data) = cli.fill_data {
        if !fill_data.is_ascii() {
            eprintln!("Fill data must be an ASCII character.");
            std::process::exit(1);
        }

        body.fill(fill_data as u8);
    }

    let mut count = 0;
    let start_time = Instant::now();

    match transport_channel(0, Layer3(proto)) {
        Ok((mut tx, _)) => loop {
            let data_size = cli
                .data
                .as_ref()
                .map(|i| i.get_random_value(&mut rng))
                .unwrap_or(0);

            let src_ip = cli
                .src_ip
                .as_ref()
                .map(|i| i.0.get_random_value(&mut rng))
                .map(|i| Ipv4Addr::from(i))
                .unwrap_or_else(|| random_public_ipv4(&mut rng));

            let dst_ip = cli
                .dst_ip
                .as_ref()
                .map(|i| i.0.get_random_value(&mut rng))
                .map(|i| Ipv4Addr::from(i))
                .unwrap_or_else(|| random_public_ipv4(&mut rng));

            let packet_size = (header_size + data_size) as usize;

            {
                let mut ip_header = MutableIpv4Packet::new(&mut packet[..packet_size]).unwrap();
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

            if proto == IpNextHeaderProtocols::Tcp || proto == IpNextHeaderProtocols::Udp {
                let src_port = cli
                    .src_port
                    .as_ref()
                    .map(|i| i.get_random_value(&mut rng))
                    .unwrap_or_else(|| rng.random());

                let dst_port = cli
                    .dst_port
                    .as_ref()
                    .map(|i| i.get_random_value(&mut rng))
                    .unwrap_or_else(|| rng.random());

                if proto == IpNextHeaderProtocols::Tcp {
                    let mut tcp_header =
                        MutableTcpPacket::new(&mut packet[IP_HEADER_SIZE as usize..packet_size])
                            .unwrap();

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
                        MutableUdpPacket::new(&mut packet[IP_HEADER_SIZE as usize..packet_size])
                            .unwrap();

                    udp_header.set_source(src_port);
                    udp_header.set_destination(dst_port);

                    udp_header.set_length(UDP_HEADER_SIZE + data_size as u16);

                    udp_header.set_checksum(0);

                    let checksum = udp_ipv4_checksum(&udp_header.to_immutable(), &src_ip, &dst_ip);
                    udp_header.set_checksum(checksum);
                }
            } else if proto == IpNextHeaderProtocols::Icmp {
                let mut icmp_packet =
                    MutableIcmpPacket::new(&mut packet[IP_HEADER_SIZE as usize..packet_size])
                        .unwrap();

                icmp_packet.set_icmp_type(IcmpType(cli.icmptype));
                icmp_packet.set_icmp_code(IcmpCode(cli.icmpcode));

                icmp_packet.set_checksum(0);

                let mut checksum = Checksum::new();
                checksum.add_bytes(&icmp_packet.packet());

                let checksum_value = checksum.checksum();
                let checksum_value = u16::from_be_bytes(checksum_value);

                icmp_packet.set_checksum(checksum_value);
            }

            let mut tmp_packet = packet.split_at_mut(packet_size).0;

            let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet).unwrap();
            let checksum = checksum(&ip_header.to_immutable());
            ip_header.set_checksum(checksum);

            debug!("{:#?}", ip_header);

            if tx
                .send_to(&ip_header, std::net::IpAddr::V4(dst_ip))
                .is_err()
            {
                error!("Failed to send packet to {:#?}", ip_header);
                continue;
            }

            packets.fetch_add(1, Ordering::SeqCst);
            bytes.fetch_add(packet_size as u64, Ordering::SeqCst);

            if let Some(duration) = cli.duration {
                if start_time.elapsed() >= duration {
                    break;
                }
            }

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
