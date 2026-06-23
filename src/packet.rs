use std::net::IpAddr;
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
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol;
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
use crate::random::random_public_ipv6;

const MAX_PACKET_SIZE: u16 = u16::MAX;

const IP_HEADER_SIZE: u16 = 20;
const IPV6_HEADER_SIZE: u16 = 40;
const TCP_HEADER_SIZE: u16 = 20;
const UDP_HEADER_SIZE: u16 = 8;
const ICMP_HEADER_SIZE: u16 = 8;

fn tcp_flags(cli: &Cli) -> u8 {
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
    flags
}

pub fn build_ipv4_packet(
    cli: Cli,
    proto: IpNextHeaderProtocol,
    packets: &Arc<AtomicU64>,
    bytes: &Arc<AtomicU64>,
) {
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
                .map(|i| i.random_ipv4(&mut rng))
                .unwrap_or_else(|| random_public_ipv4(&mut rng));

            let dst_ip = cli
                .dst_ip
                .as_ref()
                .map(|i| i.random_ipv4(&mut rng))
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

                    tcp_header.set_flags(tcp_flags(&cli));
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

/// Wraps an arbitrary byte slice so it can be handed to `send_to`, which is
/// needed for raw protocols that have no dedicated pnet packet type.
struct RawPacket<'a>(&'a [u8]);

impl<'a> Packet for RawPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.0
    }

    fn payload(&self) -> &[u8] {
        self.0
    }
}

pub fn build_ipv6_packet(
    cli: Cli,
    proto: IpNextHeaderProtocol,
    packets: &Arc<AtomicU64>,
    bytes: &Arc<AtomicU64>,
) {
    // For IPv6 the kernel builds the IP header, so the buffer only holds the
    // transport segment.
    let header_size = match proto {
        IpNextHeaderProtocols::Tcp => TCP_HEADER_SIZE,
        IpNextHeaderProtocols::Udp => UDP_HEADER_SIZE,
        _ => 0,
    };

    let mut rng = StdRng::from_rng(&mut rand::rng());

    let mut packet = [0u8; MAX_PACKET_SIZE as usize];

    let (_, body) = packet.split_at_mut(header_size as usize);

    if let Some(fill_data) = cli.fill_data {
        body.fill(fill_data as u8);
    }

    let mut count = 0;
    let start_time = Instant::now();

    let (mut tx, _) = match transport_channel(0, Layer4(TransportProtocol::Ipv6(proto))) {
        Ok(channel) => channel,
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    // The hop limit (TTL) is set on the socket, not per packet, because the
    // kernel builds the IPv6 header.
    let _ = tx.set_ttl(cli.ttl);

    // The source address can't be spoofed on an IPv6 raw socket, so we let the
    // kernel compute the transport checksum (it needs the source it selects) by
    // pointing IPV6_CHECKSUM at the checksum field's offset.
    let checksum_offset: libc::c_int = match proto {
        IpNextHeaderProtocols::Tcp => 16,
        IpNextHeaderProtocols::Udp => 6,
        _ => -1,
    };
    unsafe {
        libc::setsockopt(
            tx.socket.fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            &checksum_offset as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    loop {
        let data_size = cli
            .data
            .as_ref()
            .map(|i| i.get_random_value(&mut rng))
            .unwrap_or(0);

        let dst_ip = cli
            .dst_ip
            .as_ref()
            .map(|i| i.random_ipv6(&mut rng))
            .unwrap_or_else(|| random_public_ipv6(&mut rng));

        let packet_size = (header_size + data_size) as usize;

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
                let mut tcp_header = MutableTcpPacket::new(&mut packet[..packet_size]).unwrap();

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

                tcp_header.set_flags(tcp_flags(&cli));
                tcp_header.set_window(cli.window);
                tcp_header.set_data_offset(5);

                // The kernel fills the checksum (see IPV6_CHECKSUM above).
                tcp_header.set_checksum(0);
            } else {
                let mut udp_header = MutableUdpPacket::new(&mut packet[..packet_size]).unwrap();

                udp_header.set_source(src_port);
                udp_header.set_destination(dst_port);
                udp_header.set_length(UDP_HEADER_SIZE + data_size as u16);

                // The kernel fills the checksum (see IPV6_CHECKSUM above).
                udp_header.set_checksum(0);
            }
        }

        if tx
            .send_to(RawPacket(&packet[..packet_size]), IpAddr::V6(dst_ip))
            .is_err()
        {
            error!("Failed to send packet to {}", dst_ip);
            continue;
        }

        packets.fetch_add(1, Ordering::SeqCst);
        bytes.fetch_add(
            (IPV6_HEADER_SIZE as usize + packet_size) as u64,
            Ordering::SeqCst,
        );

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
    }
}
