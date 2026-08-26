use std::fs;
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

fn bind_to_interface(fd: libc::c_int, iface: &str) {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface.as_ptr() as *const libc::c_void,
            iface.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        error!(
            "Failed to bind to interface {}: {}",
            iface,
            std::io::Error::last_os_error()
        );
    }
}

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

fn random_data_size(cli: &Cli, rng: &mut StdRng) -> u16 {
    cli.data
        .as_ref()
        .map(|i| i.get_random_value(rng))
        .unwrap_or(0)
}

fn random_ports(cli: &Cli, rng: &mut StdRng) -> (u16, u16) {
    let src_port = cli
        .src_port
        .as_ref()
        .map(|i| i.get_random_value(rng))
        .unwrap_or_else(|| rng.random());

    let dst_port = cli
        .dst_port
        .as_ref()
        .map(|i| i.get_random_value(rng))
        .unwrap_or_else(|| rng.random());

    (src_port, dst_port)
}

fn build_tcp_header(
    tcp_header: &mut MutableTcpPacket,
    cli: &Cli,
    src_port: u16,
    dst_port: u16,
    rng: &mut StdRng,
) {
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_acknowledgement(cli.ack_seq.unwrap_or_else(|| rng.random()));
    tcp_header.set_sequence(cli.seq.unwrap_or_else(|| rng.random()));
    tcp_header.set_flags(tcp_flags(cli));
    tcp_header.set_window(cli.window);
    tcp_header.set_data_offset(5);
    tcp_header.set_checksum(0);
}

fn build_udp_header(
    udp_header: &mut MutableUdpPacket,
    src_port: u16,
    dst_port: u16,
    data_size: u16,
) {
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length(UDP_HEADER_SIZE + data_size);
    udp_header.set_checksum(0);
}

fn drive<F>(
    cli: &Cli,
    header_size: u16,
    packets: &Arc<AtomicU64>,
    bytes: &Arc<AtomicU64>,
    mut send_one: F,
) where
    F: FnMut(&mut StdRng, &mut [u8]) -> Option<u64>,
{
    let mut rng = StdRng::from_rng(&mut rand::rng());

    let mut packet = [0u8; MAX_PACKET_SIZE as usize];

    let file_data = match cli.file.as_ref() {
        Some(path) => match fs::read(path) {
            Ok(data) => Some(data),
            Err(err) => {
                error!("Failed to read payload file {}: {}", path.display(), err);
                return;
            }
        },
        None => None,
    };

    initialize_payload(
        &mut packet,
        header_size as usize,
        cli.fill_data,
        file_data.as_deref(),
    );

    let mut count = 0u32;
    let start_time = Instant::now();

    loop {
        if let Some(sent_bytes) = send_one(&mut rng, &mut packet) {
            packets.fetch_add(1, Ordering::SeqCst);
            bytes.fetch_add(sent_bytes, Ordering::SeqCst);
        }

        if let Some(duration) = cli.duration {
            if start_time.elapsed() >= duration {
                break;
            }
        }

        if cli.flood {
            continue;
        }

        if let Some(cli_count) = cli.count {
            count += 1;
            if count >= cli_count {
                break;
            }
        }

        thread::sleep(cli.interval);
    }
}

fn initialize_payload(
    packet: &mut [u8],
    header_size: usize,
    fill_data: Option<char>,
    file_data: Option<&[u8]>,
) {
    let payload = &mut packet[header_size..];

    if let Some(file_data) = file_data {
        payload.fill(0);
        let copy_len = payload.len().min(file_data.len());
        payload[..copy_len].copy_from_slice(&file_data[..copy_len]);
    } else {
        payload.fill(fill_data.unwrap_or('X') as u8);
    }
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

    let (mut tx, _) = match transport_channel(0, Layer3(proto)) {
        Ok(channel) => channel,
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    if let Some(iface) = cli.interface.as_deref() {
        bind_to_interface(tx.socket.fd, iface);
    }

    drive(&cli, header_size, packets, bytes, |rng, packet| {
        let data_size = random_data_size(&cli, rng);

        let src_ip = cli
            .src_ip
            .as_ref()
            .map(|i| i.random_ipv4(rng))
            .unwrap_or_else(|| random_public_ipv4(rng));

        let dst_ip = cli
            .dst_ip
            .as_ref()
            .map(|i| i.random_ipv4(rng))
            .unwrap_or_else(|| random_public_ipv4(rng));

        let packet_size = (header_size + data_size) as usize;

        {
            let mut ip_header = MutableIpv4Packet::new(&mut packet[..packet_size]).unwrap();
            ip_header.set_next_level_protocol(proto);
            ip_header.set_source(src_ip);
            ip_header.set_destination(dst_ip);
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_total_length(header_size + data_size);
            ip_header.set_identification(cli.id.unwrap_or_else(|| rng.random()));
            ip_header.set_ttl(cli.ttl);
        }

        match proto {
            IpNextHeaderProtocols::Tcp => {
                let (src_port, dst_port) = random_ports(&cli, rng);
                let mut tcp_header =
                    MutableTcpPacket::new(&mut packet[IP_HEADER_SIZE as usize..packet_size])
                        .unwrap();

                build_tcp_header(&mut tcp_header, &cli, src_port, dst_port, rng);

                let checksum = tcp_ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
                tcp_header.set_checksum(checksum);
            }
            IpNextHeaderProtocols::Udp => {
                let (src_port, dst_port) = random_ports(&cli, rng);
                let mut udp_header =
                    MutableUdpPacket::new(&mut packet[IP_HEADER_SIZE as usize..packet_size])
                        .unwrap();

                build_udp_header(&mut udp_header, src_port, dst_port, data_size);

                let checksum = udp_ipv4_checksum(&udp_header.to_immutable(), &src_ip, &dst_ip);
                udp_header.set_checksum(checksum);
            }
            IpNextHeaderProtocols::Icmp => {
                let mut icmp_packet =
                    MutableIcmpPacket::new(&mut packet[IP_HEADER_SIZE as usize..packet_size])
                        .unwrap();

                icmp_packet.set_icmp_type(IcmpType(cli.icmptype));
                icmp_packet.set_icmp_code(IcmpCode(cli.icmpcode));

                icmp_packet.set_checksum(0);

                let mut checksum = Checksum::new();
                checksum.add_bytes(icmp_packet.packet());

                icmp_packet.set_checksum(u16::from_be_bytes(checksum.checksum()));
            }
            _ => {}
        }

        let mut ip_header = MutableIpv4Packet::new(&mut packet[..packet_size]).unwrap();
        let checksum = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);

        debug!("{:#?}", ip_header);

        if let Err(err) = tx.send_to(&ip_header, IpAddr::V4(dst_ip)) {
            if is_transient_send_error(&err) {
                debug!("Failed to send packet to {:#?}: {}", ip_header, err);
            } else {
                error!("Failed to send packet to {:#?}: {}", ip_header, err);
            }
            return None;
        }

        Some(packet_size as u64)
    });
}

/// Returns `true` when a send failure is a transient, expected back-pressure
/// condition (the socket buffer is full / would block) rather than a real
/// error. These are logged at `debug` instead of `error`.
fn is_transient_send_error(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::WouldBlock)
        || err.raw_os_error() == Some(libc::ENOBUFS)
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

    let (mut tx, _) = match transport_channel(0, Layer4(TransportProtocol::Ipv6(proto))) {
        Ok(channel) => channel,
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    if let Some(iface) = cli.interface.as_deref() {
        bind_to_interface(tx.socket.fd, iface);
    }

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

    drive(&cli, header_size, packets, bytes, |rng, packet| {
        let data_size = random_data_size(&cli, rng);

        let dst_ip = cli
            .dst_ip
            .as_ref()
            .map(|i| i.random_ipv6(rng))
            .unwrap_or_else(|| random_public_ipv6(rng));

        let packet_size = (header_size + data_size) as usize;

        // The kernel fills the transport checksum (see IPV6_CHECKSUM above).
        match proto {
            IpNextHeaderProtocols::Tcp => {
                let (src_port, dst_port) = random_ports(&cli, rng);
                let mut tcp_header = MutableTcpPacket::new(&mut packet[..packet_size]).unwrap();
                build_tcp_header(&mut tcp_header, &cli, src_port, dst_port, rng);
            }
            IpNextHeaderProtocols::Udp => {
                let (src_port, dst_port) = random_ports(&cli, rng);
                let mut udp_header = MutableUdpPacket::new(&mut packet[..packet_size]).unwrap();
                build_udp_header(&mut udp_header, src_port, dst_port, data_size);
            }
            _ => {}
        }

        if let Err(err) = tx.send_to(RawPacket(&packet[..packet_size]), IpAddr::V6(dst_ip)) {
            if is_transient_send_error(&err) {
                debug!("Failed to send packet to {}: {}", dst_ip, err);
            } else {
                error!("Failed to send packet to {}: {}", dst_ip, err);
            }
            return None;
        }

        Some((IPV6_HEADER_SIZE as usize + packet_size) as u64)
    });
}
