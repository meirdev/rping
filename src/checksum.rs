use std::net::Ipv4Addr;

use internet_checksum::Checksum;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

fn proto_ipv4_checksum<T: Packet>(
    packet: &T,
    proto: IpNextHeaderProtocol,
    source: &Ipv4Addr,
    destination: &Ipv4Addr,
) -> u16 {
    let mut tcp_pseudo_header = [0u8; 12];

    tcp_pseudo_header[0..4].copy_from_slice(&source.octets());
    tcp_pseudo_header[4..8].copy_from_slice(&destination.octets());
    tcp_pseudo_header[9] = proto.0;
    tcp_pseudo_header[10..12].copy_from_slice(&(packet.packet().len() as u16).to_be_bytes());

    let mut checksm = Checksum::new();

    checksm.add_bytes(&tcp_pseudo_header);
    checksm.add_bytes(&packet.packet());

    u16::from_be_bytes(checksm.checksum())
}

pub fn tcp_ipv4_checksum(packet: &TcpPacket, source: &Ipv4Addr, destination: &Ipv4Addr) -> u16 {
    proto_ipv4_checksum(packet, IpNextHeaderProtocols::Tcp, source, destination)
}

pub fn udp_ipv4_checksum(packet: &UdpPacket, source: &Ipv4Addr, destination: &Ipv4Addr) -> u16 {
    proto_ipv4_checksum(packet, IpNextHeaderProtocols::Udp, source, destination)
}
