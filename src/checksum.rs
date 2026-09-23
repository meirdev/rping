use std::net::Ipv4Addr;

use internet_checksum::Checksum;
use internet_checksum::update;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

/// Reuses the checksum of the unchanged parts of packets of the same size.
#[derive(Default)]
pub struct IncrementalChecksum {
    base: Option<([u8; 2], usize)>,
}

impl IncrementalChecksum {
    pub fn new() -> Self {
        Self::default()
    }

    fn compute(&mut self, size: usize, fields: &[&[u8]], full: impl FnOnce() -> [u8; 2]) -> u16 {
        // The largest varying field is the first 12 bytes of a TCP header.
        let zeros = [0; 12];
        if let Some((base, cached_size)) = self.base {
            if cached_size == size {
                let mut checksum = base;
                for field in fields {
                    checksum = update(checksum, &zeros[..field.len()], field);
                }
                return u16::from_be_bytes(checksum);
            }
        }

        let checksum = full();
        let mut base = checksum;
        for field in fields {
            base = update(base, field, &zeros[..field.len()]);
        }
        self.base = Some((base, size));
        u16::from_be_bytes(checksum)
    }

    pub fn tcp_ipv4(
        &mut self,
        header: &TcpPacket,
        source: &Ipv4Addr,
        destination: &Ipv4Addr,
        size: usize,
    ) -> u16 {
        let fields: &[&[u8]] = &[
            &source.octets(),
            &destination.octets(),
            &header.packet()[..12],
        ];
        self.compute(size, fields, || {
            ipv4_checksum(
                header.packet(),
                IpNextHeaderProtocols::Tcp,
                source,
                destination,
            )
        })
    }

    pub fn udp_ipv4(
        &mut self,
        header: &UdpPacket,
        source: &Ipv4Addr,
        destination: &Ipv4Addr,
        size: usize,
    ) -> u16 {
        let fields: &[&[u8]] = &[
            &source.octets(),
            &destination.octets(),
            &header.packet()[..4],
        ];
        self.compute(size, fields, || {
            ipv4_checksum(
                header.packet(),
                IpNextHeaderProtocols::Udp,
                source,
                destination,
            )
        })
    }
}

fn ipv4_checksum(
    packet: &[u8],
    protocol: IpNextHeaderProtocol,
    source: &Ipv4Addr,
    destination: &Ipv4Addr,
) -> [u8; 2] {
    let mut checksum = Checksum::new();
    checksum.add_bytes(&source.octets());
    checksum.add_bytes(&destination.octets());
    checksum.add_bytes(&[0, protocol.0]);
    checksum.add_bytes(&(packet.len() as u16).to_be_bytes());
    checksum.add_bytes(packet);
    checksum.checksum()
}
