use clap::Parser;

use crate::ip::Ip;
use crate::range::Range;

#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct Cli {
    #[arg(short = 'I', long, help = "Network interface to use")]
    pub inteface: String,

    #[arg(short = 'i', long, default_value  = "100ms", value_parser = |arg: &str| duration_str::parse(arg), help = "Interval between packets (e.g., 100ms, 1s)")]
    pub interval: std::time::Duration,

    #[arg(
        long,
        default_value_t = false,
        help = "Enable flood mode (send packets as fast as possible)"
    )]
    pub flood: bool,

    #[arg(short = 'c', long, help = "Number of packets to send")]
    pub count: Option<u32>,

    #[arg(long, num_args = 0.., help = "Destination IP address or network (e.g.: 10.0.0.0/8, 10.0.1.15)")]
    pub dst_ip: Option<Ip>,

    #[arg(long, num_args = 0.., help = "Source IP address or network (e.g.: 10.0.0.0/8, 10.0.1.15)")]
    pub src_ip: Option<Ip>,

    #[arg(short = 't', long, default_value_t = 64, help = "Time to live (TTL)")]
    pub ttl: u8,

    #[arg(long, help = "IP id")]
    pub id: Option<u16>,

    #[arg(long, group = "protocol", help = "TCP mode")]
    pub tcp: bool,

    #[arg(long, group = "protocol", help = "UDP mode")]
    pub udp: bool,

    #[arg(long, group = "protocol", help = "RAW IP mode")]
    pub rawip: bool,

    #[arg(
        long,
        help = "Protocol number for raw IP packets (e.g., 6 for TCP, 17 for UDP)"
    )]
    pub proto: Option<u8>,

    #[arg(long, num_args = 0.., help = "Destination port or port range (e.g.: 80, 1000-2000)")]
    pub dst_port: Option<Range<u16>>,

    #[arg(long, num_args = 0.., help = "Source port or port range (e.g.: 80, 1000-2000)")]
    pub src_port: Option<Range<u16>>,

    #[arg(short = 'F', long, default_value_t = false, help = "Set FIN flag")]
    pub fin: bool,

    #[arg(short = 'S', long, default_value_t = false, help = "Set SYN flag")]
    pub syn: bool,

    #[arg(short = 'R', long, default_value_t = false, help = "Set RST flag")]
    pub rst: bool,

    #[arg(short = 'P', long, default_value_t = false, help = "Set PSH flag")]
    pub psh: bool,

    #[arg(short = 'A', long, default_value_t = false, help = "Set ACK flag")]
    pub ack: bool,

    #[arg(short = 'U', long, default_value_t = false, help = "Set URG flag")]
    pub urg: bool,

    #[arg(
        short = 'X',
        long,
        default_value_t = false,
        help = "Set X unused flag (0x40)"
    )]
    pub xmas: bool,

    #[arg(
        short = 'Y',
        long,
        default_value_t = false,
        help = "Set Y ununsed flag (0x80)"
    )]
    pub ymas: bool,

    #[arg(short = 'w', long, default_value_t = 64, help = "Set TCP window size")]
    pub window: u16,

    #[arg(long, help = "Set TCP sequence number")]
    pub seq: Option<u32>,

    #[arg(long, help = "Set TCP acknowledgment number")]
    pub ack_seq: Option<u32>,

    #[arg(short = 'd', long, help = "Data size in bytes (e.g.: 100, 200-300)")]
    pub data: Option<Range<u16>>,

    #[arg(short = 'C', long, help = "Fill data with a specific character (ASCII only)", default_value = "X")]
    pub fill_data: Option<char>,
}
