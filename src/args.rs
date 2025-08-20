use std::{net::Ipv4Addr, str::FromStr};

use clap::Parser;
use ipnet::Ipv4Net;

#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct Cli {
    #[arg(short = 'I', long, help = "Network interface to use")]
    pub inteface: String,

    #[arg(short = 'i', long, help = "Interval between packets (e.g., 100ms, 1s)")]
    pub interval: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Enable flood mode (send packets as fast as possible)"
    )]
    pub flood: bool,

    #[arg(short = 'c', long, help = "Number of packets to send")]
    pub count: Option<u32>,

    #[arg(long, num_args = 0.., value_delimiter = ',', help = "Destination IP address or network (e.g.: 10.0.0.0/8, 10.0.1.15)")]
    pub dst_ip: Option<Vec<ArgIp>>,

    #[arg(long, num_args = 0.., value_delimiter = ',', help = "Source IP address or network (e.g.: 10.0.0.0/8, 10.0.1.15)")]
    pub src_ip: Option<Vec<ArgIp>>,

    #[arg(short = 't', long, default_value_t = 64, help = "Time to live (TTL)")]
    pub ttl: u8,

    #[arg(long, default_value_t = true, group = "protocol", help = "TCP mode")]
    pub tcp: bool,

    #[arg(long, group = "protocol", help = "UDP mode")]
    pub udp: bool,

    #[arg(long, group = "protocol", help = "ICMP mode")]
    pub icmp: bool,

    #[arg(long, group = "protocol", help = "RAW IP mode")]
    pub rawip: bool,

    #[arg(
        long,
        help = "Protocol number for raw IP packets (e.g., 6 for TCP, 17 for UDP)"
    )]
    pub proto: Option<u8>,

    #[arg(long, num_args = 0.., value_delimiter = ',', help = "Destination port or port range (e.g.: 80, 1000-2000)")]
    pub dst_port: Option<Vec<ArgPort>>,

    #[arg(long, num_args = 0.., value_delimiter = ',', help = "Source port or port range (e.g.: 80, 1000-2000)")]
    pub src_port: Option<Vec<ArgPort>>,

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
    pub data: Option<ArgData>,
}

fn parse_range<T: std::str::FromStr + std::cmp::PartialOrd + std::fmt::Display>(
    input: &str,
    min: Option<T>,
    max: Option<T>,
) -> Result<std::ops::RangeInclusive<T>, String> {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 2 {
        return Err("Invalid range format. Use 'start-end'.".to_string());
    }

    let start = parts[0]
        .parse::<T>()
        .map_err(|_| "Invalid start".to_string())?;
    let end = parts[1]
        .parse::<T>()
        .map_err(|_| "Invalid end".to_string())?;

    if start > end {
        return Err("Start cannot be greater than end".to_string());
    }

    if let Some(min_val) = min {
        if start < min_val {
            return Err(format!("Start must be at least {}", min_val));
        }
    }

    if let Some(max_val) = max {
        if end > max_val {
            return Err(format!("End must be at most {}", max_val));
        }
    }

    Ok(start..=end)
}

#[derive(Debug, Clone)]
pub enum ArgData {
    Single(Port),
    Range(std::ops::RangeInclusive<Port>),
}

impl FromStr for ArgData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            let range = parse_range::<u16>(s, None, None)?;
            Ok(ArgData::Range(range))
        } else {
            let data_size = s
                .parse::<u16>()
                .map_err(|_| "Invalid data size".to_string())?;
            Ok(ArgData::Single(data_size))
        }
    }
}

type Port = u16;

const MIN_PORT: Port = 0;
const MAX_PORT: Port = 65535;

#[derive(Debug, Clone, PartialEq)]
pub enum ArgPort {
    Single(Port),
    Range(std::ops::RangeInclusive<Port>),
}

impl FromStr for ArgPort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            let range = parse_range::<Port>(s, Some(MIN_PORT), Some(MAX_PORT))?;
            Ok(ArgPort::Range(range))
        } else {
            let port = s.parse::<Port>().map_err(|_| "Invalid port".to_string())?;
            Ok(ArgPort::Single(port))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArgIp {
    Address(Ipv4Addr),
    Network(Ipv4Net),
}

impl FromStr for ArgIp {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('/') {
            let net = s
                .parse::<Ipv4Net>()
                .map_err(|_| "Invalid network".to_string())?;
            Ok(ArgIp::Network(net))
        } else {
            let addr = s
                .parse::<Ipv4Addr>()
                .map_err(|_| "Invalid IP address".to_string())?;
            Ok(ArgIp::Address(addr))
        }
    }
}
