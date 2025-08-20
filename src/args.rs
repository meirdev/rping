use clap::{Args, Parser, Subcommand};
use ipnet::Ipv4Net;
use std::{net::Ipv4Addr, str::FromStr};

#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub protocol: Protocol,

    #[arg(short = 'I', long)]
    pub inteface: String,

    #[arg(short = 'i', long)]
    pub interval: Option<String>,

    #[arg(long, default_value_t = false)]
    pub flood: bool,
}

#[derive(Args, Debug)]
pub struct Ip {
    #[arg(long, num_args = 0..)]
    pub dst_ip: Option<Vec<ArgIp>>,

    #[arg(long, num_args = 0..)]
    pub src_ip: Option<Vec<ArgIp>>,

    #[arg(short = 't', long)]
    pub ttl: Option<u8>,

    #[arg(short = 'd', long)]
    pub data: Option<ArgData>,
}

#[derive(Subcommand, Debug)]
pub enum Protocol {
    Tcp {
        #[command(flatten)]
        ip: Ip,

        #[arg(long, num_args = 0.., help = "Destination port(s)")]
        dst_port: Option<Vec<ArgPort>>,

        #[arg(long, num_args = 0..)]
        src_port: Option<Vec<ArgPort>>,

        #[arg(short = 'F', long, default_value_t = false)]
        fin: bool,

        #[arg(short = 'S', long, default_value_t = false)]
        syn: bool,

        #[arg(short = 'R', long, default_value_t = false)]
        rst: bool,

        #[arg(short = 'P', long, default_value_t = false)]
        psh: bool,

        #[arg(short = 'A', long, default_value_t = false)]
        ack: bool,

        #[arg(short = 'U', long, default_value_t = false)]
        urg: bool,

        #[arg(short = 'X', long, default_value_t = false)]
        xmas: bool,

        #[arg(short = 'Y', long, default_value_t = false)]
        ymas: bool,

        #[arg(short = 'w', long, default_value_t = 64)]
        window: u16,

        #[arg(long)]
        seq: Option<u32>,

        #[arg(long)]
        ack_seq: Option<u32>,
    },
    Udp {
        #[command(flatten)]
        ip: Ip,

        #[arg(long, num_args = 0..)]
        dst_port: Option<Vec<ArgPort>>,

        #[arg(long, num_args = 0..)]
        src_port: Option<Vec<ArgPort>>,
    }
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
pub struct ArgData(pub std::ops::RangeInclusive<u16>);

impl FromStr for ArgData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let range = parse_range::<u16>(s, None, None)?;
        Ok(ArgData(range))
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
