use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;

#[derive(Debug, Clone)]
pub enum Ip {
    Address(Ipv4Addr),
    Network(Ipv4Net),
}

impl FromStr for Ip {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('/') {
            Ipv4Net::from_str(s)
                .map(Ip::Network)
                .map_err(|_| "Invalid network format".to_string())
        } else {
            Ipv4Addr::from_str(s)
                .map(Ip::Address)
                .map_err(|_| "Invalid IP address format".to_string())
        }
    }
}
