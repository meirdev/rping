use std::fmt::Display;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use rand::rngs::StdRng;

use crate::range::Range;

#[derive(Debug, Clone)]
pub enum Ip {
    V4(Range<u32>),
    V6(Range<u128>),
}

impl Ip {
    pub fn is_v6(&self) -> bool {
        matches!(self, Ip::V6(_))
    }

    pub fn random_ipv4(&self, rng: &mut StdRng) -> Ipv4Addr {
        match self {
            Ip::V4(range) => Ipv4Addr::from(range.get_random_value(rng)),
            Ip::V6(_) => unreachable!("expected an IPv4 address"),
        }
    }

    pub fn random_ipv6(&self, rng: &mut StdRng) -> Ipv6Addr {
        match self {
            Ip::V6(range) => Ipv6Addr::from(range.get_random_value(rng)),
            Ip::V4(_) => unreachable!("expected an IPv6 address"),
        }
    }
}

impl FromStr for Ip {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            let net = if s.contains('/') {
                s.to_string()
            } else {
                format!("{}/128", s)
            };

            let net = Ipv6Net::from_str(&net)
                .map_err(|_| "Invalid IPv6 or network format".to_string())?;

            Ok(Ip::V6(Range::new(
                u128::from(net.network()),
                u128::from(net.broadcast()),
            )))
        } else {
            let net = if s.contains('/') {
                s.to_string()
            } else {
                format!("{}/32", s)
            };

            let net = Ipv4Net::from_str(&net)
                .map_err(|_| "Invalid IPv4 or network format".to_string())?;

            Ok(Ip::V4(Range::new(
                u32::from(net.network()),
                u32::from(net.broadcast()),
            )))
        }
    }
}

impl Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ip::V4(range) => {
                let start = Ipv4Addr::from(*range.0.start());
                let end = Ipv4Addr::from(*range.0.end());
                if start == end {
                    write!(f, "{}", start)
                } else {
                    write!(f, "{}-{}", start, end)
                }
            }
            Ip::V6(range) => {
                let start = Ipv6Addr::from(*range.0.start());
                let end = Ipv6Addr::from(*range.0.end());
                if start == end {
                    write!(f, "{}", start)
                } else {
                    write!(f, "{}-{}", start, end)
                }
            }
        }
    }
}
