use std::fmt::Display;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::IpNet;
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
        let (start, end) = if let Some((start, end)) = s.split_once('-') {
            let start = IpAddr::from_str(start).map_err(|_| "Invalid range start".to_string())?;
            let end = IpAddr::from_str(end).map_err(|_| "Invalid range end".to_string())?;
            (start, end)
        } else {
            let net = if s.contains('/') {
                IpNet::from_str(s).map_err(|_| "Invalid IP or network format".to_string())?
            } else {
                IpNet::from(IpAddr::from_str(s).map_err(|_| "Invalid IP address".to_string())?)
            };
            (net.network(), net.broadcast())
        };

        match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let (start, end) = (u32::from(start), u32::from(end));
                if start > end {
                    return Err("Range start must not be greater than end".to_string());
                }
                Ok(Ip::V4(Range::new(start, end)))
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                let (start, end) = (u128::from(start), u128::from(end));
                if start > end {
                    return Err("Range start must not be greater than end".to_string());
                }
                Ok(Ip::V6(Range::new(start, end)))
            }
            _ => Err("Range start and end must be the same IP version".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> (Ipv4Addr, Ipv4Addr) {
        match Ip::from_str(s).unwrap() {
            Ip::V4(r) => (Ipv4Addr::from(*r.0.start()), Ipv4Addr::from(*r.0.end())),
            Ip::V6(_) => panic!("expected IPv4"),
        }
    }

    fn v6(s: &str) -> (Ipv6Addr, Ipv6Addr) {
        match Ip::from_str(s).unwrap() {
            Ip::V6(r) => (Ipv6Addr::from(*r.0.start()), Ipv6Addr::from(*r.0.end())),
            Ip::V4(_) => panic!("expected IPv6"),
        }
    }

    #[test]
    fn parses_single_cidr_and_range() {
        // Single address -> a one-element range.
        assert_eq!(
            v4("10.0.1.15"),
            ("10.0.1.15".parse().unwrap(), "10.0.1.15".parse().unwrap())
        );
        // CIDR -> network..=broadcast.
        assert_eq!(
            v4("10.0.0.0/24"),
            ("10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap())
        );
        // Arbitrary range spanning two /24s.
        assert_eq!(
            v4("10.0.1.3-10.0.2.6"),
            ("10.0.1.3".parse().unwrap(), "10.0.2.6".parse().unwrap())
        );
        // IPv6 range.
        assert_eq!(
            v6("2001:db8::1-2001:db8::ff"),
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::ff".parse().unwrap()
            )
        );
    }

    #[test]
    fn rejects_reversed_and_malformed_ranges() {
        assert!(Ip::from_str("10.0.2.6-10.0.1.3").is_err());
        assert!(Ip::from_str("2001:db8::ff-2001:db8::1").is_err());
        assert!(Ip::from_str("10.0.0.1-nonsense").is_err());
        // Endpoints of different IP versions are rejected.
        assert!(Ip::from_str("10.0.0.1-2001:db8::1").is_err());
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
