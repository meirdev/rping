use std::str::FromStr;

use ipnet::Ipv4Net;

use crate::range::Range;

#[derive(Debug, Clone)]
pub struct Ip(pub Range<u32>);

impl FromStr for Ip {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let net = if s.contains('/') {
            s.to_string()
        } else {
            format!("{}/32", s)
        };

        let net = Ipv4Net::from_str(&net).map_err(|_| "Invalid IP or network format".to_string());

        net.map(|net| Ip(Range::new(net.network().into(), net.broadcast().into())))
            .map_err(|e| e.to_string())
    }
}
