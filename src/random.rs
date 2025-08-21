use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use rand::Rng;

use crate::range::Range;

pub fn random_public_ipv4(rng: &mut rand::prelude::ThreadRng) -> Ipv4Addr {
    loop {
        let ip: Ipv4Addr = rng.random_range(0..=0xFFFFFFFF).into();

        if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() {
            return ip;
        }
    }
}

pub fn random_ipv4(rng: &mut rand::prelude::ThreadRng, ipv4net: &Ipv4Net) -> Ipv4Addr {
    let start = ipv4net.network();
    let end = ipv4net.broadcast();

    let ip_num: u32 = rng.random_range(start.into()..=end.into());

    Ipv4Addr::from(ip_num)
}

pub fn random_value<T: std::cmp::PartialOrd + rand::distr::uniform::SampleUniform>(
    rng: &mut rand::prelude::ThreadRng,
    range: Range<T>,
) -> T {
    rng.random_range(range.0)
}
