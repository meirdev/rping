use std::net::Ipv4Addr;

use rand::Rng;

pub fn random_public_ipv4(rng: &mut rand::prelude::StdRng) -> Ipv4Addr {
    loop {
        let ip: Ipv4Addr = rng.random_range(0..=0xFFFFFFFF).into();

        if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() {
            return ip;
        }
    }
}
