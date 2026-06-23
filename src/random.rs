use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use rand::Rng;

pub fn random_public_ipv4(rng: &mut rand::prelude::StdRng) -> Ipv4Addr {
    loop {
        let ip: Ipv4Addr = rng.random_range(0..=0xFFFFFFFF).into();

        if is_public_ipv4(&ip) {
            return ip;
        }
    }
}

fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    !ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
}

pub fn random_public_ipv6(rng: &mut rand::prelude::StdRng) -> Ipv6Addr {
    loop {
        let ip: Ipv6Addr = rng.random::<u128>().into();

        if is_public_ipv6(&ip) {
            return ip;
        }
    }
}

// `Ipv6Addr::is_unique_local`/`is_unicast_link_local`/`is_global` are still
// unstable (the `ip` feature), so we check the prefixes manually on stable.
fn is_public_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }

    let prefix = ip.segments()[0];

    // Link-local unicast (fe80::/10).
    if prefix & 0xffc0 == 0xfe80 {
        return false;
    }

    // Unique local addresses (fc00::/7).
    if prefix & 0xfe00 == 0xfc00 {
        return false;
    }

    true
}
