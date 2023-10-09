mod checksum;
mod icmp_echo;
mod ipv4;
mod setup;

use checksum::Checksummable;
use std::{
    io::{self, prelude::*},
    mem,
    net::Ipv4Addr,
    time::Duration,
};

use timeout_readwrite::TimeoutReader;

use crate::{icmp_echo::IcmpEcho, ipv4::Ipv4, setup::open_tun};

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn main() -> io::Result<()> {
    let mut tun = open_tun("tun0")?;

    // Clean up 'old' data.
    let mut buf = [0u8; 1024];
    let mut tun_reader = TimeoutReader::new(tun.try_clone()?, Duration::from_millis(100));
    while let Ok(n) = tun_reader.read(&mut buf) {
        eprintln!("old {:02x?}", &buf[..n]);
    }

    // Send a ping.
    let ping = IcmpEcho::ping(0);
    let dst = Ipv4Addr::new(192, 0, 2, 1);
    let ipv4_header = Ipv4::new(mem::size_of::<IcmpEcho>() as u16, PROTO_ICMP, dst);
    let packet: Vec<u8> = ipv4_header
        .as_bytes()
        .iter()
        .chain(ping.as_bytes())
        .copied()
        .collect();
    tun.write_all(&packet)?;
    tun.flush()?;

    // Get a response.
    let mut buf = [0u8; 1024];
    let n = tun.read(&mut buf)?;
    assert_eq!(n, 28);
    let ipv4_resp = Ipv4::from_bytes(&buf[..20]);
    let icmp_resp = IcmpEcho::from_bytes(&buf[20..28]);
    dbg!(ipv4_resp, icmp_resp);

    // Check for 'extra' data.
    let mut buf = [0u8; 1024];
    while let Ok(n) = tun_reader.read(&mut buf) {
        eprintln!("extra {:02x?}", &buf[..n]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_round_trip_bytes() {
        // Serialize.
        let ping = IcmpEcho::ping(1);
        let dst = Ipv4Addr::new(192, 0, 2, 1);
        let ipv4_header = Ipv4::new(mem::size_of::<IcmpEcho>() as u16, PROTO_ICMP, dst);
        let packet: Vec<u8> = ipv4_header
            .as_bytes()
            .iter()
            .chain(ping.as_bytes())
            .copied()
            .collect();
        assert_eq!(packet.len(), 28);

        // Deserialize.
        let ipv4_resp = Ipv4::from_bytes(&packet[..20]);
        let icmp_resp = IcmpEcho::from_bytes(&packet[20..28]);
        assert_eq!(ipv4_resp, ipv4_header);
        assert_eq!(icmp_resp, ping);
    }
}
