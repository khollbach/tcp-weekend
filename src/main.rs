mod setup;
mod checksum;
mod ipv4;
mod icmp_echo;
mod udp;

use std::{fs::File, io::prelude::*, mem, net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result};
use timeout_readwrite::TimeoutReader;
use udp::new_udp_packet;

use crate::{checksum::AsBytes, icmp_echo::IcmpEcho, ipv4::Ipv4, setup::open_tun, udp::UdpHeader};

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn main() -> Result<()> {
    let mut tun = open_tun("tun0")?;

    // Clean up 'old' data.
    let mut buf = [0u8; 1024];
    let mut tun_reader = TimeoutReader::new(tun.try_clone()?, Duration::from_millis(100));
    while let Ok(n) = tun_reader.read(&mut buf) {
        eprintln!("old {:02x?}", &buf[..n]);
    }

    // send_ping(&mut tun)?;
    send_dns(&mut tun)?;

    // Check for 'extra' data.
    let mut buf = [0u8; 1024];
    while let Ok(n) = tun_reader.read(&mut buf) {
        eprintln!("extra {:02x?}", &buf[..n]);
    }

    Ok(())
}

fn send_dns(tun: &mut File) -> Result<()> {
    // Send a DNS query
    let query =
        b"D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    // let packet = new_udp_packet([8, 8, 8, 8].into(), 12345, 53, query);
    let packet = new_udp_packet([192, 0, 2, 1].into(), 12345, 53, query);

    let expected = hex::decode("45000039000100004011a8a1c000020208080808303900350025e8ea44cb01000001000000000000076578616d706c6503636f6d0000010001")?;
    eprintln!("packet\n {:02x?}\n", packet);
    eprintln!("expected\n {:02x?}\n", expected);
    // assert_eq!(packet, expected);
    tun.write_all(&packet).context("tun write_all")?;
    tun.flush().context("tun flush")?;

    // Get a response.
    let mut buf = [0u8; 1024];
    let n = tun.read(&mut buf).context("tun read")?;
    eprintln!("resp {n} {:02x?}", &buf[..n]);
    // assert_eq!(n, 32);
    let ipv4_resp = Ipv4::from_bytes(&buf[..20]);
    let udp = UdpHeader::from_bytes(&buf[20..28]);
    let contents = &buf[28..32];
    dbg!(ipv4_resp, udp);
    eprintln!("contents {contents:02x?}");

    Ok(())
}

#[allow(unused)]
fn send_ping(tun: &mut File) -> Result<()> {
    // Send a ping.
    let ping = IcmpEcho::ping(0);
    let dst = Ipv4Addr::new(192, 0, 2, 1);
    let ipv4_header = Ipv4::new(mem::size_of::<IcmpEcho>() as u16, PROTO_ICMP, dst);
    let packet = ipv4_header.concat(&ping);
    tun.write_all(&packet)?;
    tun.flush()?;

    // Get a response.
    let mut buf = [0u8; 1024];
    let n = tun.read(&mut buf)?;
    assert_eq!(n, 28);
    let ipv4_resp = Ipv4::from_bytes(&buf[..20]);
    let icmp_resp = IcmpEcho::from_bytes(&buf[20..28]);
    dbg!(ipv4_resp, icmp_resp);

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
        let packet = ipv4_header.concat(&ping);
        assert_eq!(packet.len(), 28);

        // Deserialize.
        let ipv4_resp = Ipv4::from_bytes(&packet[..20]);
        let icmp_resp = IcmpEcho::from_bytes(&packet[20..28]);
        assert_eq!(ipv4_resp, ipv4_header);
        assert_eq!(icmp_resp, ping);
    }
}
