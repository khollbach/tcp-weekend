mod setup;
mod checksum;
mod ipv4;

use core::fmt;
use checksum::Checksummable;
use simple_endian::*;
use std::{
    io::{self, prelude::*},
    mem::{self, transmute},
    net::Ipv4Addr,
    time::Duration,
};

use timeout_readwrite::TimeoutReader;

use crate::{setup::open_tun, ipv4::Ipv4};

fn main() -> io::Result<()> {
    let mut tun = open_tun("tun0")?;

    // let syn = b"E\x00\x00,\x00\x01\x00\x00@\x06\x00\xc4\xc0\x00\x02\x02\"\xc2\x95Cx\x0c\x00P\xf4p\x98\x8b\x00\x00\x00\x00`\x02\xff\xff\x18\xc6\x00\x00\x02\x04\x05\xb4";
    // tun.write_all(syn)?;
    // tun.flush()?;

    // let mut ack = [0u8; 1024];
    // let n = tun.read(&mut ack)?;
    // eprintln!("{:02x?}", &ack[..n]);

    // Step 1.2 -- clean up 'old' data.
    let mut buf = [0u8; 1024];
    let mut tun_reader = TimeoutReader::new(tun.try_clone()?, Duration::from_millis(100));
    while let Ok(n) = tun_reader.read(&mut buf) {
        eprintln!("read {:02x?}", &buf[..n]);
    }

    let ping = IcmpEcho::ping(0);
    let dst = Ipv4Addr::new(192, 0, 2, 2);
    let ipv4_header = Ipv4::new(mem::size_of::<IcmpEcho>() as u16, PROTO_ICMP, dst);
    dbg!(ipv4_header, &ping);

    let packet: Vec<u8> = ipv4_header
        .as_bytes()
        .iter()
        .chain(ping.as_bytes().iter()) // Iterator<&u8>
        .copied() // Iterator<&T> -> Iterator<T>  (where T: Copy)
        .collect(); // Vec<u8>

    // for b in &packet {
    //     println!("{b}");
    // }
    // panic!();

    dbg!();

    tun.write_all(&packet)?;
    tun.flush()?;

    dbg!();

    let mut buf = [0u8; 1024];
    let n = tun.read(&mut buf)?;
    assert!(n >= 28);

    dbg!(n); // 28 ?

    let ipv4_resp = Ipv4::from_bytes(&buf[..20]);
    let icmp_resp = IcmpEcho::from_bytes(&buf[20..28]);
    dbg!(ipv4_resp, icmp_resp);

    dbg!();

    // dbg!(&buf[28..n]);
    let mut i = 0;
    while let Ok(n) = tun_reader.read(&mut buf) {
        dbg!("read (after)", i, n);
        eprintln!("{:?}", &buf[..n]);
        i += 1;
    }

    Ok(())
}

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

#[repr(C)]
#[derive(PartialEq, Eq)]
struct IcmpEcho {
    type_: u8,
    code: u8,
    checksum: u16be,
    id: u16be,
    seq: u16be,
}

impl fmt::Debug for IcmpEcho {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcmpEcho")
            .field("type_", &self.type_)
            .field("code", &self.code)
            .field("checksum", &self.checksum.to_native())
            .field("id", &self.id.to_native())
            .field("seq", &self.seq.to_native())
            .finish()
    }
}

impl IcmpEcho {
    fn ping(seq: u16) -> Self {
        Self {
            type_: 8,
            code: 0,
            checksum: 0.into(),
            id: 12345.into(),
            seq: seq.into(),
        }
        .apply_checksum()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 8);
        unsafe { transmute::<[u8; 8], Self>(bytes.try_into().unwrap()) }
    }
}

impl Checksummable for IcmpEcho {
    fn set_checksum(&mut self, checksum: u16be) {
        self.checksum = checksum;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_round_trip_bytes() {
        let ping = IcmpEcho::ping(1);
        let dst = Ipv4Addr::new(192, 0, 2, 1);
        let ipv4_header = Ipv4::new(mem::size_of::<IcmpEcho>() as u16, PROTO_ICMP, dst);

        let packet: Vec<u8> = ipv4_header
            .as_bytes()
            .iter()
            .chain(ping.as_bytes().iter())
            .copied()
            .collect();
        let ipv4_resp = Ipv4::from_bytes(&packet[..20]);
        let icmp_resp = IcmpEcho::from_bytes(&packet[20..28]);

        assert_eq!(ipv4_resp, ipv4_header);
        assert_eq!(icmp_resp, ping);
    }
}
