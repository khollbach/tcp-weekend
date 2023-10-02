use core::{fmt, slice};
use simple_endian::*;
use std::{
    fs::File,
    io::{self, prelude::*},
    mem::{self, transmute},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    time::Duration,
};

use timeout_readwrite::TimeoutReader;

fn main() -> io::Result<()> {
    let mut tun = open_tun("tun0")?;

    // let syn = b"E\x00\x00,\x00\x01\x00\x00@\x06\x00\xc4\xc0\x00\x02\x02\"\xc2\x95Cx\x0c\x00P\xf4p\x98\x8b\x00\x00\x00\x00`\x02\xff\xff\x18\xc6\x00\x00\x02\x04\x05\xb4";
    // // dbg!(syn.len());
    // // write!(tun, "{syn}")?;
    // tun.write_all(syn)?;
    // tun.flush()?;

    // dbg!("write successful; about to read");

    // let mut ack = vec![];
    // tun.read_to_end(&mut ack)?;

    // Handle: Write
    // &mut Handle: Write

    // Step 1.2 -- clean up 'old' data.
    let mut buf = [0u8; 1024];
    let mut tun_reader = TimeoutReader::new(tun.try_clone()?, Duration::from_secs(1));
    let mut i = 0;
    while let Ok(n) = tun_reader.read(&mut buf) {
        dbg!("read", i, n);
        eprintln!("{:?}", &buf[..n]);
        i += 1;
    }

    // dbg!(size_of::<Ipv4>());

    // let ip = Ipv4::new(100, 1, Ipv4Addr::new(127, 0, 0, 1)); // ?
    // dbg!(ip);

    // ----

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

const LINUX_TUNSETIFF: u64 = 0x400454CA;

fn open_tun(tun_name: &str) -> io::Result<File> {
    let tun = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let flags = libc::IFF_TUN | libc::IFF_NO_PI;

    // 16 bytes (fill in the prefix with the filename) then 2byte flag then 22 bytes NUL
    let mut ifs = vec![];
    ifs.extend(tun_name.as_bytes());
    ifs.extend(vec![0; 16 - tun_name.len()]);
    ifs.extend(flags.to_le_bytes());
    ifs.extend(vec![0; 22]);

    let ret = unsafe { libc::ioctl(tun.as_raw_fd(), LINUX_TUNSETIFF, ifs.as_ptr(), ifs.len()) };
    if ret != 0 {
        panic!("ioctl non-zero ret: {ret}");
    }

    Ok(tun)
}

/// Packet header.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Ipv4 {
    vers_ihl: u8,
    tos: u8,
    total_length: u16be, // 201
    id: u16be,
    frag_off: u16be,
    ttl: u8,
    protocol: u8,
    checksum: u16be,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4")
            .field("vers_ihl", &self.vers_ihl)
            .field("tos", &self.tos)
            .field("total_length", &self.total_length.to_native())
            .field("id", &self.id.to_native())
            .field("frag_off", &self.frag_off.to_native())
            .field("ttl", &self.ttl)
            .field("protocol", &self.protocol)
            .field("checksum", &self.checksum.to_native())
            .field("src", &self.src)
            .field("dst", &self.dst)
            .finish()
    }
}

impl Ipv4 {
    fn new(contents_len: u16, protocol: u8, dst: Ipv4Addr) -> Self {
        let src = Ipv4Addr::new(192, 0, 2, 2);
        Self {
            vers_ihl: 0x45,
            tos: 0,
            total_length: (20 + contents_len).into(),
            id: 1.into(),
            frag_off: 0.into(),
            ttl: 64,
            protocol,
            checksum: 0.into(),
            src,
            dst,
        }
        .apply_checksum()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 20);
        unsafe { transmute::<[u8; 20], Self>(bytes[..20].try_into().unwrap()) }
    }
}

impl Checksummable for Ipv4 {
    fn set_checksum(&mut self, checksum: u16be) {
        self.checksum = checksum;
    }
}

trait Checksummable: Sized {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            let ptr = self as *const Self as *const u8;
            slice::from_raw_parts(ptr, mem::size_of::<Self>())
        }
    }

    fn set_checksum(&mut self, checksum: u16be);

    fn apply_checksum(mut self) -> Self {
        self.set_checksum(0.into());
        self.set_checksum(checksum(self.as_bytes()).into());
        debug_assert_eq!(checksum(self.as_bytes()), 0);
        self
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut result: u16 = 0;

    for part in bytes.chunks(2) {
        // Pad the odd byte at the end, if any.
        let part: u16 = if part.len() == 1 {
            (part[0] as u16) << 8
        } else {
            u16::from_be_bytes(part.try_into().unwrap())
        }
        .into();

        let (sum, carry) = result.overflowing_add(part);
        result = sum + (carry as u16);

        // let result_u16: u16 = result.into();
        // let (sum, carry) = result_u16.overflowing_add(part.to_native());
        // result = (sum + (carry as u16)).into();

        // let result_u16: u16 = result.into();
        // result = result_u16.wrapping_add(part.into()).into();
    }

    !result
}

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
        assert!(bytes.len() >= 8);
        unsafe { transmute::<[u8; 8], Self>(bytes[..8].try_into().unwrap()) }
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
