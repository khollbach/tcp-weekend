use std::{fmt::Debug, mem, net::Ipv4Addr};

use simple_endian::u16be;

use crate::{
    checksum::{checksum, AsBytes},
    ipv4::Ipv4,
    PROTO_UDP,
};

#[repr(C)]
pub struct UdpHeader {
    src_port: u16be,
    dst_port: u16be,
    length: u16be,
    checksum: u16be,
}

impl Debug for UdpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHeader")
            .field("src_port", &self.src_port.to_native())
            .field("dst_port", &self.dst_port.to_native())
            .field("length", &self.length.to_native())
            .field("checksum", &self.checksum.to_native())
            .finish()
    }
}

impl UdpHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 8);
        unsafe { mem::transmute::<[u8; 8], Self>(bytes.try_into().unwrap()) }
    }
}

pub fn new_udp_packet(dst: Ipv4Addr, src_port: u16, dst_port: u16, contents: &[u8]) -> Vec<u8> {
    let mut udp = UdpHeader {
        src_port: src_port.into(),
        dst_port: dst_port.into(),
        length: ((contents.len() + mem::size_of::<UdpHeader>()) as u16).into(),
        checksum: 0.into(),
    };
    let ipv4 = Ipv4::new(udp.length.into(), PROTO_UDP, dst);
    udp.checksum = pseudoheader_checksum(ipv4, &udp.concat(contents));

    ipv4.concat(&udp).as_slice().concat(contents) // !!! Vec -> AsBytes = scary
}

#[repr(C)]
struct UdpPseudoheader {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    zero: u8,
    proto: u8,
    length: u16be,
}

fn pseudoheader_checksum(ipv4: Ipv4, udp_contents: &[u8]) -> u16be {
    let pheader = UdpPseudoheader {
        src: ipv4.src,
        dst: ipv4.dst,
        zero: 0u8,
        proto: ipv4.protocol,
        length: (udp_contents.len() as u16).into(),
    };
    let bytes = pheader.concat(udp_contents);
    checksum(&bytes).into()
}
