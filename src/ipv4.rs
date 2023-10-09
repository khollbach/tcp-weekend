use std::{fmt, mem, net::Ipv4Addr};

use simple_endian::u16be;

use crate::checksum::Checksummable;

/// Packet header.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ipv4 {
    vers_ihl: u8,
    tos: u8,
    total_length: u16be,
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
    pub fn new(contents_len: u16, protocol: u8, dst: Ipv4Addr) -> Self {
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

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 20);
        unsafe { mem::transmute::<[u8; 20], Self>(bytes.try_into().unwrap()) }
    }
}

impl Checksummable for Ipv4 {
    fn set_checksum(&mut self, checksum: u16be) {
        self.checksum = checksum;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_to_bytes() {
        let ipv4 = Ipv4 {
            vers_ihl: 4 << 4 | 5,
            tos: 0,
            total_length: 28.into(),
            id: 1.into(),
            frag_off: 0.into(),
            ttl: 16,
            protocol: 6,
            checksum: 0.into(),
            src: [192, 168, 0, 1].into(),
            dst: [8, 8, 8, 8].into(),
        };
        let expected =
            b"E\x00\x00\x1c\x00\x01\x00\x00\x10\x06\x00\x00\xc0\xa8\x00\x01\x08\x08\x08\x08";
        assert_eq!(ipv4.as_bytes(), expected);
    }
}
