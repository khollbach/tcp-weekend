use std::{fmt, mem};

use simple_endian::u16be;

use crate::checksum::Checksummable;

#[repr(C)]
#[derive(PartialEq, Eq)]
pub struct IcmpEcho {
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
    pub fn ping(seq: u16) -> Self {
        Self {
            type_: 8,
            code: 0,
            checksum: 0.into(),
            id: 12345.into(),
            seq: seq.into(),
        }
        .apply_checksum()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 8);
        unsafe { mem::transmute::<[u8; 8], Self>(bytes.try_into().unwrap()) }
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
    fn make_ping() {
        let ping = IcmpEcho::ping(1);
        let expected = b"\x08\x00\xc7\xc509\x00\x01";
        assert_eq!(ping.as_bytes(), expected);
    }
}
