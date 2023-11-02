use std::mem;

use bitflags::bitflags;
use simple_endian::{u16be, u32be};

use crate::checksum::AsBytes;

bitflags! {
    pub struct Flags: u8 {
        const FIN = 1;
        const SYN = 2;
        const RST = 4;
        const PSH = 8;
        const ACK = 16;
    }
}

#[repr(C)]
pub struct TcpHeader {
    src_port: u16be,
    dst_port: u16be,
    seq: u32be,
    ack: u32be,
    offset: u8,
    flags: u8,
    window: u16be,
    checksum: u16be,
    urgent: u16be,
}

pub struct TcpPacket {
    header: TcpHeader,
    options: Vec<u8>,
    data: Vec<u8>,
}

impl TcpPacket {
    fn new(flags: u8, src_port: u16, dst_port: u16, seq: u32, ack: u32, data: Vec<u8>) -> Self {
        let opt_mss = 2;
        let mss: u16 = 1460;

        let options = if flags == Flags::SYN.bits() {
            let mss_bytes = mss.to_be_bytes();
            vec![opt_mss, 4, mss_bytes[0], mss_bytes[1]]
        } else {
            vec![]
        };


        let offset = (mem::size_of::<TcpHeader>() + (options.len() / 4 << 4)) as u8;
        Self {
            header: TcpHeader {
                src_port: src_port.into(),
                dst_port: dst_port.into(),
                seq: seq.into(),
                ack: ack.into(),
                offset,
                flags,
                window: u16::MAX.into(),
                checksum: 0.into(),
                urgent: 0.into(),
            },
            options,
            data,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        assert_eq!(self.header.offset as usize, self.options.len() / 4 << 4);

        let mut out = vec![];
        out.extend(self.header.as_bytes());
        out.extend(&self.options);
        out.extend(&self.data);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let header_bytes = bytes[..20].try_into().unwrap();
        let header = unsafe { mem::transmute::<[u8; 20], TcpHeader>(header_bytes) };

        let offset = (header.offset >> 4 * 4) as usize;

        let options = bytes[20..offset].to_vec();
        let data = bytes[offset..].to_vec();

        // (could check the checksum here)

        Self {
            header,
            options,
            data,
        }
    }
}

// struct Offset(priv u8)
// impl
//     pub into() -> usize
//     pub from() -> usize
