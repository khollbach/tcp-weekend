use std::{mem, slice};

use simple_endian::u16be;

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];

    fn concat<T>(&self, other: &T) -> Vec<u8>
    where
        T: AsBytes + ?Sized,
    {
        self.as_bytes()
            .iter()
            .chain(other.as_bytes())
            .copied()
            .collect()
    }
}

impl<T> AsBytes for T
where
    T: Sized,
{
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            let ptr = self as *const Self as *const u8;
            slice::from_raw_parts(ptr, mem::size_of::<Self>())
        }
    }
}

impl AsBytes for [u8] {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

pub trait Checksummable: AsBytes + Sized {
    fn set_checksum(&mut self, checksum: u16be);

    fn apply_checksum(mut self) -> Self {
        self.set_checksum(0.into());
        self.set_checksum(checksum(self.as_bytes()).into());
        debug_assert_eq!(checksum(self.as_bytes()), 0);
        self
    }
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut result: u16 = 0;

    for part in bytes.chunks(2) {
        // Pad the odd byte at the end, if any.
        let part: u16 = if part.len() == 1 {
            (part[0] as u16) << 8
        } else {
            u16::from_be_bytes(part.try_into().unwrap())
        };

        let (sum, carry) = result.overflowing_add(part);
        result = sum + (carry as u16);
    }

    !result
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    #[test_case(b"11aabbccddee123412341234", 7678)]
    #[test_case(b"01", 0xfeff)]
    #[test_case(b"0001", 0xfffe)]
    #[test_case(b"00010001", 0xfffd)]
    #[test_case(b"11aabbccddee1234123412341dfe", 0)]
    fn checksum(data: &[u8], expected: u16) {
        let data = hex::decode(data).unwrap();
        assert_eq!(super::checksum(&data), expected);
    }
}
