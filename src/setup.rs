use std::{fs::File, io, os::fd::AsRawFd};

const LINUX_TUNSETIFF: u64 = 0x400454CA;

pub fn open_tun(tun_name: &str) -> io::Result<File> {
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
