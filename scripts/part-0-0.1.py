#!/usr/bin/python3

import struct
from fcntl import ioctl
import os

def openTun(tunName):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA  # 8 hex chars  --   4 bytes
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = struct.pack("16sH22s", tunName, flags, b"")
    // tun0___________400454...
    // ^0             ^16
    print(ifs[:16])
    print(ifs[16:])
    ioctl(tun, LINUX_TUNSETIFF, ifs)
    return tun

tun = openTun(b"tun0")

syn = b'E\x00\x00,\x00\x01\x00\x00@\x06\x00\xc4\xc0\x00\x02\x02"\xc2\x95Cx\x0c\x00P\xf4p\x98\x8b\x00\x00\x00\x00`\x02\xff\xff\x18\xc6\x00\x00\x02\x04\x05\xb4'
tun.write(syn)
reply = tun.read(1024)
#print(reply)
import sys
sys.stdout.buffer.write(reply)

# TODO: translate (or find equivalent library function) in Rust ?
from select import select
# timeout is in milliseconds
def read_with_timeout(tun, n_bytes, timeout):
    reads, _, _ = select([tun], [], [], timeout/1000.0)
    if len(reads) == 0:
        raise TimeoutError("Timed out")
    return tun.read(n_bytes)


