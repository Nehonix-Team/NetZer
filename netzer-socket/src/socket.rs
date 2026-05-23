use std::ffi::CString;
use std::io;

pub struct RawSocket {
    fd: i32,
}

impl RawSocket {
    pub fn new(interface_name: &str) -> io::Result<Self> {
        unsafe {
            // AF_PACKET (17) / SOCK_RAW (3) / ETH_P_ALL (0x0003 in network byte order -> 0x0300)
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0x0300);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Get interface index (SIOCGIFINDEX)
            let c_ifname = CString::new(interface_name)?;
            
            #[repr(C)]
            struct ifreq {
                ifr_name: [libc::c_char; libc::IFNAMSIZ],
                ifr_ifru: libc::c_int,
            }
            
            let mut ifr: ifreq = std::mem::zeroed();
            let name_bytes = c_ifname.as_bytes_with_nul();
            if name_bytes.len() > libc::IFNAMSIZ {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Interface name too long"));
            }
            
            for i in 0..name_bytes.len() {
                ifr.ifr_name[i] = name_bytes[i] as libc::c_char;
            }

            if libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifr) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // Bind socket to the interface
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = 0x0300; // ETH_P_ALL
            sll.sll_ifindex = ifr.ifr_ifru;

            if libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            ) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            Ok(Self { fd })
        }
    }

    pub fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let res = libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            );
            
            if res < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(res as usize)
            }
        }
    }

    pub fn attach_filter_port(&self, port: u16) -> io::Result<()> {
        let mut filter = vec![
            libc::sock_filter { code: 0x28, jt: 0, jf: 8, k: 12 },
            libc::sock_filter { code: 0x15, jt: 0, jf: 8, k: 0x0800 },
            libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 23 },
            libc::sock_filter { code: 0x15, jt: 1, jf: 0, k: 6 },
            libc::sock_filter { code: 0x15, jt: 0, jf: 5, k: 17 },
            libc::sock_filter { code: 0xb1, jt: 0, jf: 0, k: 14 },
            libc::sock_filter { code: 0x48, jt: 0, jf: 0, k: 14 },
            libc::sock_filter { code: 0x15, jt: 2, jf: 0, k: port as u32 },
            libc::sock_filter { code: 0x48, jt: 0, jf: 0, k: 16 },
            libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: port as u32 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
        ];

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };

        unsafe {
            let ret = libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn attach_filter_proto(&self, proto: &str) -> io::Result<()> {
        let mut filter = match proto.to_lowercase().as_str() {
            "tcp" => vec![
                libc::sock_filter { code: 0x28, jt: 0, jf: 3, k: 12 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 2, k: 0x0800 },
                libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 23 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 6 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
            ],
            "udp" => vec![
                libc::sock_filter { code: 0x28, jt: 0, jf: 3, k: 12 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 2, k: 0x0800 },
                libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 23 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 17 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
            ],
            "icmp" => vec![
                libc::sock_filter { code: 0x28, jt: 0, jf: 3, k: 12 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 2, k: 0x0800 },
                libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 23 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 1 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
            ],
            "arp" => vec![
                libc::sock_filter { code: 0x28, jt: 0, jf: 1, k: 12 },
                libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 0x0806 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
                libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
            ],
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported protocol for BPF")),
        };

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };

        unsafe {
            let ret = libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub fn drop_privileges() -> io::Result<()> {
    unsafe {
        let current_uid = libc::getuid();
        if current_uid != 0 {
            return Ok(());
        }

        let sudo_uid_str = std::env::var("SUDO_UID").ok();
        let sudo_gid_str = std::env::var("SUDO_GID").ok();

        if let (Some(uid_str), Some(gid_str)) = (sudo_uid_str, sudo_gid_str) {
            let uid: libc::uid_t = uid_str.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Failed to parse SUDO_UID")
            })?;
            let gid: libc::gid_t = gid_str.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Failed to parse SUDO_GID")
            })?;

            if libc::setgid(gid) < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::setuid(uid) < 0 {
                return Err(io::Error::last_os_error());
            }

            println!(" [SECURITY] Privilege Dropping: Swapped from root to UID={}, GID={}", uid, gid);
        } else {
            let nobody_uid: libc::uid_t = 65534;
            let nobody_gid: libc::gid_t = 65534;

            if libc::setgid(nobody_gid) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(nobody_uid) < 0 {
                return Err(io::Error::last_os_error());
            }
            println!(" [SECURITY] Privilege Dropping: Swapped from root to 'nobody' (UID={}, GID={})", nobody_uid, nobody_gid);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TPACKET_V3 Ring Buffer
// ---------------------------------------------------------------------------
// Linux constants not exposed by libc
const PACKET_VERSION: libc::c_int = 10;
const PACKET_RX_RING: libc::c_int = 5;
const TPACKET_V3: libc::c_int = 2;
const TP_STATUS_USER: u32 = 1;
const TP_STATUS_KERNEL: u32 = 0;

// Ring buffer geometry — tunable
const BLOCK_SIZE: usize = 1 << 22; // 4 MiB per block
const BLOCK_NR: usize = 8;         // 8 blocks = 32 MiB total ring
const FRAME_SIZE: usize = 1 << 11; // 2048 bytes per frame
const BLOCK_TIMEOUT_MS: u32 = 10;  // retire block every 10 ms

// TPACKET_V3 kernel structures (manual repr(C) layout, must match <linux/if_packet.h>)
#[repr(C)]
struct TpacketReq3 {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
    tp_retire_blk_tov: libc::c_uint,
    tp_sizeof_priv: libc::c_uint,
    tp_feature_req_word: libc::c_uint,
}

#[repr(C)]
struct TpacketBdTs {
    ts_sec: libc::c_uint,
    ts_usec_or_nsec: libc::c_uint,
}

#[repr(C)]
struct TpacketBlockDesc {
    version: libc::c_uint,
    offset_to_priv: libc::c_uint,
    hdr: TpacketBdHeader,
}

#[repr(C)]
struct TpacketBdHeader {
    block_status: libc::c_uint,
    num_pkts: libc::c_uint,
    offset_to_first_pkt: libc::c_uint,
    blk_len: libc::c_uint,
    seq_num: u64,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: libc::c_uint,
    tp_sec: libc::c_uint,
    tp_nsec: libc::c_uint,
    tp_snaplen: libc::c_uint,
    tp_len: libc::c_uint,
    tp_status: libc::c_uint,
    tp_mac: libc::c_ushort,
    tp_net: libc::c_ushort,
    // hv1 union — 12 bytes
    tp_vlan_tci: libc::c_ushort,
    tp_vlan_tpid: libc::c_ushort,
    _padding: [u8; 8],
}

pub struct RingSocket {
    fd: i32,
    ring_ptr: *mut u8,
    ring_size: usize,
    current_block: usize,
}

// Safety: RingSocket is only used from a single thread in our capture loop.
unsafe impl Send for RingSocket {}

impl RingSocket {
    pub fn new(interface_name: &str) -> io::Result<Self> {
        unsafe {
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0x0300);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Enable TPACKET_V3
            let version: libc::c_int = TPACKET_V3;
            if libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            ) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // Configure the ring buffer geometry
            let frame_nr = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;
            let req3 = TpacketReq3 {
                tp_block_size: BLOCK_SIZE as libc::c_uint,
                tp_block_nr: BLOCK_NR as libc::c_uint,
                tp_frame_size: FRAME_SIZE as libc::c_uint,
                tp_frame_nr: frame_nr as libc::c_uint,
                tp_retire_blk_tov: BLOCK_TIMEOUT_MS,
                tp_sizeof_priv: 0,
                tp_feature_req_word: 0,
            };

            if libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_RX_RING,
                &req3 as *const _ as *const libc::c_void,
                std::mem::size_of::<TpacketReq3>() as u32,
            ) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // mmap the ring buffer into user space
            let ring_size = BLOCK_SIZE * BLOCK_NR;
            let ring_ptr = libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED,
                fd,
                0,
            );

            if ring_ptr == libc::MAP_FAILED {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // Bind to interface
            let c_ifname = CString::new(interface_name)?;

            #[repr(C)]
            struct ifreq {
                ifr_name: [libc::c_char; libc::IFNAMSIZ],
                ifr_ifru: libc::c_int,
            }

            let mut ifr: ifreq = std::mem::zeroed();
            let name_bytes = c_ifname.as_bytes_with_nul();
            for i in 0..name_bytes.len().min(libc::IFNAMSIZ) {
                ifr.ifr_name[i] = name_bytes[i] as libc::c_char;
            }
            libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifr);

            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = 0x0300;
            sll.sll_ifindex = ifr.ifr_ifru;

            if libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            ) < 0 {
                let err = io::Error::last_os_error();
                libc::munmap(ring_ptr, ring_size);
                libc::close(fd);
                return Err(err);
            }

            Ok(Self {
                fd,
                ring_ptr: ring_ptr as *mut u8,
                ring_size,
                current_block: 0,
            })
        }
    }

    /// Iterate all ready frames in the next available ring block.
    /// Calls `callback` for each raw Ethernet frame — zero syscalls per packet.
    /// Blocks via `poll()` when no block is ready yet.
    pub fn recv_block(&mut self, mut callback: impl FnMut(&[u8])) -> io::Result<()> {
        unsafe {
            // Pointer to the current block descriptor
            let block_base = self.ring_ptr.add(self.current_block * BLOCK_SIZE);
            let block_desc = block_base as *mut TpacketBlockDesc;

            // Poll until the kernel retires the block (status flips to TP_STATUS_USER)
            loop {
                let status = std::ptr::read_volatile(&(*block_desc).hdr.block_status);
                if status & TP_STATUS_USER != 0 {
                    break;
                }

                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN | libc::POLLERR,
                    revents: 0,
                };

                let ret = libc::poll(&mut pfd, 1, BLOCK_TIMEOUT_MS as i32 * 2);
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            let num_pkts = (*block_desc).hdr.num_pkts;
            let mut pkt_offset = (*block_desc).hdr.offset_to_first_pkt as usize;

            for _ in 0..num_pkts {
                if pkt_offset + std::mem::size_of::<Tpacket3Hdr>() > BLOCK_SIZE {
                    break;
                }

                let pkt_hdr = block_base.add(pkt_offset) as *const Tpacket3Hdr;
                let snaplen = (*pkt_hdr).tp_snaplen as usize;
                let mac_offset = (*pkt_hdr).tp_mac as usize;

                if pkt_offset + mac_offset + snaplen <= BLOCK_SIZE && snaplen > 0 {
                    let frame_data = std::slice::from_raw_parts(
                        block_base.add(pkt_offset + mac_offset),
                        snaplen,
                    );
                    callback(frame_data);
                }

                let next = (*pkt_hdr).tp_next_offset as usize;
                if next == 0 {
                    break;
                }
                pkt_offset += next;
            }

            // Release block back to the kernel
            std::ptr::write_volatile(&mut (*block_desc).hdr.block_status, TP_STATUS_KERNEL);

            self.current_block = (self.current_block + 1) % BLOCK_NR;
        }

        Ok(())
    }
}

impl Drop for RingSocket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring_ptr as *mut libc::c_void, self.ring_size);
            libc::close(self.fd);
        }
    }
}
