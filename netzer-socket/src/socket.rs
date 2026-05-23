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

