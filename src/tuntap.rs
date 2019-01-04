use std::path::Path;
use std::default::Default;
use std::fs::OpenOptions;
use std::os::unix::prelude::AsRawFd;
use std::os::unix::io::RawFd;
use std::io::Result as IoResult;
use std::io::Error as IoError;

use libc::write;
use libc::socket;
use libc::{AF_INET, AF_INET6, SOCK_DGRAM, IFNAMSIZ};
use libc::c_void;
use libc::{c_char,c_ushort,c_int};
use libc::{in_addr,in6_addr};
use nix::sys::socket::{sockaddr_in,sockaddr};
use futures::sync::mpsc::Receiver;
use futures::sync::mpsc::Sender;
use tokio::prelude::*;
use tokio::fs::File;

#[repr(C)]
struct InterfaceRequest16 {
	name: [u8; IFNAMSIZ],
	flags: c_ushort,
}

#[repr(C)]
struct InterfaceRequest32 {
	name: [u8; IFNAMSIZ],
	flags: c_int,
}

#[repr(C)]
struct InterfaceRequestSockaddrIn {
	name: [u8; IFNAMSIZ],
	sockaddr: sockaddr_in,
}

#[repr(C)]
struct InterfaceRequestSockaddr {
	name: [u8; IFNAMSIZ],
	sockaddr: sockaddr,
}

#[repr(C)]
struct InterfaceRequestIn6 {
	addr:      in6_addr,
	prefixlen: u32,
	ifindex:   c_int,
}

impl Default for InterfaceRequest16 {
	fn default() -> InterfaceRequest16 {
		InterfaceRequest16 {
			name: [0; IFNAMSIZ],
			flags: 0,
		}		
	}
}

impl Default for InterfaceRequest32 {
	fn default() -> InterfaceRequest32 {
		InterfaceRequest32 {
			name: [0; IFNAMSIZ],
			flags: 0,
		}		
	}
}

impl Default for InterfaceRequestSockaddrIn {
	fn default() -> InterfaceRequestSockaddrIn {
		InterfaceRequestSockaddrIn {
			name: [0; IFNAMSIZ],
			sockaddr: sockaddr_in {
				sin_family: 0,
				sin_port:   0,
				sin_addr:   in_addr {
					s_addr: 0
				},
				sin_zero:   [0;8],
			}
		}		
	}
}

impl Default for InterfaceRequestSockaddr {
	fn default() -> InterfaceRequestSockaddr {
		InterfaceRequestSockaddr {
			name: [0; IFNAMSIZ],
			sockaddr: sockaddr {
				sa_family: 0,
				sa_data:   [0;14]
			}
		}		
	}
}

type Uid = u32;
type Gid = u32;

extern "C" {
	//fn ioctl(fd: i32, icr: IoCtlRequest, some: c_ulong) -> i32;
	fn inet_pton(af: c_int, src: *const c_char, dst: &mut libc::in_addr) -> c_int;
}

bitflags! {
	pub struct TunTapFlags: u16 {
		const IFF_UP        = 1<<0;
		const IFF_RUNNING   = 1<<6;
		const IFF_TUN       = 0x0001;
		const IFF_TAP       = 0x0002;
		const IFF_NO_PI     = 0x0100;
		const IFF_ONE_QUEUE = 0x0200;
		const IFF_VNET_HDR  = 0x0400;
		const IFF_TUN_EXCL  = 0x0800;
	}
}

bitflags! {
	#[repr(C)]
	struct IoCtlRequest: u64 {
		const TUNSETIFF      = 0x400454ca;
		const TUNSETOWNER    = 0x400454cc;
		const TUNSETGROUP    = 0x400454ce;

		const SIOCGIFFLAGS   = 0x8913;
		const SIOCSIFFLAGS   = 0x8914;
		const SIOCSIFADDR    = 0x8916;
		const SIOCSIFMTU     = 0x8922;
		const SIOCSIFNAME    = 0x8923;
		const SIOCSIFHWADDR  = 0x8924;
		const SIOCGIFINDEX   = 0x8933;
		const SIOGIFINDEX    = 0x8933; // same as SIOCGIFINDEX
	}
}

pub struct TunTap {
	fd:    RawFd,
	sock4: c_int,
	sock6: c_int,
	name: [u8; IFNAMSIZ],
}

macro_rules! ioctl(
	($fd:expr, $flags:expr, $value:expr) => ({
		//let ptr = ::std::mem::transmute($value);
		let res = libc::ioctl($fd, $flags.bits(), $value);

		if res < 0 {
			Err(IoError::last_os_error())
		} else {
			Ok(())
		}
	})
);

impl TunTap {
	pub async fn new(flags: TunTapFlags)
		-> IoResult<(TunTap,(Sender<Vec<u8>>, Receiver<Vec<u8>>))>
	{
		let p = Path::new("/dev/net/tun");
		let file = OpenOptions::new().write(true)
							.read(true)
							.open(p)?;
		let fd = file.as_raw_fd();
		let mut file = File::from_std(file);

		let ifr_create = InterfaceRequest16 {
			flags: flags.bits(),
			..Default::default()
		};
		unsafe { ioctl!(fd, IoCtlRequest::TUNSETIFF, &ifr_create) }?;

		const IPPROTO_IP: c_int = 0;
		let sock4 = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) };
		if sock4 < 0 {
			return Err(IoError::last_os_error())
		}

		let sock6 = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
		if sock6 < 0 {
			return Err(IoError::last_os_error())
		}

		let tuntap = TunTap {
			fd: fd,
			sock4: sock4,
			sock6: sock6,
			name: ifr_create.name,
		};

		let (your_tx, mut my_rx): (Sender<Vec<u8>>,_) = futures::sync::mpsc::channel(128 * 1024);
		let (mut my_tx, your_rx): (Sender<Vec<u8>>,_) = futures::sync::mpsc::channel(128 * 1024);

		tokio::spawn_async(async move {
			while let Some(Ok(packet)) = await!(my_rx.next()) {
				let ptr = packet.as_slice().as_ptr();
				unsafe {
					write(fd, ptr as *const c_void, packet.len() as usize);
				}
			}
		});

		tokio::spawn_async(async move {
			let mut buf = [0; 2048];
			loop {
				match await!(file.read_async(&mut buf)) {
					Ok(n) => await!(my_tx.send_async(buf[..n].to_vec())).unwrap(),
					_ => break
				};
			}
		});

		Ok((tuntap,(your_tx,your_rx)))
	}

	pub fn set_owner(&mut self, owner: Uid) -> IoResult<()> {
		unsafe { ioctl!(self.fd, IoCtlRequest::TUNSETOWNER, owner as u64) }
	}

	pub fn set_group(&mut self, group: Gid) -> IoResult<()> {
		unsafe { ioctl!(self.fd, IoCtlRequest::TUNSETGROUP, group as u64) }
	}

	pub fn set_mtu(&mut self, mtu: i32) -> IoResult<()> {
		let ifr = InterfaceRequest32 {
			name: self.name,
			flags: mtu,
		};
		unsafe { ioctl!(self.sock4, IoCtlRequest::SIOCSIFMTU, &ifr) }
	}

	/*
	pub fn set_mac(self, mac: [u8;6]) -> IoResult<()> {
		// only works on TAPs!
		// but still fails - why? TODO
		let mut ifr = InterfaceRequestSockaddr {
			name: self.name,
			..Default::default()
		};
		ifr.sockaddr.sa_family = AF_INET as c_ushort;
		for (i, b) in mac.iter().enumerate() {
			ifr.sockaddr.sa_data[i] = *b;
		}
		unsafe { ioctl!(self.sock4, SIOCSIFHWADDR, &ifr) }
	}*/
/*
	pub fn set_ipv4(self, ipv4: &'static str) -> IoResult<()> {
		let mut ifr_ipaddr = InterfaceRequestSockaddrIn {
			name:     self.name,
			..Default::default()
		};
		ifr_ipaddr.sockaddr.sin_family = AF_INET as c_ushort;
		let ip = ::std::ffi::CString::new(ipv4.as_bytes()).unwrap();
		let res = unsafe { inet_pton(AF_INET, ip.as_ptr(),
								&mut ifr_ipaddr.sockaddr.sin_addr) == 1 };
		if !res {
			return Err(IoError::last_os_error());
		}

		unsafe { ioctl!(self.sock4, IoCtlRequest::SIOCSIFADDR, &ifr_ipaddr) }
	}

	pub fn set_ipv6(self, ipv6: &'static str) -> IoResult<()> {
		let mut ifr = InterfaceRequest32 {
			name: self.name,
			..Default::default()
		};
		let res = unsafe { ioctl!(self.sock6, IoCtlRequest::SIOGIFINDEX, &mut ifr) };
		if res.is_err() {
			return Err(res.unwrap_err());
		}

		let mut ifr6 = InterfaceRequestIn6 {
			addr:      in6_addr { s6_addr: [0; 16] },
			prefixlen: 64,
			ifindex:   ifr.flags,
		};

		let ip = ::std::ffi::CString::new(ipv6.as_bytes()).unwrap();
		let res = unsafe { inet_pton(AF_INET6, ip.as_ptr(),
								::std::mem::transmute(&mut (ifr6.addr.s6_addr))) == 1 };
		if !res {
			return Err(IoError::last_os_error());
		}
		unsafe { ioctl!(self.sock6, IoCtlRequest::SIOCSIFADDR, &ifr6) }
	}*/

	pub fn set_ip(&mut self, addr: std::net::IpAddr) -> IoResult<()> {
		let addr = nix::sys::socket::InetAddr::from_std(&(addr, 0).into());
		match addr {
			nix::sys::socket::InetAddr::V4(sockaddr_in) => {
				let mut ifr_ipaddr = InterfaceRequestSockaddrIn {
					name:     self.name,
					..Default::default()
				};
				ifr_ipaddr.sockaddr = sockaddr_in;

				unsafe { ioctl!(self.sock4, IoCtlRequest::SIOCSIFADDR, &ifr_ipaddr) }?;
				Ok(())
			},
			nix::sys::socket::InetAddr::V6(sockaddr_in6) => {
				let mut ifr = InterfaceRequest32 {
					name: self.name,
					..Default::default()
				};
				unsafe { ioctl!(self.sock6, IoCtlRequest::SIOGIFINDEX, &mut ifr) }?;

				let ifr6 = InterfaceRequestIn6 {
					addr:      sockaddr_in6.sin6_addr,
					prefixlen: 64,
					ifindex:   ifr.flags,
				};

				unsafe { ioctl!(self.sock6, IoCtlRequest::SIOCSIFADDR, &ifr6) }?;
				Ok(())
			},
		}
	}

	pub fn set_up(&mut self) -> IoResult<()> {
		let mut ifr_setup = InterfaceRequest16 {
			name: self.name,
			..Default::default()
		};
		let setup = unsafe { ioctl!(self.sock4, IoCtlRequest::SIOCGIFFLAGS, &ifr_setup) };
		if setup.is_err() {
			return Err(setup.unwrap_err());
		}

		ifr_setup.flags |= (TunTapFlags::IFF_UP | TunTapFlags::IFF_RUNNING).bits();
		unsafe { ioctl!(self.sock4, IoCtlRequest::SIOCSIFFLAGS, &ifr_setup) }
	}
}
