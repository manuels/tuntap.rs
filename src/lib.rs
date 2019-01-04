#![feature(pin)]
#![feature(await_macro, async_await, futures_api)]
#![allow(dead_code)]

#[macro_use] extern crate bitflags;
#[macro_use] extern crate tokio;
extern crate libc;

//use tuntap::{TunTap,IFF_TUN,IFF_TAP,IFF_NO_PI};

mod tuntap;
pub use crate::tuntap::*;

#[test]
fn it_works() {
	use tokio::prelude::*;

	tokio::run_async(async {
		let flags = crate::TunTapFlags::IFF_TUN | crate::TunTapFlags::IFF_NO_PI;
		let (mut tun1, (mut tx1, mut rx1)) = await!(TunTap::new(flags)).unwrap();
		let (mut tun2, (mut tx2, mut rx2)) = await!(TunTap::new(flags)).unwrap();

		tun1.set_owner(1001).unwrap();
		tun1.set_group(1001).unwrap();
		//tun.set_mac([11,22,33,44,55,66+i as u8]).unwrap();

		tun1.set_ip("10.0.0.1".parse().unwrap()).unwrap();
		tun1.set_ip("fe80::0db8:1234:1211".parse().unwrap()).unwrap();

		tun1.set_mtu(1400).unwrap();
		tun1.set_up().unwrap();


		tun2.set_owner(1001).unwrap();
		tun2.set_group(1001).unwrap();
		//tun.set_mac([11,22,33,44,55,66+i as u8]).unwrap();

		tun2.set_ip("10.0.0.2".parse().unwrap()).unwrap();
		tun2.set_ip("fe80::0db8:1234:1212".parse().unwrap()).unwrap();

		tun2.set_mtu(1400).unwrap();
		tun2.set_up().unwrap();

		tokio::spawn_async(async move {
			println!("send0");
			while let Some(Ok(packet)) = await!(rx1.next()) {
				println!("rx1 {}", packet.len());
				await!(tx2.send_async(packet)).unwrap();
			}
		});

		while let Some(Ok(packet)) = await!(rx2.next()) {
			println!("rx2 {}", packet.len());
			await!(tx1.send_async(packet)).unwrap();
		}
	})
}
	