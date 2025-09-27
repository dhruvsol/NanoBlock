#![no_std]
#![no_main]

use aya::maps::array;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use core::net::IpAddr;

#[derive(Default)]
#[repr(C)]
pub struct IpConfig {
    pub port: Option<u16>,
    pub protocol: Option<u8>,
    pub allowed: bool,
}

#[array]
static mut ALLOWED_PORTS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0); // allow ports for everyone without no ip block
#[array]
static mut ALLOWED_IPS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0); // allowed ips for everyone without no port block

#[map]
static mut ALLOWED_IP_CONFIG: HashMap<u32, IpConfig> =
    HashMap::<IpAddr, IpConfig>::with_max_entries(1024, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

pub fn check_packet(ctx: XdpContext) -> Result<bool, ()> {
    return Ok(true);
}
