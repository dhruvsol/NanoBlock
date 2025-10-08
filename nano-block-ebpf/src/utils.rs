use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use core::mem;
#[derive(Default)]
#[repr(C)]
pub struct IpConfig {
    pub port: u16,
    pub protocol: u8,
}

/// Allow ports for everyone without no ip block
#[map]
pub static ALLOWED_PORTS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

// Allow ips for everyone without no port block
#[map]
pub static ALLOWED_IP_V4: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0); // allowed ips for everyone without no port block
// Allow ips for everyone with port and protocol limits
#[map]
pub static ALLOWED_IP_V4_CONFIG: HashMap<u32, IpConfig> =
    HashMap::<u32, IpConfig>::with_max_entries(1024, 0);

// Block ips for everyone with port and protocol limits
#[map]
pub static BLOCKED_IP_V4_CONFIG: HashMap<u32, IpConfig> =
    HashMap::<u32, IpConfig>::with_max_entries(1024, 0);
// Block ips for everyone without no port block
#[map]
pub static BLOCKED_IP_V4: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

// Block ips for everyone without no port block
#[map]
pub static BLOCKED_IP_V6: HashMap<u128, u32> = HashMap::<u128, u32>::with_max_entries(1024, 0);
// Allow ips for everyone without no port block
#[map]
pub static ALLOWED_IP_V6: HashMap<u128, u32> = HashMap::<u128, u32>::with_max_entries(1024, 0); // allowed ips for everyone without no port block

// Allow ips for everyone with port and protocol limits
#[map]
pub static ALLOWED_IP_V6_CONFIG: HashMap<u128, IpConfig> =
    HashMap::<u128, IpConfig>::with_max_entries(1024, 0);

// Block ips for everyone with port and protocol limits
#[map]
pub static BLOCKED_IP_V6_CONFIG: HashMap<u128, IpConfig> =
    HashMap::<u128, IpConfig>::with_max_entries(1024, 0);

#[inline(always)]
pub fn allowed_port(port: u32) -> bool {
    unsafe { ALLOWED_PORTS.get(&port).is_some() }
}

#[inline(always)]
pub fn allowed_v4_ip(address: u32) -> bool {
    unsafe { ALLOWED_IP_V4.get(&address).is_some() }
}
#[inline(always)]
pub fn blocked_ip_v4(address: u32) -> bool {
    unsafe { BLOCKED_IP_V4.get(&address).is_some() }
}

#[inline(always)]
pub fn blocked_ip_v4_config(address: u32, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { BLOCKED_IP_V4_CONFIG.get(&address) } {
        return config.port == port && config.protocol == protocol;
    }
    false
}
#[inline(always)]
pub fn allowed_ip_v4_config(address: u32, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { ALLOWED_IP_V4_CONFIG.get(&address) } {
        return config.port == port && config.protocol == protocol;
    }
    false
}

#[inline(always)]
pub fn allowed_ip_v6(address: u128) -> bool {
    unsafe { ALLOWED_IP_V6.get(&address).is_some() }
}

#[inline(always)]
pub fn blocked_ip_v6_config(address: u128, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { BLOCKED_IP_V6_CONFIG.get(&address) } {
        return config.port == port && config.protocol == protocol;
    }
    false
}
#[inline(always)]
pub fn blocked_ip_v6(address: u128) -> bool {
    unsafe { BLOCKED_IP_V6.get(&address).is_some() }
}

#[inline(always)]
pub fn allowed_ip_v6_config(address: u128, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { ALLOWED_IP_V6_CONFIG.get(&address) } {
        return config.port == port && config.protocol == protocol;
    }
    false
}

#[inline(always)]
pub fn ipv6_to_u128(addr: [u8; 16]) -> u128 {
    u128::from_be_bytes(addr)
}

#[inline(always)]
pub fn read_u32(data: [u8; 4]) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(data))
}

#[inline(always)]
pub fn read_u16(data: [u8; 2]) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(data))
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
