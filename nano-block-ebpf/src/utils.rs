use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::debug;
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
pub static ALLOWED_V4_IPS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0); // allowed ips for everyone without no port block
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
pub static ALLOWED_V6_IPS: HashMap<u128, u32> = HashMap::<u128, u32>::with_max_entries(1024, 0); // allowed ips for everyone without no port block

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
    let result = unsafe { ALLOWED_PORTS.get(&port).is_some() };
    if result {
        debug!("Port {} found in ALLOWED_PORTS", port);
    }
    result
}

#[inline(always)]
pub fn allowed_v4_ip(address: u32) -> bool {
    let result = unsafe { ALLOWED_V4_IPS.get(&address).is_some() };
    if result {
        debug!("IPv4 address {} found in ALLOWED_V4_IPS", address);
    }
    result
}
#[inline(always)]
pub fn blocked_ip_v4(address: u32) -> bool {
    let result = unsafe { BLOCKED_IP_V4.get(&address).is_some() };
    if result {
        debug!("IPv4 address {} found in BLOCKED_IP_V4", address);
    }
    result
}

#[inline(always)]
pub fn blocked_ip_v4_config(address: u32, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { BLOCKED_IP_V4_CONFIG.get(&address) } {
        let matches = config.port == port && config.protocol == protocol;
        if matches {
            debug!("IPv4 address {} blocked for port {} protocol {}", address, port, protocol);
        }
        return matches;
    }
    false
}
#[inline(always)]
pub fn allowed_ip_v4_config(address: u32, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { ALLOWED_IP_V4_CONFIG.get(&address) } {
        let matches = config.port == port && config.protocol == protocol;
        if matches {
            debug!("IPv4 address {} allowed for port {} protocol {}", address, port, protocol);
        }
        return matches;
    }
    false
}

#[inline(always)]
pub fn allowed_ip_v6(address: u128) -> bool {
    let result = unsafe { ALLOWED_V6_IPS.get(&address).is_some() };
    if result {
        debug!("IPv6 address {} found in ALLOWED_V6_IPS", address);
    }
    result
}

#[inline(always)]
pub fn blocked_ip_v6_config(address: u128, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { BLOCKED_IP_V6_CONFIG.get(&address) } {
        let matches = config.port == port && config.protocol == protocol;
        if matches {
            debug!("IPv6 address {} blocked for port {} protocol {}", address, port, protocol);
        }
        return matches;
    }
    false
}
#[inline(always)]
pub fn blocked_ip_v6(address: u128) -> bool {
    let result = unsafe { BLOCKED_IP_V6.get(&address).is_some() };
    if result {
        debug!("IPv6 address {} found in BLOCKED_IP_V6", address);
    }
    result
}

#[inline(always)]
pub fn allowed_ip_v6_config(address: u128, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { ALLOWED_IP_V6_CONFIG.get(&address) } {
        let matches = config.port == port && config.protocol == protocol;
        if matches {
            debug!("IPv6 address {} allowed for port {} protocol {}", address, port, protocol);
        }
        return matches;
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
        debug!("ptr_at: buffer overflow - offset: {}, len: {}, available: {}", offset, len, end - start);
        return Err(());
    }

    Ok((start + offset) as *const T)
}
