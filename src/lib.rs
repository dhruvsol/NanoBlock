#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    macros::map,
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[derive(Default)]
#[repr(C)]
pub struct IpConfig {
    pub port: Option<u16>,
    pub protocol: Option<u8>,
    pub allowed: bool,
}

#[map]
static ALLOWED_PORTS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0); // allow ports for everyone without no ip block
#[map]
static ALLOWED_IPS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0); // allowed ips for everyone without no port block

#[map]
static ALLOWED_IP_CONFIG: HashMap<u32, IpConfig> =
    HashMap::<u32, IpConfig>::with_max_entries(1024, 0); // check ip against configuration

pub fn read_u32(data: [u8; 4]) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(data))
}
pub fn read_u16(data: [u8; 2]) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(data))
}
fn allowed_ip(address: u32) -> bool {
    unsafe { ALLOWED_IPS.get(&address).is_some() }
}
fn allowed_port(port: u32) -> bool {
    unsafe { ALLOWED_PORTS.get(&port).is_some() }
}

fn allowed_ip_config(address: u32, port: u16, protocol: u8) -> bool {
    if let Some(config) = unsafe { ALLOWED_IP_CONFIG.get(&address) } {
        return config.port.is_some()
            && config.port.unwrap() == port
            && config.protocol.is_some()
            && config.protocol.unwrap() == protocol
            && config.allowed;
    }
    false
}

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

fn check_ipv4_packet(ctx: &XdpContext, src_ip: u32) -> Result<u32, ()> {
    // Parse IPv4 header
    let iphdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let iphdr = unsafe { *iphdr };

    let protocol = iphdr.proto;
    let ip_header_len = (iphdr.ihl() as usize * 4) as usize;
    let transport_offset = EthHdr::LEN + ip_header_len;

    // Extract destination port from transport layer
    let dest_port = if protocol as u8 == 6 || protocol as u8 == 17 {
        // TCP or UDP
        if let Ok(port_ptr) = ptr_at::<u16>(ctx, transport_offset + 2) {
            u16::from_be(unsafe { *port_ptr })
        } else {
            return Ok(XDP_PASS); // If we can't read port, let it pass
        }
    } else {
        return Ok(XDP_PASS); // Non-TCP/UDP, let it pass
    };
    // Check if port is allowed to accept everything

    if allowed_port(dest_port as u32) {
        return Ok(XDP_PASS);
    }

    //  Check if IP is in the allowed list
    if allowed_ip(src_ip) {
        return Ok(XDP_PASS);
    }

    //  Check if IP is in ALLOWED_IP_CONFIG and match other configs
    if allowed_ip_config(src_ip, dest_port, protocol as u8) {
        return Ok(XDP_PASS);
    }

    Ok(XDP_DROP)
}

fn check_ipv6_packet(ctx: &XdpContext, src_ip: [u8; 16]) -> Result<u32, ()> {
    // Parse IPv6 header
    let ipv6hdr: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let ipv6hdr = unsafe { &*ipv6hdr };

    let next_header = ipv6hdr.next_hdr;
    let transport_offset = EthHdr::LEN + Ipv6Hdr::LEN;

    // Extract destination port from transport layer
    let dest_port = if next_header as u8 == 6 || next_header as u8 == 17 {
        // TCP or UDP
        if let Ok(port_ptr) = ptr_at::<u16>(ctx, transport_offset + 2) {
            u16::from_be(unsafe { *port_ptr })
        } else {
            return Ok(XDP_PASS); // If we can't read port, let it pass
        }
    } else {
        return Ok(XDP_PASS); // Non-TCP/UDP, let it pass
    };

    let src_ip_key = u32::from_be_bytes([src_ip[0], src_ip[1], src_ip[2], src_ip[3]]);

    //  Check if port is allowed to accept everything
    if allowed_port(dest_port as u32) {
        return Ok(XDP_PASS);
    }

    //Check if IP is in the allowed list
    if allowed_ip(src_ip_key) {
        return Ok(XDP_PASS);
    }

    // Check if IP is in ALLOWED_IP_CONFIG and match other configs
    if allowed_ip_config(src_ip_key, dest_port, next_header as u8) {
        return Ok(XDP_PASS);
    }

    Ok(XDP_DROP)
}

pub fn check_packet(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // Check if we have enough data for Ethernet header
    if start + EthHdr::LEN > end {
        return Ok(XDP_PASS);
    }

    // Parse Ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ethhdr = unsafe { &*ethhdr };

    // Check EtherType to determine if it's IPv4 or IPv6
    match ethhdr.ether_type {
        // Ipv4
        0x0800_u16 => {
            // Parse IPv4 header
            let iphdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let iphdr = unsafe { *iphdr };
            let src_ip = read_u32(iphdr.src_addr)?;

            check_ipv4_packet(&ctx, src_ip)
        }
        // Ipv6
        0x86DD_u16 => {
            // Parse IPv6 header
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let ipv6hdr = unsafe { &*ipv6hdr };
            let src_ip = ipv6hdr.src_addr;

            check_ipv6_packet(&ctx, src_ip)
        }
        _ => {
            // Not an IP packet (could be ARP, VLAN, etc.)
            return Ok(XDP_PASS);
        }
    }
}
