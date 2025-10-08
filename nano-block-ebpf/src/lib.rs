#![no_std]

pub mod utils;

use crate::utils::{
    allowed_ip_v4_config, allowed_ip_v6, allowed_ip_v6_config, allowed_port, allowed_v4_ip,
    blocked_ip_v4, blocked_ip_v4_config, blocked_ip_v6, blocked_ip_v6_config, ipv6_to_u128, ptr_at,
    read_u32,
};
use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

fn check_ipv4_packet(ctx: &XdpContext, src_ip: u32) -> Result<u32, ()> {
    debug!(&ctx, "Processing IPv4 packet from IP: {}", src_ip);

    // Parse IPv4 header
    let iphdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let iphdr = unsafe { *iphdr };

    let protocol = iphdr.proto;
    let ip_header_len = (iphdr.ihl() as usize * 4) as usize;
    let transport_offset = EthHdr::LEN + ip_header_len;

    debug!(
        &ctx,
        "IPv4 protocol: {}, header_len: {}", protocol as u8, ip_header_len
    );

    // Extract destination port from transport layer
    let dest_port = if protocol as u8 == 6 || protocol as u8 == 17 {
        // TCP or UDP
        if let Ok(port_ptr) = ptr_at::<u16>(ctx, transport_offset + 2) {
            let port = u16::from_be(unsafe { *port_ptr });
            debug!(&ctx, "TCP/UDP packet, dest_port: {}", port);
            port
        } else {
            debug!(&ctx, "Failed to read port, passing packet");
            return Ok(XDP_PASS); // If we can't read port, let it pass
        }
    } else {
        debug!(
            &ctx,
            "Non-TCP/UDP protocol: {}, passing packet", protocol as u8
        );
        return Ok(XDP_PASS); // Non-TCP/UDP, let it pass
    };

    // Check if IP is blocked
    if blocked_ip_v4(src_ip) {
        debug!(&ctx, "IPv4 IP {} is in blocked list, dropping", src_ip);
        return Ok(XDP_DROP);
    }

    // Check if port is allowed to accept everything
    if blocked_ip_v4_config(src_ip, dest_port, protocol as u8) {
        debug!(
            &ctx,
            "IPv4 IP {} blocked for port {} protocol {}, dropping",
            src_ip,
            dest_port,
            protocol as u8
        );
        return Ok(XDP_DROP);
    }

    // if port is allowed to accept everything
    if allowed_port(dest_port as u32) {
        debug!(&ctx, "Port {} is globally allowed, passing", dest_port);
        return Ok(XDP_PASS);
    }

    //  Check if IP is in the allowed list
    if allowed_v4_ip(src_ip) {
        debug!(&ctx, "IPv4 IP {} is globally allowed, passing", src_ip);
        return Ok(XDP_PASS);
    }

    //  Check if IP is in ALLOWED_IP_CONFIG and match other configs
    if allowed_ip_v4_config(src_ip, dest_port, protocol as u8) {
        debug!(
            &ctx,
            "IPv4 IP {} allowed for port {} protocol {}, passing",
            src_ip,
            dest_port,
            protocol as u8
        );
        return Ok(XDP_PASS);
    }

    debug!(
        &ctx,
        "IPv4 packet from {} to port {} protocol {} not explicitly allowed, dropping",
        src_ip,
        dest_port,
        protocol as u8
    );
    Ok(XDP_DROP)
}

fn check_ipv6_packet(ctx: &XdpContext, src_ip: [u8; 16]) -> Result<u32, ()> {
    debug!(&ctx, "Processing IPv6 packet");

    // Parse IPv6 header
    let ipv6hdr: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let ipv6hdr = unsafe { &*ipv6hdr };

    let next_header = ipv6hdr.next_hdr;
    let transport_offset = EthHdr::LEN + Ipv6Hdr::LEN;

    debug!(&ctx, "IPv6 next_header: {}", next_header as u8);

    // Extract destination port from transport layer
    let dest_port = if next_header as u8 == 6 || next_header as u8 == 17 {
        // TCP or UDP
        if let Ok(port_ptr) = ptr_at::<u16>(ctx, transport_offset + 2) {
            let port = u16::from_be(unsafe { *port_ptr });
            debug!(&ctx, "TCP/UDP packet, dest_port: {}", port);
            port
        } else {
            debug!(&ctx, "Failed to read port, passing packet");
            return Ok(XDP_PASS); // If we can't read port, let it pass
        }
    } else {
        debug!(
            &ctx,
            "Non-TCP/UDP protocol: {}, passing packet", next_header as u8
        );
        return Ok(XDP_PASS); // Non-TCP/UDP, let it pass
    };

    let src_ip_key = ipv6_to_u128(src_ip);
    debug!(&ctx, "IPv6 src_ip_key processed");

    // Check if IP is blocked
    if blocked_ip_v6(src_ip_key) {
        debug!(&ctx, "IPv6 IP is in blocked list, dropping");
        return Ok(XDP_DROP);
    }

    if blocked_ip_v6_config(src_ip_key, dest_port, next_header as u8) {
        debug!(&ctx, "IPv6 IP blocked for port and protocol, dropping");
        return Ok(XDP_DROP);
    }

    //  Check if port is allowed to accept everything
    if allowed_port(dest_port as u32) {
        debug!(&ctx, "Port {} is globally allowed, passing", dest_port);
        return Ok(XDP_PASS);
    }

    //Check if IP is in the allowed list
    if allowed_ip_v6(src_ip_key) {
        debug!(&ctx, "IPv6 IP is globally allowed, passing");
        return Ok(XDP_PASS);
    }

    // Check if IP is in ALLOWED_IP_CONFIG and match other configs
    if allowed_ip_v6_config(src_ip_key, dest_port, next_header as u8) {
        debug!(&ctx, "IPv6 IP allowed for port and protocol, passing");
        return Ok(XDP_PASS);
    }

    debug!(&ctx, "IPv6 packet not explicitly allowed, dropping");
    Ok(XDP_DROP)
}

pub fn check_packet(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    debug!(&ctx, "Packet received, data_len: {}", end - start);

    // Check if we have enough data for Ethernet header
    if start + EthHdr::LEN > end {
        debug!(&ctx, "Packet too short for Ethernet header, passing");
        return Ok(XDP_PASS);
    }

    // Parse Ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ethhdr = unsafe { &*ethhdr };

    debug!(&ctx, "EtherType: {}", ethhdr.ether_type);

    // Check EtherType to determine if it's IPv4 or IPv6
    match ethhdr.ether_type {
        // Ipv4
        0x0800_u16 => {
            debug!(&ctx, "IPv4 packet detected");
            // Parse IPv4 header
            let iphdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let iphdr = unsafe { *iphdr };
            let src_ip = read_u32(iphdr.src_addr)?;

            check_ipv4_packet(&ctx, src_ip)
        }
        // Ipv6
        0x86DD_u16 => {
            debug!(&ctx, "IPv6 packet detected");
            // Parse IPv6 header
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let ipv6hdr = unsafe { &*ipv6hdr };
            let src_ip = ipv6hdr.src_addr;

            check_ipv6_packet(&ctx, src_ip)
        }
        _ => {
            // Not an IP packet (could be ARP, VLAN, etc.)
            debug!(
                &ctx,
                "Non-IP packet (EtherType: {}), passing", ethhdr.ether_type
            );
            return Ok(XDP_PASS);
        }
    }
}
