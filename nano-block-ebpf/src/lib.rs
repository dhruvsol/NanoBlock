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
use aya_log_ebpf::{debug, info};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

fn check_ipv4_packet(ctx: &XdpContext, src_ip: u32) -> u32 {
    debug!(&ctx, "Processing IPv4 packet from IP: {}", src_ip);

    // Parse IPv4 header
    let iphdr_ptr: *const Ipv4Hdr = match ptr_at(ctx, EthHdr::LEN) {
        Ok(p) => p,
        Err(_) => {
            debug!(&ctx, "No IPv4 header, passing");
            return XDP_PASS;
        }
    };
    let iphdr = unsafe { *iphdr_ptr };

    let protocol = iphdr.proto;
    let ip_header_len = (iphdr.ihl() as usize) * 4;
    let transport_offset = EthHdr::LEN + ip_header_len;

    debug!(
        &ctx,
        "IPv4 protocol: {}, header_len: {}", protocol as u8, ip_header_len
    );

    // Extract destination port from transport layer (TCP=6, UDP=17)
    let dest_port = if protocol as u8 == 6 || protocol as u8 == 17 {
        match ptr_at::<u16>(ctx, transport_offset + 2) {
            Ok(port_ptr) => {
                let port = u16::from_be(unsafe { *port_ptr });
                debug!(&ctx, "TCP/UDP packet, dest_port: {}", port);
                port
            }
            Err(_) => {
                debug!(&ctx, "Failed to read port, passing packet");
                return XDP_PASS;
            }
        }
    } else {
        debug!(
            &ctx,
            "Non-TCP/UDP protocol: {}, passing packet", protocol as u8
        );
        return XDP_PASS;
    };

    // Policy checks
    if blocked_ip_v4(src_ip) {
        info!(&ctx, "IPv4 IP {} is in blocked list, dropping", src_ip);
        return XDP_DROP;
    }

    if blocked_ip_v4_config(src_ip, dest_port, protocol as u8) {
        info!(
            &ctx,
            "IPv4 IP {} blocked for port {} proto {}, dropping", src_ip, dest_port, protocol as u8
        );
        return XDP_DROP;
    }

    if allowed_port(dest_port as u32) {
        info!(&ctx, "Port {} is globally allowed, passing", dest_port);
        return XDP_PASS;
    }

    if allowed_v4_ip(src_ip) {
        info!(&ctx, "IPv4 IP {} is globally allowed, passing", src_ip);
        return XDP_PASS;
    }

    if allowed_ip_v4_config(src_ip, dest_port, protocol as u8) {
        info!(
            &ctx,
            "IPv4 IP {} allowed for port {} proto {}, passing", src_ip, dest_port, protocol as u8
        );
        return XDP_PASS;
    }

    debug!(
        &ctx,
        "IPv4 packet from {} to port {} proto {} not allowed, dropping",
        src_ip,
        dest_port,
        protocol as u8
    );
    XDP_DROP
}

fn check_ipv6_packet(ctx: &XdpContext, src_ip: [u8; 16]) -> u32 {
    debug!(&ctx, "Processing IPv6 packet");

    // Parse IPv6 header
    let ipv6hdr_ptr: *const Ipv6Hdr = match ptr_at(ctx, EthHdr::LEN) {
        Ok(p) => p,
        Err(_) => {
            debug!(&ctx, "No IPv6 header, passing");
            return XDP_PASS;
        }
    };
    let ipv6hdr = unsafe { &*ipv6hdr_ptr };

    let next_header = ipv6hdr.next_hdr;
    let transport_offset = EthHdr::LEN + Ipv6Hdr::LEN;

    debug!(&ctx, "IPv6 next_header: {}", next_header as u8);

    // Extract destination port from transport layer (TCP=6, UDP=17)
    let dest_port = if next_header as u8 == 6 || next_header as u8 == 17 {
        match ptr_at::<u16>(ctx, transport_offset + 2) {
            Ok(port_ptr) => {
                let port = u16::from_be(unsafe { *port_ptr });
                debug!(&ctx, "TCP/UDP packet, dest_port: {}", port);
                port
            }
            Err(_) => {
                debug!(&ctx, "Failed to read port, passing packet");
                return XDP_PASS;
            }
        }
    } else {
        debug!(
            &ctx,
            "Non-TCP/UDP protocol: {}, passing packet", next_header as u8
        );
        return XDP_PASS;
    };

    let src_ip_key = ipv6_to_u128(src_ip);
    debug!(&ctx, "IPv6 src_ip_key processed");

    // Policy checks
    if blocked_ip_v6(src_ip_key) {
        info!(&ctx, "IPv6 IP is in blocked list, dropping");
        return XDP_DROP;
    }

    if blocked_ip_v6_config(src_ip_key, dest_port, next_header as u8) {
        info!(&ctx, "IPv6 IP blocked for port and protocol, dropping");
        return XDP_DROP;
    }

    if allowed_port(dest_port as u32) {
        info!(&ctx, "Port {} is globally allowed, passing", dest_port);
        return XDP_PASS;
    }

    if allowed_ip_v6(src_ip_key) {
        info!(&ctx, "IPv6 IP is globally allowed, passing");
        return XDP_PASS;
    }

    if allowed_ip_v6_config(src_ip_key, dest_port, next_header as u8) {
        info!(&ctx, "IPv6 IP allowed for port and protocol, passing");
        return XDP_PASS;
    }

    debug!(&ctx, "IPv6 packet not explicitly allowed, dropping");
    XDP_DROP
}

pub fn check_packet(ctx: &XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();

    debug!(&ctx, "Packet received, data_len: {}", end - start);

    if start + EthHdr::LEN > end {
        debug!(&ctx, "Packet too short for Ethernet header, passing");
        return XDP_PASS;
    }

    let ethhdr_ptr: *const EthHdr = match ptr_at(&ctx, 0) {
        Ok(p) => p,
        Err(_) => {
            debug!(&ctx, "Failed to read EthHdr, passing");
            return XDP_PASS;
        }
    };
    let ethhdr = unsafe { &*ethhdr_ptr };

    debug!(&ctx, "EtherType: {}", ethhdr.ether_type);

    match ethhdr.ether_type {
        0x0800_u16 => {
            debug!(&ctx, "IPv4 packet detected");
            let iphdr_ptr: *const Ipv4Hdr = match ptr_at(&ctx, EthHdr::LEN) {
                Ok(p) => p,
                Err(_) => {
                    debug!(&ctx, "No IPv4 header at offset, passing");
                    return XDP_PASS;
                }
            };
            let iphdr = unsafe { *iphdr_ptr };
            let src_ip = match read_u32(iphdr.src_addr) {
                Ok(v) => v,
                Err(_) => {
                    debug!(&ctx, "Failed to read IPv4 src, passing");
                    return XDP_PASS;
                }
            };
            check_ipv4_packet(&ctx, src_ip)
        }
        0x86DD_u16 => {
            debug!(&ctx, "IPv6 packet detected");
            let ipv6hdr_ptr: *const Ipv6Hdr = match ptr_at(&ctx, EthHdr::LEN) {
                Ok(p) => p,
                Err(_) => {
                    debug!(&ctx, "No IPv6 header at offset, passing");
                    return XDP_PASS;
                }
            };
            let ipv6hdr = unsafe { &*ipv6hdr_ptr };
            let src_ip = ipv6hdr.src_addr;
            check_ipv6_packet(&ctx, src_ip)
        }
        _ => {
            debug!(
                &ctx,
                "Non-IP packet (EtherType: {}), passing", ethhdr.ether_type
            );
            XDP_PASS
        }
    }
}
