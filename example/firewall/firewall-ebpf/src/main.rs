#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use nano_block::check_packet;

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_firewall(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    // Use the nano-block library to check the packet
    match check_packet(ctx) {
        Ok(action) => match action {
            xdp_action::XDP_PASS => {
                info!(&ctx, "packet allowed");
                Ok(xdp_action::XDP_PASS)
            }
            xdp_action::XDP_DROP => {
                info!(&ctx, "packet blocked");
                Ok(xdp_action::XDP_DROP)
            }
            _ => {
                info!(&ctx, "packet action: {}", action);
                Ok(action)
            }
        },
        Err(_) => {
            info!(&ctx, "error checking packet, defaulting to pass");
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
