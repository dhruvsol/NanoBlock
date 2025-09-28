#![no_std]

// Shared types and constants between eBPF and user space

/// IP configuration structure for firewall rules
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IpConfig {
    pub port: Option<u16>,
    pub protocol: Option<u8>,
    pub allowed: bool,
}

/// Protocol types for firewall rules
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    Any = 0,
}

/// Action types for firewall rules
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow = 0,
    Block = 1,
    Log = 2,
}

/// Common ports for easy reference
pub mod ports {
    pub const SSH: u16 = 22;
    pub const HTTP: u16 = 80;
    pub const HTTPS: u16 = 443;
    pub const DNS: u16 = 53;
    pub const NTP: u16 = 123;
    pub const MYSQL: u16 = 3306;
    pub const POSTGRES: u16 = 5432;
    pub const WEB_SERVER: u16 = 8080;
}

/// Common IP addresses for easy reference
pub mod ips {
    pub const LOCALHOST: [u8; 4] = [127, 0, 0, 1];
    pub const PRIVATE_10_0_0_1: [u8; 4] = [10, 0, 0, 1];
    pub const PRIVATE_192_168_1_1: [u8; 4] = [192, 168, 1, 1];
}

/// Helper functions for IP address conversion
pub fn ip_to_u32(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes(ip)
}

pub fn u32_to_ip(ip_u32: u32) -> [u8; 4] {
    ip_u32.to_be_bytes()
}

/// Helper function to format IP address as string
#[cfg(feature = "user")]
pub fn format_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Helper function to format IPv6 address as string
#[cfg(feature = "user")]
pub fn format_ipv6(ip: [u8; 16]) -> String {
    let mut result = String::new();
    for i in (0..16).step_by(2) {
        if i > 0 {
            result.push(':');
        }
        result.push_str(&format!("{:02x}{:02x}", ip[i], ip[i + 1]));
    }
    result
}

/// Example firewall rules for initialization
pub mod example_rules {
    use super::*;

    /// Get default allowed ports
    pub fn get_default_allowed_ports() -> &'static [u16] {
        &[
            ports::SSH, // Always allow SSH
            ports::HTTP,
            ports::HTTPS,
            ports::DNS,
            ports::NTP,
        ]
    }

    /// Get default trusted IPs
    pub fn get_default_trusted_ips() -> &'static [[u8; 4]] {
        &[
            ips::LOCALHOST,
            ips::PRIVATE_10_0_0_1,
            ips::PRIVATE_192_168_1_1,
        ]
    }

    /// Get example IP configurations
    pub fn get_example_ip_configs() -> &'static [([u8; 4], IpConfig)] {
        &[
            // Allow admin IP to access MySQL
            (
                [192, 168, 1, 100],
                IpConfig {
                    port: Some(ports::MYSQL),
                    protocol: Some(Protocol::TCP as u8),
                    allowed: true,
                },
            ),
            // Block specific IP from accessing database
            (
                [192, 168, 1, 200],
                IpConfig {
                    port: Some(ports::MYSQL),
                    protocol: Some(Protocol::TCP as u8),
                    allowed: false,
                },
            ),
        ]
    }
}
