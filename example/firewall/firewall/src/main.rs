use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use clap::{Parser, Subcommand};
use firewall_common::{IpConfig, example_rules, format_ip, ip_to_u32, ips, ports};
use nano_block::{ALLOWED_IP_CONFIG, ALLOWED_IPS, ALLOWED_PORTS};
#[rustfmt::skip]
use log::{debug, info, warn};
use std::net::Ipv4Addr;

use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize firewall with default rules
    Init,
    /// Add an allowed port
    AddPort { port: u16 },
    /// Add a trusted IP address
    AddTrustedIp { ip: String },
    /// Add IP-specific configuration
    AddIpConfig {
        ip: String,
        port: u16,
        protocol: u8,
        allowed: bool,
    },
    /// List current firewall rules
    List,
    /// Show firewall statistics
    Stats,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load the eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;

    // Initialize eBPF logger
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Get access to the maps
    let mut allowed_ports: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("ALLOWED_PORTS").unwrap())?;
    let mut allowed_ips: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("ALLOWED_IPS").unwrap())?;
    let mut allowed_ip_config: HashMap<_, u32, IpConfig> =
        HashMap::try_from(ebpf.take_map("ALLOWED_IP_CONFIG").unwrap())?;

    // Handle commands
    match opt.command {
        Some(Commands::Init) => {
            init_firewall_rules(&mut allowed_ports, &mut allowed_ips, &mut allowed_ip_config)?;
            info!("Firewall initialized with default rules");
        }
        Some(Commands::AddPort { port }) => {
            add_allowed_port(&mut allowed_ports, port)?;
            info!("Added port {} to allowed ports", port);
        }
        Some(Commands::AddTrustedIp { ip }) => {
            let ip_addr: Ipv4Addr = ip.parse()?;
            add_trusted_ip(&mut allowed_ips, ip_addr.octets())?;
            info!("Added IP {} to trusted IPs", ip);
        }
        Some(Commands::AddIpConfig {
            ip,
            port,
            protocol,
            allowed,
        }) => {
            let ip_addr: Ipv4Addr = ip.parse()?;
            add_ip_config(
                &mut allowed_ip_config,
                ip_addr.octets(),
                port,
                protocol,
                allowed,
            )?;
            info!(
                "Added IP configuration for {}: port={}, protocol={}, allowed={}",
                ip, port, protocol, allowed
            );
        }
        Some(Commands::List) => {
            list_firewall_rules(&allowed_ports, &allowed_ips, &allowed_ip_config)?;
        }
        Some(Commands::Stats) => {
            show_firewall_stats(&ebpf)?;
        }
        None => {
            // No command specified, just run the firewall
            info!("Starting firewall on interface: {}", opt.iface);

            // Initialize with default rules if not already done
            init_firewall_rules(&mut allowed_ports, &mut allowed_ips, &mut allowed_ip_config)?;

            // Attach the XDP program
            let program: &mut Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
            program.load()?;
            program.attach(&opt.iface, XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

            let ctrl_c = signal::ctrl_c();
            println!("Firewall running on {}. Waiting for Ctrl-C...", opt.iface);
            ctrl_c.await?;
            println!("Exiting...");
        }
    }

    Ok(())
}

/// Initialize firewall with default rules
fn init_firewall_rules(
    allowed_ports: &mut HashMap<u32, u32>,
    allowed_ips: &mut HashMap<u32, u32>,
    allowed_ip_config: &mut HashMap<u32, IpConfig>,
) -> anyhow::Result<()> {
    // Add default allowed ports
    for &port in example_rules::get_default_allowed_ports() {
        allowed_ports.insert(port as u32, 1, 0)?;
    }

    // Add default trusted IPs
    for &ip in example_rules::get_default_trusted_ips() {
        allowed_ips.insert(ip_to_u32(ip), 1, 0)?;
    }

    // Add example IP configurations
    for &(ip, config) in example_rules::get_example_ip_configs() {
        allowed_ip_config.insert(ip_to_u32(ip), config, 0)?;
    }

    info!(
        "Initialized firewall with {} allowed ports, {} trusted IPs, and {} IP configurations",
        example_rules::get_default_allowed_ports().len(),
        example_rules::get_default_trusted_ips().len(),
        example_rules::get_example_ip_configs().len()
    );

    Ok(())
}

/// Add an allowed port
fn add_allowed_port(allowed_ports: &mut HashMap<u32, u32>, port: u16) -> anyhow::Result<()> {
    allowed_ports.insert(port as u32, 1, 0)?;
    Ok(())
}

/// Add a trusted IP
fn add_trusted_ip(allowed_ips: &mut HashMap<u32, u32>, ip: [u8; 4]) -> anyhow::Result<()> {
    allowed_ips.insert(ip_to_u32(ip), 1, 0)?;
    Ok(())
}

/// Add IP-specific configuration
fn add_ip_config(
    allowed_ip_config: &mut HashMap<u32, IpConfig>,
    ip: [u8; 4],
    port: u16,
    protocol: u8,
    allowed: bool,
) -> anyhow::Result<()> {
    let config = IpConfig {
        port: Some(port),
        protocol: Some(protocol),
        allowed,
    };
    allowed_ip_config.insert(ip_to_u32(ip), config, 0)?;
    Ok(())
}

/// List current firewall rules
fn list_firewall_rules(
    allowed_ports: &HashMap<u32, u32>,
    allowed_ips: &HashMap<u32, u32>,
    allowed_ip_config: &HashMap<u32, IpConfig>,
) -> anyhow::Result<()> {
    println!("=== Firewall Rules ===");

    println!("\nAllowed Ports:");
    for result in allowed_ports.iter() {
        if let Ok((port, _)) = result {
            println!("  Port: {}", port);
        }
    }

    println!("\nTrusted IPs:");
    for result in allowed_ips.iter() {
        if let Ok((ip_u32, _)) = result {
            let ip = ip_u32.to_be_bytes();
            println!("  IP: {}", format_ip(ip));
        }
    }

    println!("\nIP Configurations:");
    for result in allowed_ip_config.iter() {
        if let Ok((ip_u32, config)) = result {
            let ip = ip_u32.to_be_bytes();
            let port_str = config
                .port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "any".to_string());
            let protocol_str = config
                .protocol
                .map(|p| match p {
                    6 => "TCP".to_string(),
                    17 => "UDP".to_string(),
                    1 => "ICMP".to_string(),
                    _ => format!("{}", p),
                })
                .unwrap_or_else(|| "any".to_string());
            let action = if config.allowed { "ALLOW" } else { "BLOCK" };
            println!(
                "  IP: {} | Port: {} | Protocol: {} | Action: {}",
                format_ip(ip),
                port_str,
                protocol_str,
                action
            );
        }
    }

    Ok(())
}

/// Show firewall statistics
fn show_firewall_stats(ebpf: &aya::Ebpf) -> anyhow::Result<()> {
    // This would require adding a statistics map to the eBPF program
    // For now, just show a placeholder
    println!("=== Firewall Statistics ===");
    println!("Statistics feature not yet implemented");
    println!("Would show: packets allowed, packets blocked, etc.");
    Ok(())
}
