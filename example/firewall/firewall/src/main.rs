use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::{Parser, Subcommand};
use nano_block::{FirewallManager, Protocol, FirewallResult};
#[rustfmt::skip]
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    /// Block a port
    BlockPort { port: u16 },
    /// Add a trusted IP address
    AddTrustedIp { ip: String },
    /// Block an IP address
    BlockIp { ip: String },
    /// Add IP-specific configuration
    AddIpConfig {
        ip: String,
        port: u16,
        protocol: String,
        allowed: bool,
    },
    /// Remove allowed IP
    RemoveAllowedIp { ip: String },
    /// Remove blocked IP
    RemoveBlockedIp { ip: String },
    /// List current firewall rules
    List,
    /// Clear all rules
    Clear,
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

    // Create FirewallManager
    let mut firewall_manager = FirewallManager::new(ebpf)?;

    // Handle commands
    match opt.command {
        Some(Commands::Init) => {
            init_firewall_rules(&mut firewall_manager).await?;
            info!("Firewall initialized with default rules");
        }
        Some(Commands::AddPort { port }) => {
            firewall_manager.allow_port(port).await?;
            info!("Added port {} to allowed ports", port);
        }
        Some(Commands::BlockPort { port }) => {
            firewall_manager.block_port(port).await?;
            info!("Blocked port {}", port);
        }
        Some(Commands::AddTrustedIp { ip }) => {
            let ip_addr: IpAddr = ip.parse()?;
            firewall_manager.allow_ip(ip_addr).await?;
            info!("Added IP {} to trusted IPs", ip);
        }
        Some(Commands::BlockIp { ip }) => {
            let ip_addr: IpAddr = ip.parse()?;
            firewall_manager.block_ip(ip_addr).await?;
            info!("Blocked IP {}", ip);
        }
        Some(Commands::AddIpConfig {
            ip,
            port,
            protocol,
            allowed,
        }) => {
            let ip_addr: IpAddr = ip.parse()?;
            let protocol = match protocol.to_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return Err(anyhow::anyhow!("Invalid protocol: {}. Use 'tcp' or 'udp'", protocol)),
            };
            
            if allowed {
                firewall_manager.allow_ip_port_protocol(ip_addr, port, protocol).await?;
                info!("Added allowed IP configuration for {}: port={}, protocol={}", ip, port, protocol);
            } else {
                firewall_manager.block_ip_port_protocol(ip_addr, port, protocol).await?;
                info!("Added blocked IP configuration for {}: port={}, protocol={}", ip, port, protocol);
            }
        }
        Some(Commands::RemoveAllowedIp { ip }) => {
            let ip_addr: IpAddr = ip.parse()?;
            firewall_manager.remove_allowed_ip(ip_addr).await?;
            info!("Removed allowed IP {}", ip);
        }
        Some(Commands::RemoveBlockedIp { ip }) => {
            let ip_addr: IpAddr = ip.parse()?;
            firewall_manager.remove_blocked_ip(ip_addr).await?;
            info!("Removed blocked IP {}", ip);
        }
        Some(Commands::List) => {
            list_firewall_rules(&firewall_manager).await?;
        }
        Some(Commands::Clear) => {
            firewall_manager.clear_all_rules().await?;
            info!("Cleared all firewall rules");
        }
        None => {
            // No command specified, just run the firewall
            info!("Starting firewall on interface: {}", opt.iface);

            // Initialize with default rules if not already done
            init_firewall_rules(&mut firewall_manager).await?;

            // Note: The XDP program attachment would need to be handled differently
            // since we now use FirewallManager. For now, we'll just show a message.
            info!("Firewall rules initialized. XDP program attachment not implemented in this example.");
            
            let ctrl_c = signal::ctrl_c();
            println!("Firewall running on {}. Waiting for Ctrl-C...", opt.iface);
            ctrl_c.await?;
            println!("Exiting...");
        }
    }

    Ok(())
}

/// Initialize firewall with default rules
async fn init_firewall_rules(firewall_manager: &mut FirewallManager) -> anyhow::Result<()> {
    // Add default allowed ports (HTTP, HTTPS, SSH, DNS)
    let default_ports = [80, 443, 22, 53];
    for &port in &default_ports {
        firewall_manager.allow_port(port).await?;
    }

    let default_ips = [
        "127.0.0.1".parse::<IpAddr>()?,
        "::1".parse::<IpAddr>()?,
    ];
    for ip in &default_ips {
        firewall_manager.allow_ip(*ip).await?;
    }

    let example_configs = [
        ("192.168.1.100".parse::<IpAddr>()?, 8080, Protocol::Tcp),
        ("10.0.0.5".parse::<IpAddr>()?, 3306, Protocol::Tcp),
    ];
    for (ip, port, protocol) in &example_configs {
        firewall_manager.allow_ip_port_protocol(*ip, *port, *protocol).await?;
    }

    info!(
        "Initialized firewall with {} allowed ports, {} trusted IPs, and {} IP configurations",
        default_ports.len(),
        default_ips.len(),
        example_configs.len()
    );

    Ok(())
}

async fn list_firewall_rules(firewall_manager: &FirewallManager) -> anyhow::Result<()> {
    // Use the list_rules method to get all current rules
    match firewall_manager.list_rules().await {
        Ok(rules) => {
            for rule in rules {
                println!("{}", rule);
            }
        }
        Err(e) => {
            println!("Error listing rules: {}", e);
        }
    }

    Ok(())
}
