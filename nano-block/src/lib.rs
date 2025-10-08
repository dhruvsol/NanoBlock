use aya::maps::{HashMap, MapData};
use aya::Pod;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
}

unsafe impl Pod for Protocol {}
impl Protocol {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPortConfig {
    pub port: u16,
    pub protocol: Protocol,
}
unsafe impl Pod for IpPortConfig {}

impl IpPortConfig {
    pub fn new(port: u16, protocol: Protocol) -> Self {
        Self { port, protocol }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("eBPF map operation failed: {0}")]
    MapOperation(String),
    #[error("eBPF map not found: {0}")]
    MapNotFound(String),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Invalid port number: {0}")]
    InvalidPort(u16),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("eBPF map error: {0}")]
    MapError(#[from] aya::maps::MapError),

    #[error("eBPF program not loaded")]
    ProgramNotLoaded,

    #[error("Permission denied - requires root privileges")]
    PermissionDenied,
}

pub type FirewallResult<T> = std::result::Result<T, FirewallError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum InternalIpAddr {
    V4(u32),
    V6(u128),
}

impl From<IpAddr> for InternalIpAddr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => InternalIpAddr::V4(u32::from_be_bytes(ipv4.octets())),
            IpAddr::V6(ipv6) => InternalIpAddr::V6(u128::from_be_bytes(ipv6.octets())),
        }
    }
}

pub struct FirewallManager {
    allowed_ports: Arc<RwLock<HashMap<MapData, u32, u32>>>,
    allowed_v4_ips: Arc<RwLock<HashMap<MapData, u32, u32>>>,
    allowed_v6_ips: Arc<RwLock<HashMap<MapData, u128, u32>>>,
    blocked_v4_ips: Arc<RwLock<HashMap<MapData, u32, u32>>>,
    blocked_v6_ips: Arc<RwLock<HashMap<MapData, u128, u32>>>,
    allowed_v4_configs: Arc<RwLock<HashMap<MapData, u32, IpPortConfig>>>,
    allowed_v6_configs: Arc<RwLock<HashMap<MapData, u128, IpPortConfig>>>,
    blocked_v4_configs: Arc<RwLock<HashMap<MapData, u32, IpPortConfig>>>,
    blocked_v6_configs: Arc<RwLock<HashMap<MapData, u128, IpPortConfig>>>,
}

impl FirewallManager {
    pub fn new(ebpf: &mut aya::Ebpf) -> FirewallResult<Self> {
        let allowed_ports: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.take_map("ALLOWED_PORTS")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_PORTS".to_string()))?,
        )?;
        let allowed_v4_ips: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.take_map("ALLOWED_IP_V4")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_IP_V4".to_string()))?,
        )?;
        let allowed_v6_ips: HashMap<_, u128, u32> = HashMap::try_from(
            ebpf.take_map("ALLOWED_IP_V6")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_IP_V6".to_string()))?,
        )?;
        let blocked_v4_ips: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.take_map("BLOCKED_IP_V4")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_IP_V4".to_string()))?,
        )?;
        let blocked_v6_ips: HashMap<_, u128, u32> = HashMap::try_from(
            ebpf.take_map("BLOCKED_IP_V6")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_IP_V6".to_string()))?,
        )?;

        let allowed_v4_configs: HashMap<_, u32, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("ALLOWED_V4_CONFIG")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_V4_CONFIG".to_string()))?,
        )?;
        let allowed_v6_configs: HashMap<_, u128, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("ALLOWED_V6_CONFIG")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_V6_CONFIG".to_string()))?,
        )?;
        let blocked_v4_configs: HashMap<_, u32, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("BLOCKED_V4_CONFIG")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_V4_CONFIG".to_string()))?,
        )?;
        let blocked_v6_configs: HashMap<_, u128, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("BLOCKED_V6_CONFIG")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_V6_CONFIG".to_string()))?,
        )?;
        Ok(Self {
            allowed_ports: Arc::new(RwLock::new(allowed_ports)),
            allowed_v4_ips: Arc::new(RwLock::new(allowed_v4_ips)),
            allowed_v6_ips: Arc::new(RwLock::new(allowed_v6_ips)),
            blocked_v4_ips: Arc::new(RwLock::new(blocked_v4_ips)),
            blocked_v6_ips: Arc::new(RwLock::new(blocked_v6_ips)),
            allowed_v4_configs: Arc::new(RwLock::new(allowed_v4_configs)),
            allowed_v6_configs: Arc::new(RwLock::new(allowed_v6_configs)),
            blocked_v4_configs: Arc::new(RwLock::new(blocked_v4_configs)),
            blocked_v6_configs: Arc::new(RwLock::new(blocked_v6_configs)),
        })
    }

    pub async fn allow_port(&mut self, port: u16) -> FirewallResult<()> {
        if port == 0 {
            return Err(FirewallError::InvalidPort(port));
        }

        // Update in-memory storage
        let mut allowed_ports = self.allowed_ports.write().await;
        allowed_ports.insert(port as u32, 1, 0).map_err(|e| {
            FirewallError::MapOperation(format!("Failed to insert port {}: {}", port, e))
        })?;

        Ok(())
    }

    pub async fn allow_ip(&mut self, ip: IpAddr) -> FirewallResult<()> {
        let internal_ip = InternalIpAddr::from(ip);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let mut allowed_v4_ips = self.allowed_v4_ips.write().await;
                allowed_v4_ips.insert(ipv4, 1, 0).map_err(|e| {
                    FirewallError::MapOperation(format!("Failed to insert IPv4 {}: {}", ip, e))
                })?;
            }
            InternalIpAddr::V6(ipv6) => {
                let mut allowed_v6_ips = self.allowed_v6_ips.write().await;
                allowed_v6_ips.insert(ipv6, 1, 0).map_err(|e| {
                    FirewallError::MapOperation(format!("Failed to insert IPv6 {}: {}", ip, e))
                })?;
            }
        }

        Ok(())
    }

    pub async fn block_ip(&mut self, ip: IpAddr) -> FirewallResult<()> {
        let internal_ip = InternalIpAddr::from(ip);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let mut blocked_v4_ips = self.blocked_v4_ips.write().await;
                blocked_v4_ips.insert(ipv4, 1, 0).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to insert blocked IPv4 {}: {}",
                        ip, e
                    ))
                })?;
                // In a real implementation: self.update_ebpf_map("BLOCKED_IP_V4", ipv4, 1).await?;
            }
            InternalIpAddr::V6(ipv6) => {
                let mut blocked_v6_ips = self.blocked_v6_ips.write().await;
                blocked_v6_ips.insert(ipv6, 1, 0).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to insert blocked IPv6 {}: {}",
                        ip, e
                    ))
                })?;
                // In a real implementation: self.update_ebpf_map("BLOCKED_IP_V6", ipv6, 1).await?;
            }
        }

        Ok(())
    }

    pub async fn allow_ip_port_protocol(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
    ) -> FirewallResult<()> {
        if port == 0 {
            return Err(FirewallError::InvalidPort(port));
        }

        let internal_ip = InternalIpAddr::from(ip);
        let config = IpPortConfig::new(port, protocol);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let mut allowed_v4_configs = self.allowed_v4_configs.write().await;
                allowed_v4_configs.insert(ipv4, config, 0).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to insert IPv4 config for {}:{}: {}",
                        ip, port, e
                    ))
                })?;
            }
            InternalIpAddr::V6(ipv6) => {
                let mut allowed_v6_configs = self.allowed_v6_configs.write().await;
                allowed_v6_configs.insert(ipv6, config, 0).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to insert IPv6 config for {}:{}: {}",
                        ip, port, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub async fn block_ip_port_protocol(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
    ) -> FirewallResult<()> {
        if port == 0 {
            return Err(FirewallError::InvalidPort(port));
        }

        let internal_ip = InternalIpAddr::from(ip);
        let config = IpPortConfig::new(port, protocol);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let mut blocked_v4_configs = self.blocked_v4_configs.write().await;
                blocked_v4_configs.insert(ipv4, config, 0).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to insert blocked IPv4 config for {}:{}: {}",
                        ip, port, e
                    ))
                })?;
            }
            InternalIpAddr::V6(ipv6) => {
                let mut blocked_v6_configs = self.blocked_v6_configs.write().await;
                blocked_v6_configs.insert(ipv6, config, 0).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to insert blocked IPv6 config for {}:{}: {}",
                        ip, port, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub async fn remove_allowed_ip(&mut self, ip: IpAddr) -> FirewallResult<()> {
        let internal_ip = InternalIpAddr::from(ip);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let mut allowed_v4_ips = self.allowed_v4_ips.write().await;
                allowed_v4_ips.remove(&ipv4).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to remove allowed IPv4 {}: {}",
                        ip, e
                    ))
                })?;
            }
            InternalIpAddr::V6(ipv6) => {
                let mut allowed_v6_ips = self.allowed_v6_ips.write().await;
                allowed_v6_ips.remove(&ipv6).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to remove allowed IPv6 {}: {}",
                        ip, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub async fn remove_blocked_ip(&mut self, ip: IpAddr) -> FirewallResult<()> {
        let internal_ip = InternalIpAddr::from(ip);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let mut blocked_v4_ips = self.blocked_v4_ips.write().await;
                blocked_v4_ips.remove(&ipv4).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to remove blocked IPv4 {}: {}",
                        ip, e
                    ))
                })?;
            }
            InternalIpAddr::V6(ipv6) => {
                let mut blocked_v6_ips = self.blocked_v6_ips.write().await;
                blocked_v6_ips.remove(&ipv6).map_err(|e| {
                    FirewallError::MapOperation(format!(
                        "Failed to remove blocked IPv6 {}: {}",
                        ip, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub async fn is_port_allowed(&self, port: u16) -> FirewallResult<bool> {
        let allowed_ports = self.allowed_ports.read().await;
        match allowed_ports.get(&(port as u32), 0) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn is_ip_allowed(&self, ip: IpAddr) -> FirewallResult<bool> {
        let internal_ip = InternalIpAddr::from(ip);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let allowed_v4_ips = self.allowed_v4_ips.read().await;
                match allowed_v4_ips.get(&ipv4, 0) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            InternalIpAddr::V6(ipv6) => {
                let allowed_v6_ips = self.allowed_v6_ips.read().await;
                match allowed_v6_ips.get(&ipv6, 0) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    pub async fn is_ip_blocked(&self, ip: IpAddr) -> FirewallResult<bool> {
        let internal_ip = InternalIpAddr::from(ip);

        match internal_ip {
            InternalIpAddr::V4(ipv4) => {
                let blocked_v4_ips = self.blocked_v4_ips.read().await;
                match blocked_v4_ips.get(&ipv4, 0) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            InternalIpAddr::V6(ipv6) => {
                let blocked_v6_ips = self.blocked_v6_ips.read().await;
                match blocked_v6_ips.get(&ipv6, 0) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }
}
