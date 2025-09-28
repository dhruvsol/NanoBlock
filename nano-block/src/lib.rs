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

impl Protocol {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPortConfig {
    pub port: u16,
    pub protocol: Protocol,
}

// Implement Pod trait for aya eBPF compatibility
unsafe impl Pod for IpPortConfig {}
impl TryFrom<nano_block_ebpf::utils::IpConfig> for IpPortConfig {
    type Error = std::io::Error;

    fn try_from(value: nano_block_ebpf::utils::IpConfig) -> std::result::Result<Self, Self::Error> {
        let protocol = match value.protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid protocol: {}", value.protocol),
                ))
            }
        };
        Ok(Self {
            port: value.port,
            protocol,
        })
    }
}

impl From<IpPortConfig> for nano_block_ebpf::utils::IpConfig {
    fn from(value: IpPortConfig) -> Self {
        Self {
            port: value.port,
            protocol: value.protocol.as_u8(),
        }
    }
}

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
    pub fn new(mut ebpf: aya::Ebpf) -> FirewallResult<Self> {
        let allowed_ports: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.take_map("ALLOWED_PORTS")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_PORTS".to_string()))?,
        )?;
        let allowed_v4_ips: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.take_map("ALLOWED_V4_IPS")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_V4_IPS".to_string()))?,
        )?;
        let allowed_v6_ips: HashMap<_, u128, u32> = HashMap::try_from(
            ebpf.take_map("ALLOWED_V6_IPS")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_V6_IPS".to_string()))?,
        )?;
        let blocked_v4_ips: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.take_map("BLOCKED_V4_IPS")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_V4_IPS".to_string()))?,
        )?;
        let blocked_v6_ips: HashMap<_, u128, u32> = HashMap::try_from(
            ebpf.take_map("BLOCKED_V6_IPS")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_V6_IPS".to_string()))?,
        )?;

        let allowed_v4_configs: HashMap<_, u32, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("ALLOWED_V4_CONFIGS")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_V4_CONFIGS".to_string()))?,
        )?;
        let allowed_v6_configs: HashMap<_, u128, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("ALLOWED_V6_CONFIGS")
                .ok_or_else(|| FirewallError::MapNotFound("ALLOWED_V6_CONFIGS".to_string()))?,
        )?;
        let blocked_v4_configs: HashMap<_, u32, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("BLOCKED_V4_CONFIGS")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_V4_CONFIGS".to_string()))?,
        )?;
        let blocked_v6_configs: HashMap<_, u128, IpPortConfig> = HashMap::try_from(
            ebpf.take_map("BLOCKED_V6_CONFIGS")
                .ok_or_else(|| FirewallError::MapNotFound("BLOCKED_V6_CONFIGS".to_string()))?,
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

    pub async fn list_rules(&self) -> FirewallResult<Vec<String>> {
        let mut rules = vec![];

        // List allowed ports
        rules.push("=== ALLOWED PORTS ===".to_string());
        let allowed_ports = self.allowed_ports.read().await;
        let mut port_count = 0;
        for result in allowed_ports.iter() {
            match result {
                Ok((port, _)) => {
                    rules.push(format!("  Port: {}", port));
                    port_count += 1;
                }
                Err(_) => {}
            }
        }
        if port_count == 0 {
            rules.push("  (No allowed ports configured)".to_string());
        }

        // List allowed IPv4 IPs
        rules.push("\n=== ALLOWED IPv4 ADDRESSES ===".to_string());
        let allowed_v4_ips = self.allowed_v4_ips.read().await;
        let mut v4_count = 0;
        for result in allowed_v4_ips.iter() {
            match result {
                Ok((ip_u32, _)) => {
                    let ip_bytes = ip_u32.to_be_bytes();
                    let ip = format!(
                        "{}.{}.{}.{}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                    );
                    rules.push(format!("  IP: {}", ip));
                    v4_count += 1;
                }
                Err(_e) => {}
            }
        }
        if v4_count == 0 {
            rules.push("  (No allowed IPv4 addresses configured)".to_string());
        }

        // List allowed IPv6 IPs
        rules.push("\n=== ALLOWED IPv6 ADDRESSES ===".to_string());
        let allowed_v6_ips = self.allowed_v6_ips.read().await;
        let mut v6_count = 0;
        for result in allowed_v6_ips.iter() {
            match result {
                Ok((ip_u128, _)) => {
                    let ip_bytes = ip_u128.to_be_bytes();
                    let ip = format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                        ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                        ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
                    );
                    rules.push(format!("  IP: {}", ip));
                    v6_count += 1;
                }
                Err(_e) => {}
            }
        }
        if v6_count == 0 {
            rules.push("  (No allowed IPv6 addresses configured)".to_string());
        }

        // List blocked IPv4 IPs
        rules.push("\n=== BLOCKED IPv4 ADDRESSES ===".to_string());
        let blocked_v4_ips = self.blocked_v4_ips.read().await;
        let mut blocked_v4_count = 0;
        for result in blocked_v4_ips.iter() {
            match result {
                Ok((ip_u32, _)) => {
                    let ip_bytes = ip_u32.to_be_bytes();
                    let ip = format!(
                        "{}.{}.{}.{}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                    );
                    rules.push(format!("  IP: {}", ip));
                    blocked_v4_count += 1;
                }
                Err(_e) => {}
            }
        }
        if blocked_v4_count == 0 {
            rules.push("  (No blocked IPv4 addresses configured)".to_string());
        }

        // List blocked IPv6 IPs
        rules.push("\n=== BLOCKED IPv6 ADDRESSES ===".to_string());
        let blocked_v6_ips = self.blocked_v6_ips.read().await;
        let mut blocked_v6_count = 0;
        for result in blocked_v6_ips.iter() {
            match result {
                Ok((ip_u128, _)) => {
                    let ip_bytes = ip_u128.to_be_bytes();
                    let ip = format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                        ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                        ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
                    );
                    rules.push(format!("  IP: {}", ip));
                    blocked_v6_count += 1;
                }
                Err(_e) => {}
            }
        }
        if blocked_v6_count == 0 {
            rules.push("  (No blocked IPv6 addresses configured)".to_string());
        }

        // List allowed IPv4 configurations
        rules.push("\n=== ALLOWED IPv4 CONFIGURATIONS ===".to_string());
        let allowed_v4_configs = self.allowed_v4_configs.read().await;
        let mut v4_config_count = 0;
        for result in allowed_v4_configs.iter() {
            match result {
                Ok((ip_u32, config)) => {
                    let ip_bytes = ip_u32.to_be_bytes();
                    let ip = format!(
                        "{}.{}.{}.{}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                    );
                    let protocol = match config.protocol {
                        Protocol::Tcp => "TCP",
                        Protocol::Udp => "UDP",
                    };
                    rules.push(format!(
                        "  IP: {} | Port: {} | Protocol: {} | Action: ALLOW",
                        ip, config.port, protocol
                    ));
                    v4_config_count += 1;
                }
                Err(_e) => {}
            }
        }
        if v4_config_count == 0 {
            rules.push("  (No allowed IPv4 configurations configured)".to_string());
        }

        // List allowed IPv6 configurations
        rules.push("\n=== ALLOWED IPv6 CONFIGURATIONS ===".to_string());
        let allowed_v6_configs = self.allowed_v6_configs.read().await;
        let mut v6_config_count = 0;
        for result in allowed_v6_configs.iter() {
            match result {
                Ok((ip_u128, config)) => {
                    let ip_bytes = ip_u128.to_be_bytes();
                    let ip = format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                        ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                        ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
                    );
                    let protocol = match config.protocol {
                        Protocol::Tcp => "TCP",
                        Protocol::Udp => "UDP",
                    };
                    rules.push(format!(
                        "  IP: {} | Port: {} | Protocol: {} | Action: ALLOW",
                        ip, config.port, protocol
                    ));
                    v6_config_count += 1;
                }
                Err(_e) => {}
            }
        }
        if v6_config_count == 0 {
            rules.push("  (No allowed IPv6 configurations configured)".to_string());
        }

        // List blocked IPv4 configurations
        rules.push("\n=== BLOCKED IPv4 CONFIGURATIONS ===".to_string());
        let blocked_v4_configs = self.blocked_v4_configs.read().await;
        let mut blocked_v4_config_count = 0;
        for result in blocked_v4_configs.iter() {
            match result {
                Ok((ip_u32, config)) => {
                    let ip_bytes = ip_u32.to_be_bytes();
                    let ip = format!(
                        "{}.{}.{}.{}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                    );
                    let protocol = match config.protocol {
                        Protocol::Tcp => "TCP",
                        Protocol::Udp => "UDP",
                    };
                    rules.push(format!(
                        "  IP: {} | Port: {} | Protocol: {} | Action: BLOCK",
                        ip, config.port, protocol
                    ));
                    blocked_v4_config_count += 1;
                }
                Err(_e) => {}
            }
        }
        if blocked_v4_config_count == 0 {
            rules.push("  (No blocked IPv4 configurations configured)".to_string());
        }

        // List blocked IPv6 configurations
        rules.push("\n=== BLOCKED IPv6 CONFIGURATIONS ===".to_string());
        let blocked_v6_configs = self.blocked_v6_configs.read().await;
        let mut blocked_v6_config_count = 0;
        for result in blocked_v6_configs.iter() {
            match result {
                Ok((ip_u128, config)) => {
                    let ip_bytes = ip_u128.to_be_bytes();
                    let ip = format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                        ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                        ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
                    );
                    let protocol = match config.protocol {
                        Protocol::Tcp => "TCP",
                        Protocol::Udp => "UDP",
                    };
                    rules.push(format!(
                        "  IP: {} | Port: {} | Protocol: {} | Action: BLOCK",
                        ip, config.port, protocol
                    ));
                    blocked_v6_config_count += 1;
                }
                Err(_e) => {}
            }
        }
        if blocked_v6_config_count == 0 {
            rules.push("  (No blocked IPv6 configurations configured)".to_string());
        }

        Ok(rules)
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

    pub async fn block_port(&mut self, port: u16) -> FirewallResult<()> {
        if port == 0 {
            return Err(FirewallError::InvalidPort(port));
        }

        let mut allowed_ports = self.allowed_ports.write().await;
        allowed_ports.remove(&(port as u32)).map_err(|e| {
            FirewallError::MapOperation(format!("Failed to remove port {}: {}", port, e))
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
