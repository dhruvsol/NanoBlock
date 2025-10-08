# NanoBlock

A lightweight, high-performance firewall library for Rust that uses XDP (eXpress Data Path) to provide fast and efficient network traffic filtering at the kernel level.

## ⚠️ **IMPORTANT SAFETY WARNING** ⚠️

**🚨 BY DEFAULT, EVERYTHING IS BLOCKED ON TCP AND UDP 🚨**

This firewall library blocks all traffic by default. **BE EXTREMELY CAREFUL** when using it to avoid locking yourself out of your system:

- **Always ensure SSH access** before deploying rules
- **Test in a safe environment** first (VM, test machine)
- **Have a backup access method** (console, KVM, etc.)
- **Start with permissive rules** and gradually tighten them
- **Never deploy on production systems** without thorough testing

**If you get locked out, you may need physical/console access to recover!**

## Features

- **High Performance**: Uses XDP for kernel-level packet filtering
- **Low Latency**: Packet processing before kernel network stack
- **IPv4 & IPv6 Support**: Handles both IP versions
- **Protocol Support**: TCP and UDP filtering
- **Flexible Rules**: IP-based, port-based, and protocol-based filtering
- **Memory Efficient**: Optimized eBPF bytecode
- **Async Support**: User-space API with async/await

## Architecture

NanoBlock consists of two main components:

### 1. **eBPF Program** (`nano-block-ebpf`)

- Kernel-space packet filtering logic
- XDP-based packet processing
- Multiple eBPF maps for different rule types

### 2. **User-space Library** (`nano-block`)

- `FirewallManager` for rule management
- Async API for configuration
- Type-safe interfaces

## Quick Start

### Prerequisites

1. **Rust Toolchain**:

   ```bash
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   ```

2. **eBPF Tools**:

   ```bash
   cargo install bpf-linker
   ```

3. **System Requirements**:
   - Linux kernel 4.18+ with XDP support
   - Root privileges for eBPF program loading

### Basic Usage

```rust
use nano_block::{FirewallManager, Protocol};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load your eBPF program
    let mut ebpf = aya::Ebpf::load(include_bytes!("path/to/your/program"))?;

    // Create firewall manager
    let mut firewall = FirewallManager::new(&mut ebpf)?;

    // Allow specific ports
    firewall.allow_port(80).await?;   // HTTP
    firewall.allow_port(443).await?;  // HTTPS
    firewall.allow_port(22).await?;   // SSH (CRITICAL!)

    // Allow specific IPs
    firewall.allow_ip("192.168.1.100".parse()?).await?;
    firewall.allow_ip("10.0.0.1".parse()?).await?;

    // Allow specific IP + Port + Protocol combinations
    firewall.allow_ip_port_protocol(
        "192.168.1.50".parse()?,
        3306,
        Protocol::Tcp
    ).await?;

    // Block specific IPs
    firewall.block_ip("192.168.1.200".parse()?).await?;

    // Block specific IP + Port + Protocol combinations
    firewall.block_ip_port_protocol(
        "192.168.1.201".parse()?,
        22,
        Protocol::Tcp
    ).await?;

    Ok(())
}
```

## Example Implementation

For a complete, production-ready firewall implementation, see the [NanoBlock Example Repository](https://github.com/dhruvsol/NanoBlock-example).

## Rule Types

### 1. Port-Based Rules

Allow specific ports for all IPs:

```rust
firewall.allow_port(80).await?;   // Allow HTTP for everyone
firewall.allow_port(443).await?;  // Allow HTTPS for everyone
```

### 2. IP-Based Rules

Allow or block specific IPs:

```rust
firewall.allow_ip("192.168.1.50".parse()?).await?;  // Allow this IP completely
firewall.block_ip("192.168.1.200".parse()?).await?; // Block this IP completely
```

### 3. IP + Port + Protocol Rules

Fine-grained control:

```rust
// Allow specific IP to access specific port with specific protocol
firewall.allow_ip_port_protocol(
    "192.168.1.100".parse()?,
    3306,                    // MySQL port
    Protocol::Tcp
).await?;

// Block specific IP from accessing specific port with specific protocol
firewall.block_ip_port_protocol(
    "192.168.1.201".parse()?,
    22,                      // SSH port
    Protocol::Tcp
).await?;
```

## eBPF Maps

The library uses the following eBPF maps:

- **`ALLOWED_PORTS`**: Global port allowlist
- **`ALLOWED_IP_V4`**: IPv4 IP allowlist
- **`ALLOWED_IP_V6`**: IPv6 IP allowlist
- **`BLOCKED_IP_V4`**: IPv4 IP blocklist
- **`BLOCKED_IP_V6`**: IPv6 IP blocklist
- **`ALLOWED_IP_V4_CONFIG`**: IPv4 IP + Port + Protocol allowlist
- **`ALLOWED_IP_V6_CONFIG`**: IPv6 IP + Port + Protocol allowlist
- **`BLOCKED_IP_V4_CONFIG`**: IPv4 IP + Port + Protocol blocklist
- **`BLOCKED_IP_V6_CONFIG`**: IPv6 IP + Port + Protocol blocklist

## Safety Features

### SSH Protection

**CRITICAL**: Always allow SSH port 22 to prevent lockouts:

```rust
// Always add this first!
firewall.allow_port(22).await?; // SSH port
```

### Safe Defaults

The library operates on a **deny-by-default** policy:

- All traffic is blocked unless explicitly allowed
- No implicit permissions
- Clear rule hierarchy

## Building

```bash
# Build the library
cargo build --release

# Build with examples
cargo build --examples --release
```

## Cross-Compilation

For cross-compilation to different architectures:

```bash
# Install target
rustup target add ${ARCH}-unknown-linux-musl

# Cross-compile
CC=${ARCH}-linux-musl-gcc cargo build --release \
  --target=${ARCH}-unknown-linux-musl
```

## Testing

**⚠️ ALWAYS TEST IN A SAFE ENVIRONMENT FIRST ⚠️**

```bash
# Test in a VM or isolated environment
cargo test

# Test with example firewall
cd example/firewall
cargo build --release
sudo ./target/release/firewall --iface lo  # Start with loopback
```

## API Reference

### FirewallManager

The main interface for managing firewall rules:

```rust
impl FirewallManager {
    // Create new manager from eBPF program
    pub fn new(ebpf: &mut aya::Ebpf) -> FirewallResult<Self>

    // Port management
    pub async fn allow_port(&mut self, port: u16) -> FirewallResult<()>

    // IP management
    pub async fn allow_ip(&mut self, ip: IpAddr) -> FirewallResult<()>
    pub async fn block_ip(&mut self, ip: IpAddr) -> FirewallResult<()>

    // IP + Port + Protocol management
    pub async fn allow_ip_port_protocol(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol
    ) -> FirewallResult<()>

    pub async fn block_ip_port_protocol(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol
    ) -> FirewallResult<()>

    // Rule removal
    pub async fn remove_allowed_ip(&mut self, ip: IpAddr) -> FirewallResult<()>
    pub async fn remove_blocked_ip(&mut self, ip: IpAddr) -> FirewallResult<()>

    // Rule checking
    pub async fn is_port_allowed(&self, port: u16) -> FirewallResult<bool>
    pub async fn is_ip_allowed(&self, ip: IpAddr) -> FirewallResult<bool>
    pub async fn is_ip_blocked(&self, ip: IpAddr) -> FirewallResult<bool>
}
```

### Protocol Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
}
```

### Error Handling

```rust
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
    // ... more error types
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure running with root privileges
2. **Interface Not Found**: Verify interface name with `ip link show`
3. **eBPF Loading Failed**: Check kernel version and eBPF support
4. **Locked Out**: Use console/KVM access to recover

### Recovery

If you get locked out:

1. **Physical Access**: Use console or KVM
2. **Remove eBPF Program**: `sudo bpftool prog list` and unload
3. **Disable Interface**: `sudo ip link set dev eth0 down`
4. **Reboot**: Last resort if other methods fail

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under:

See [LICENSE-MIT](LICENSE-MIT)for details.

## Related Projects

- [NanoBlock Example](https://github.com/dhruvsol/NanoBlock-example) - Complete firewall implementation
- [Aya](https://github.com/aya-rs/aya) - eBPF library for Rust
- [XDP](https://www.iovisor.org/technology/xdp) - eXpress Data Path

---

**Remember: With great power comes great responsibility. Use this library carefully and always maintain access to your systems!**
