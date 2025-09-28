# NanoBlock - High-Performance eBPF Firewall

A user-friendly client library for managing eBPF-based firewall rules. This library provides a clean API that abstracts away the complexity of eBPF maps and allows users to manage firewall rules using standard Rust types.

## Features

- **IPv4 and IPv6 Support**: Full support for both IP address families
- **Port-based Rules**: Allow or block specific ports globally
- **IP-based Rules**: Allow or block specific IP addresses
- **Granular Control**: IP + Port + Protocol combinations
- **High Performance**: eBPF-based packet filtering at kernel level
- **Async/Await Support**: Built with Tokio for modern async Rust applications
- **Type Safety**: Uses standard Rust networking types (`std::net::IpAddr`, etc.)
- **Configuration Builder**: Fluent API for building complex firewall configurations

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
nano-block = "0.1.0"
tokio = { version = "1.0", features = ["rt", "rt-multi-thread", "sync"] }
```

## Basic Usage

```rust
use nano_block::{FirewallManager, Protocol};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create firewall manager
    let mut firewall = FirewallManager::new()?;

    // Allow SSH (port 22) from anywhere
    firewall.allow_port(22).await?;

    // Block a specific IP address
    let malicious_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    firewall.block_ip(malicious_ip).await?;

    // Allow specific IP to access HTTP (port 80) with TCP
    let trusted_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    firewall.allow_ip_port_protocol(trusted_ip, 80, Protocol::Tcp).await?;

    Ok(())
}
```

## Configuration Builder

Use the fluent configuration builder for complex setups:

```rust
use nano_block::{FirewallConfig, Protocol};
use std::net::{IpAddr, Ipv4Addr};

let config = FirewallConfig::new()
    .allow_port(80)   // HTTP
    .allow_port(443)  // HTTPS
    .allow_port(22)   // SSH
    .allow_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    .block_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .allow_ip_port_protocol(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        3306,
        Protocol::Tcp,
    );

// Apply configuration to firewall
config.apply(&mut firewall).await?;
```

## API Reference

### FirewallManager

The main interface for managing firewall rules.

#### Core Methods

- `new()` - Create a new firewall manager
- `allow_port(port: u16)` - Allow a port for all IPs
- `block_port(port: u16)` - Block a port for all IPs
- `allow_ip(ip: IpAddr)` - Allow an IP to access any port
- `block_ip(ip: IpAddr)` - Block an IP from accessing any port
- `allow_ip_port_protocol(ip, port, protocol)` - Allow specific IP+Port+Protocol
- `block_ip_port_protocol(ip, port, protocol)` - Block specific IP+Port+Protocol

#### Utility Methods

- `remove_allowed_ip(ip)` - Remove IP from allowed list
- `remove_blocked_ip(ip)` - Remove IP from blocked list
- `get_allowed_ports()` - Get all allowed ports
- `get_allowed_v4_ips()` - Get all allowed IPv4 addresses
- `get_allowed_v6_ips()` - Get all allowed IPv6 addresses
- `get_blocked_v4_ips()` - Get all blocked IPv4 addresses
- `get_blocked_v6_ips()` - Get all blocked IPv6 addresses
- `clear_all_rules()` - Remove all firewall rules

### Protocol

Supported protocols:

- `Protocol::Tcp` - Transmission Control Protocol (port 6)
- `Protocol::Udp` - User Datagram Protocol (port 17)

### FirewallConfig

Configuration builder for setting up multiple rules at once:

- `new()` - Create new configuration
- `allow_port(port)` - Add port to allowed list
- `allow_ip(ip)` - Add IP to allowed list
- `block_ip(ip)` - Add IP to blocked list
- `allow_ip_port_protocol(ip, port, protocol)` - Add specific rule
- `block_ip_port_protocol(ip, port, protocol)` - Add specific block rule
- `apply(firewall)` - Apply configuration to firewall manager

## Error Handling

The library uses a custom `FirewallError` enum for error handling:

```rust
use nano_block::FirewallError;

match firewall.allow_port(0).await {
    Ok(()) => println!("Port allowed successfully"),
    Err(FirewallError::InvalidPort(port)) => {
        println!("Invalid port number: {}", port);
    }
    Err(e) => println!("Other error: {}", e),
}
```

## Examples

See the `examples/` directory for more detailed usage examples:

- `basic_usage.rs` - Comprehensive example showing all features

## Architecture

This client library is designed to work with the eBPF-based packet filtering system. The actual eBPF program runs in the kernel and performs high-performance packet filtering, while this client library provides a user-friendly interface for managing the rules.

### Key Design Principles

1. **Abstraction**: Hide eBPF complexity from users
2. **Type Safety**: Use standard Rust types (`IpAddr`, `Ipv4Addr`, `Ipv6Addr`)
3. **Performance**: Async operations with minimal overhead
4. **Flexibility**: Support both simple and complex rule configurations
5. **Safety**: Comprehensive error handling and validation

## Testing

Run the test suite:

```bash
cargo test
```

Run the example:

```bash
cargo run --example basic_usage
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
