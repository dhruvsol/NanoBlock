# Nano-Block Firewall Example

This example demonstrates how to use the nano-block library to create a high-performance eBPF-based firewall with XDP (eXpress Data Path).

## Features

- **High Performance**: Uses XDP for packet filtering at the kernel level
- **Flexible Rules**: Support for IP-based, port-based, and protocol-based filtering
- **SSH Protection**: SSH port 22 is always allowed to prevent lockouts
- **Dynamic Configuration**: Add/remove rules at runtime
- **IPv4 and IPv6 Support**: Handles both IP versions
- **Protocol Support**: TCP, UDP, and ICMP filtering

## Architecture

The firewall consists of three main components:

1. **firewall-ebpf**: The eBPF program that runs in the kernel
2. **firewall-common**: Shared types and constants
3. **firewall**: User-space program for configuration and management

## Building

```bash
cd example/firewall
cargo build --release
```

## Usage

### Basic Firewall Operation

Start the firewall on a network interface:

```bash
sudo ./target/release/firewall --iface eth0
```

### Command Line Interface

The firewall supports various commands for configuration:

#### Initialize with Default Rules

```bash
sudo ./target/release/firewall --iface eth0 init
```

This sets up:

- **Allowed Ports**: SSH (22), HTTP (80), HTTPS (443), DNS (53), NTP (123)
- **Trusted IPs**: localhost (127.0.0.1), 10.0.0.1, 192.168.1.1
- **IP Configurations**: Example rules for specific IPs

#### Add Allowed Ports

```bash
# Allow web server port
sudo ./target/release/firewall --iface eth0 add-port 8080

# Allow MySQL port
sudo ./target/release/firewall --iface eth0 add-port 3306
```

#### Add Trusted IPs

```bash
# Add a trusted IP that can access any port
sudo ./target/release/firewall --iface eth0 add-trusted-ip 192.168.1.50

# Add another trusted IP
sudo ./target/release/firewall --iface eth0 add-trusted-ip 10.0.0.100
```

#### Add IP-Specific Configurations

```bash
# Allow specific IP to access MySQL on TCP
sudo ./target/release/firewall --iface eth0 add-ip-config 192.168.1.100 3306 6 true

# Block specific IP from accessing database
sudo ./target/release/firewall --iface eth0 add-ip-config 192.168.1.200 3306 6 false
```

#### List Current Rules

```bash
sudo ./target/release/firewall --iface eth0 list
```

#### Show Statistics

```bash
sudo ./target/release/firewall --iface eth0 stats
```

## Rule Types

### 1. Port-Based Rules

- Allow specific ports for all IPs
- Example: Allow HTTP (80) and HTTPS (443) for everyone

### 2. IP-Based Rules

- Trust specific IPs to access any port
- Example: Trust admin IPs to access any service

### 3. IP-Specific Configurations

- Fine-grained control: IP + Port + Protocol + Action
- Example: Allow 192.168.1.100 to access MySQL (3306) on TCP only

## Protocol Support

- **TCP (6)**: Most common protocol for web, database, SSH
- **UDP (17)**: DNS, NTP, some streaming protocols
- **ICMP (1)**: Ping and network diagnostics
- **Any (0)**: Match any protocol

## Safety Features

### SSH Protection

SSH port 22 is **always allowed** regardless of other rules to prevent accidental lockouts:

```rust
// This check happens in both IPv4 and IPv6 packet processing
if dest_port == 22 {
    return Ok(XDP_PASS); // Always allow SSH
}
```

### Default Rules

The firewall initializes with safe defaults:

- Common ports (HTTP, HTTPS, DNS, NTP) are allowed
- Localhost is always trusted
- SSH is always allowed

## Example Scenarios

### Scenario 1: Web Server Protection

```bash
# Initialize firewall
sudo ./target/release/firewall --iface eth0 init

# Allow web server port
sudo ./target/release/firewall --iface eth0 add-port 8080

# Trust admin IP
sudo ./target/release/firewall --iface eth0 add-trusted-ip 192.168.1.10

# Block specific IP from accessing database
sudo ./target/release/firewall --iface eth0 add-ip-config 192.168.1.200 3306 6 false
```

### Scenario 2: Database Server

```bash
# Initialize firewall
sudo ./target/release/firewall --iface eth0 init

# Allow database port for specific IPs only
sudo ./target/release/firewall --iface eth0 add-ip-config 192.168.1.100 3306 6 true
sudo ./target/release/firewall --iface eth0 add-ip-config 192.168.1.101 3306 6 true

# Block all other access to database
# (Default behavior - only explicitly allowed IPs can access)
```

### Scenario 3: Development Environment

```bash
# Initialize firewall
sudo ./target/release/firewall --iface eth0 init

# Allow development ports
sudo ./target/release/firewall --iface eth0 add-port 3000  # React dev server
sudo ./target/release/firewall --iface eth0 add-port 8080  # Backend API
sudo ./target/release/firewall --iface eth0 add-port 5432  # PostgreSQL

# Trust development team IPs
sudo ./target/release/firewall --iface eth0 add-trusted-ip 192.168.1.50
sudo ./target/release/firewall --iface eth0 add-trusted-ip 192.168.1.51
```

## Performance

The firewall operates at the kernel level using XDP, providing:

- **Low Latency**: Packet filtering happens before kernel network stack
- **High Throughput**: Can handle millions of packets per second
- **Low CPU Usage**: Efficient eBPF bytecode execution

## Troubleshooting

### Cannot Access SSH

SSH port 22 is always allowed. If you can't access SSH:

1. Check if the firewall is running on the correct interface
2. Verify network connectivity
3. Check if another firewall is blocking access

### Rules Not Working

1. Verify the interface name is correct (`ip link show`)
2. Check if rules were added successfully (`list` command)
3. Ensure the eBPF program is loaded (`bpftool prog list`)

### Performance Issues

1. Monitor CPU usage during high traffic
2. Consider reducing rule complexity
3. Use trusted IP rules for frequently accessed services

## Development

### Adding New Features

1. Update `firewall-common/src/lib.rs` for shared types
2. Modify `firewall-ebpf/src/main.rs` for eBPF logic
3. Update `firewall/src/main.rs` for user-space interface

### Testing

```bash
# Build and test
cargo build --release

# Test with different interfaces
sudo ./target/release/firewall --iface lo    # Loopback
sudo ./target/release/firewall --iface eth0  # Ethernet
```

## Security Considerations

- Always test rules in a safe environment first
- Keep SSH access available during testing
- Monitor logs for blocked connections
- Regularly review and update rules
- Consider using fail2ban for additional protection

## License

This example is part of the nano-block project and follows the same licensing terms.
