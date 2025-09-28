# Nano-Block Firewall Example

This example demonstrates how to use the nano-block crates to build a high-performance eBPF-based firewall.


### Building

```bash
cd example/firewall
cargo build --release
```

### Running

The firewall application provides several commands:

```bash
# Initialize firewall with default rules
./target/release/firewall init

# Add an allowed port
./target/release/firewall add-port 8080

# Block a port
./target/release/firewall block-port 8080

# Add a trusted IP
./target/release/firewall add-trusted-ip 192.168.1.100

# Block an IP
./target/release/firewall block-ip 192.168.1.200

# Add IP-specific configuration
./target/release/firewall add-ip-config 192.168.1.50 3306 tcp true

# Remove allowed IP
./target/release/firewall remove-allowed-ip 192.168.1.100

# Remove blocked IP
./target/release/firewall remove-blocked-ip 192.168.1.200

# List current rules
./target/release/firewall list

# Show statistics
./target/release/firewall stats

# Clear all rules
./target/release/firewall clear

# Run firewall (without XDP attachment in this example)
./target/release/firewall --iface eth0
```

