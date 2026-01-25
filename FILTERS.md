# Packet Capture Filters Guide

## Overview
BPF and capture filters for network traffic analysis.

## BPF Syntax

### Protocol Filters
- `tcp`, `udp`, `icmp`
- `ip`, `ip6`, `arp`
- `ether`, `wlan`

### Host Filters
- `host 192.168.1.1`
- `src host 10.0.0.1`
- `dst host 172.16.0.1`
- `net 192.168.0.0/24`

### Port Filters
- `port 80`
- `src port 443`
- `dst port 22`
- `portrange 8000-9000`

## Advanced Filters

### Compound Expressions
- `tcp and port 80`
- `host 10.0.0.1 and not port 22`
- `(port 80 or port 443) and src net 192.168.0.0/16`

### Payload Matching
- `tcp[13] & 2 != 0` (SYN)
- `tcp[13] & 16 != 0` (ACK)
- `tcp[13] == 18` (SYN-ACK)

### Size Filters
- `len > 100`
- `greater 1500`
- `less 64`

## Use Cases

### Web Traffic
```
tcp port 80 or tcp port 443
```

### DNS Analysis
```
udp port 53 or tcp port 53
```

### Lateral Movement Detection
```
tcp port 445 or tcp port 139 or tcp port 135
```

## Performance Tips
- Filter early to reduce capture volume
- Use ring buffers for continuous capture

## Legal Notice
Capture only authorized traffic.
