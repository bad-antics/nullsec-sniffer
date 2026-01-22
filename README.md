# nullsec-sniffer

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
      ░   ░    ░   ░       ░       ░         ░     ░   ░ ░      
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ S N I F F E R ░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Clojure](https://img.shields.io/badge/Clojure-5881D8?style=for-the-badge&logo=clojure&logoColor=white)

## Overview

**nullsec-sniffer** is a network packet analyzer written in Clojure. Leverages JVM performance with Lisp expressiveness for protocol dissection, pattern matching, and data extraction.

## Features

- 📦 **Packet Capture** - Raw socket packet capture
- 🔍 **Protocol Analysis** - TCP, UDP, ICMP, HTTP, DNS dissection
- 🎯 **Pattern Matching** - Regex-based content filtering
- 📊 **Statistics** - Real-time traffic statistics
- 💾 **PCAP Export** - Save captures in standard format
- 🔐 **Credential Extraction** - Automatic credential detection

## Requirements

- Clojure 1.11+
- Java 11+
- libpcap (Linux) / WinPcap (Windows)
- Root/Administrator privileges

## Installation

```bash
# Clone repository
git clone https://github.com/bad-antics/nullsec-sniffer.git
cd nullsec-sniffer

# Run with Clojure CLI
clj -M sniffer.clj

# Or build uberjar
clj -T:build uber
java -jar target/sniffer.jar
```

## Usage

```bash
# Start capture on interface
clj -M sniffer.clj capture -i eth0

# Capture with filter
clj -M sniffer.clj capture -i eth0 -f "tcp port 80"

# Extract credentials
clj -M sniffer.clj capture -i eth0 --extract-creds

# Save to PCAP
clj -M sniffer.clj capture -i eth0 -o capture.pcap

# Analyze existing capture
clj -M sniffer.clj analyze -f capture.pcap
```

## Options

| Flag | Description |
|------|-------------|
| `-i, --interface` | Network interface to capture |
| `-f, --filter` | BPF filter expression |
| `-o, --output` | Output file (PCAP format) |
| `-c, --count` | Number of packets to capture |
| `--extract-creds` | Extract credentials |
| `--stats` | Show traffic statistics |
| `-v, --verbose` | Verbose output |

## Supported Protocols

- **Layer 2**: Ethernet, ARP
- **Layer 3**: IPv4, IPv6, ICMP
- **Layer 4**: TCP, UDP
- **Layer 7**: HTTP, FTP, SMTP, POP3, DNS, Telnet

## Credential Detection

Automatically extracts:
- HTTP Basic/Digest Auth
- FTP credentials
- SMTP/POP3 logins
- Telnet sessions
- Form submissions

## Disclaimer

This tool is intended for authorized network testing and educational purposes only. Unauthorized packet capture is illegal.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*Part of the NullSec Security Toolkit*
