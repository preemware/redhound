# redhound

A minimal concurrent internal network enumerator written in Go with SOCKS4/5 proxy support.

## Features

- **Flexible Targeting**: Supports both single IP addresses and CIDR ranges for scanning
- **Concurrent Scanning**: Rate-limited concurrent per-host scans for optimal performance
- **Proxy Support**: Full SOCKS4/5 proxy support for internal network enumeration via pivoting
- **Service Detection**: Advanced service detection via banner grabbing and port-based identification
- **HTTP Enumeration**: Extracts HTTP titles, server information, and web application details
- **LDAP Enumeration**: Comprehensive LDAP enumeration and fingerprinting
- **SMB Fingerprinting**: Comprehensive SMB/CIFS enumeration including:
  - Domain and computer information extraction
  - Share enumeration and access testing
  - Security misconfiguration detection (null sessions, guest access, etc.)
  - SMB version and dialect detection
  - MS17-010 vulnerability detection
- **JSON Output**: Structured JSON output for easy integration with other tools
- **No External Dependencies**: Pure Go implementation with minimal dependencies

## Installation

### Prerequisites
- Go ≥1.20

### Build from Source
```bash
git clone https://github.com/preemware/redhound.git
cd redhound
go build .
```

## Usage

### Basic Examples

```bash
# Scan a single host
./redhound 192.168.1.100 -o results.json

# Direct scan of a /24 network
./redhound 192.168.1.0/24 -o results.json -r 64

# Route all traffic through SOCKS4 proxy
./redhound 10.0.0.0/24 -p socks4://127.0.0.1:1080

# SOCKS5 proxy scan (also supported)
./redhound 10.0.0.0/24 -p socks5://127.0.0.1:9050

# Custom port range scan
./redhound 192.168.1.0/24 -P 1-1000 -o detailed_scan.json

# Verbose output with custom settings
./redhound 10.0.0.0/16 -r 10 -t 10s -v -n
```

### Command Line Options

**Usage:** `./redhound [options] <target>`

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `<target>` | | Target to scan: single IP or CIDR range (required positional argument) | - |
| `-o` | | Output JSON file | `results.json` |
| `-rate` | `-r` | Maximum concurrent host scans | `32` |
| `-timeout` | `-t` | Per-port connection timeout | `5s` |
| `-proxy` | `-p` | Proxy URL (socks4\|socks5) | - |
| `-ports` | `-P` | Port range to scan | Common ports |
| `-no-color` | `-n` | Disable colored output | `false` |
| `-v` | | Enable verbose output | `false` |

### Port Specification

You can specify ports in several formats:
- **Range**: `-P 1-1000` (scan ports 1 through 1000)
- **List**: `-P 80,443,8080,8443` (scan specific ports)
- **Default**: Leave empty to scan common ports (see below)

### Target Specification

You can specify targets as positional arguments in two formats:
- **Single IP**: `./redhound 192.168.1.100` (scan a single host)
- **CIDR Range**: `./redhound 192.168.1.0/24` (scan entire subnet)

## Output Format

The tool outputs results in JSON format with detailed service information:

```json
[
  {
    "ip": "192.168.1.100",
    "hostname": "dc01.example.local",
    "services": [
      {
        "port": 80,
        "protocol": "tcp",
        "name": "http",
        "product": "Microsoft IIS",
        "version": "10.0",
        "state": "open",
        "banner": "HTTP/1.1 200 OK | Server: Microsoft-IIS/10.0",
        "title": "IIS Windows Server - Welcome"
      },
      {
        "port": 445,
        "protocol": "tcp",
        "name": "smb",
        "state": "open",
        "smb": {
          "domain": "EXAMPLE",
          "computer": "DC01",
          "netbios_name": "DC01",
          "netbios_domain": "EXAMPLE",
          "dns_name": "dc01.example.local",
          "dns_domain": "example.local",
          "os_version": "Windows Server 2019",
          "smb_version": "SMB 3.1.1",
          "signing": true,
          "shares": ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"],
          "null_session": false,
          "guest_access": false,
          "security_misconfigs": [],
          "ms17_010": false
        }
      },
      {
        "port": 389,
        "protocol": "tcp",
        "name": "ldap",
        "state": "open",
        "ldap": {
          "naming_contexts": ["DC=example,DC=local"],
          "domain_name": "example.local",
          "forest_name": "example.local",
          "domain_controller": "dc01.example.local",
          "domain_functionality": "2016",
          "forest_functionality": "2016"
        }
      }
    ]
  }
]
```

## Service Enumeration Features

### SMB Enumeration
- **Domain Information**: Domain name, computer name, DNS details
- **SMB Protocol**: Version, supported dialects, signing requirements
- **Operating System**: Version detection where possible
- **Share Enumeration**: Lists available shares
- **Access Testing**: Tests null sessions, guest access, anonymous access
- **MS17-010**: Detection of EternalBlue vulnerability

### LDAP Enumeration
- **Domain Information**: Domain and forest names
- **Functionality Levels**: Domain and forest functionality levels
- **Naming Contexts**: Available LDAP naming contexts
- **Domain Controller**: Primary DC identification
- **Security Settings**: LDAP security configuration detection

### HTTP Enumeration
- **Server Information**: Web server type and version (Apache, nginx, IIS, Tomcat, etc.)
- **Title Extraction**: Page titles and basic content analysis
- **Technology Detection**: PHP, ASP.NET, and other platform identification
- **Extended Port Coverage**: Supports 80+ HTTP-related ports

### SSH Enumeration
- **Version Detection**: SSH protocol version (1.x/2.x)
- **Implementation**: OpenSSH, Dropbear, and other SSH server identification
- **Banner Analysis**: Detailed SSH banner parsing

### FTP Enumeration
- **Server Detection**: vsftpd, ProFTPD, Pure-FTPd, FileZilla, Microsoft FTP
- **Anonymous Access**: Tests for anonymous login capabilities
- **Banner Analysis**: Comprehensive FTP banner examination

### Database Enumeration
- **Redis**: Version detection and service verification
- **MongoDB**: Connection testing and basic fingerprinting
- **Multi-Database Support**: Enhanced detection for MySQL, PostgreSQL, Oracle, MSSQL, and more

### Remote Access Services
- **VNC**: Version detection and implementation identification (RealVNC, TightVNC, UltraVNC)
- **Telnet**: Protocol negotiation detection and banner capture
- **Docker API**: Version detection and API endpoint identification

### Network Services
- **SNMP**: Service detection and basic enumeration
- **Enhanced Coverage**: Support for 200+ additional service types including industrial protocols, IoT devices, and cloud services

## Proxy Usage

When using proxy mode, the tool automatically adjusts settings for optimal performance:
- **Rate Limiting**: Automatically reduces concurrent scans to 10 for proxy connections
- **Timeout**: Increases timeout to 10 seconds for proxy connections
- **Connection Routing**: All traffic (including DNS lookups where applicable) routes through the specified proxy

### Supported Proxy Types
- **SOCKS4**: `-p socks4://127.0.0.1:1080`
- **SOCKS5**: `-p socks5://127.0.0.1:9050`

## Performance Considerations

### Direct Scanning
- Default rate: 32 concurrent hosts
- Default timeout: 5 seconds per port
- Up to 20 concurrent ports per host

### Proxy Scanning
- Recommended rate: 10 concurrent hosts (auto-adjusted)
- Recommended timeout: 10 seconds per port (auto-adjusted)
- More conservative settings to prevent proxy overload

## Contributing

Contributions are welcome! Please ensure all contributions maintain the tool's focus on simplicity and effectiveness for internal network enumeration.
