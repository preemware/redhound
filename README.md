# redhound

A minimal concurrent internal network enumerator written in Go with SOCKS4/5 proxy support.

## Features

- **CIDR Expansion**: Automatically expands CIDR ranges into individual hosts for scanning
- **Concurrent Scanning**: Rate-limited concurrent per-host scans for optimal performance
- **Proxy Support**: Full SOCKS4/5 proxy support for internal network enumeration via pivoting
- **Service Detection**: Advanced service detection via banner grabbing and port-based identification
- **HTTP Enumeration**: Extracts HTTP titles, server information, and web application details
- **SMB Fingerprinting**: Comprehensive SMB/CIFS enumeration including:
  - Domain and computer information extraction
  - Share enumeration and access testing
  - Security misconfiguration detection (null sessions, guest access, etc.)
  - SMB version and dialect detection
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
# Direct scan of a /24 network
./redhound -cidr 192.168.1.0/24 -o results.json -rate 64

# Route all traffic through SOCKS4 proxy
./redhound -cidr 10.0.0.0/24 -proxy socks4://127.0.0.1:1080

# SOCKS5 proxy scan (also supported)
./redhound -cidr 10.0.0.0/24 -proxy socks5://127.0.0.1:9050

# Custom port range scan
./redhound -cidr 192.168.1.0/24 -ports 1-1000 -o detailed_scan.json

# Verbose output with custom settings
./redhound -cidr 10.0.0.0/16 -rate 10 -timeout 10s -v -no-color
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-cidr` | CIDR range to scan (required) | - |
| `-o` | Output JSON file | `results.json` |
| `-rate` | Maximum concurrent host scans | `32` |
| `-timeout` | Per-port connection timeout | `5s` |
| `-proxy` | Proxy URL (socks4\|socks5) | - |
| `-ports` | Port range to scan | Common ports |
| `-no-color` | Disable colored output | `false` |
| `-v` | Enable verbose output | `false` |

### Port Specification

You can specify ports in several formats:
- **Range**: `1-1000` (scan ports 1 through 1000)
- **List**: `80,443,8080,8443` (scan specific ports)
- **Default**: Leave empty to scan common ports (see below)

## Default Port List

The tool scans the following common ports by default:
```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 88 (Kerberos),
110 (POP3), 111 (RPC), 135 (RPC), 139 (NetBIOS), 143 (IMAP), 389 (LDAP),
443 (HTTPS), 445 (SMB), 464 (Kerberos), 636 (LDAPS), 993 (IMAPS), 995 (POP3S),
1433 (SQL Server), 1434 (SQL Browser), 1521 (Oracle), 1723 (PPTP), 2049 (NFS),
3050 (Firebird), 3268 (AD Global Catalog), 3306 (MySQL), 3389 (RDP),
5432 (PostgreSQL), 5900 (VNC), 5984 (CouchDB), 5985 (WinRM HTTP), 5986 (WinRM HTTPS),
6379 (Redis), 7001 (Cassandra), 8000-8090 (Various HTTP), 8181, 8443, 8888,
9000, 9043, 9090, 9200 (Elasticsearch), 9443, 27017 (MongoDB)
```

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
          "security_misconfigs": []
        }
      }
    ]
  }
]
```

## SMB Enumeration Features

The tool performs comprehensive SMB enumeration when SMB ports (139, 445) are detected:

### Information Gathered
- **Domain Information**: Domain name, computer name, DNS details
- **SMB Protocol**: Version, supported dialects, signing requirements
- **Operating System**: Version detection where possible
- **Share Enumeration**: Lists available shares
- **Access Testing**: Tests null sessions, guest access, anonymous access

### Security Misconfiguration Detection
- Null authentication allowed
- Guest account accessible
- Anonymous access permitted
- Share enumeration via SMB protocol
- Weak or default credentials

## Proxy Usage

When using proxy mode, the tool automatically adjusts settings for optimal performance:
- **Rate Limiting**: Automatically reduces concurrent scans to 10 for proxy connections
- **Timeout**: Increases timeout to 10 seconds for proxy connections
- **Connection Routing**: All traffic (including DNS lookups where applicable) routes through the specified proxy

### Supported Proxy Types
- **SOCKS4**: `socks4://127.0.0.1:1080`
- **SOCKS5**: `socks5://127.0.0.1:9050`

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
