package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func createProxyDialer(proxyURL string) (proxy.Dialer, error) {
	if strings.HasPrefix(proxyURL, "socks4://") {
		addr := strings.TrimPrefix(proxyURL, "socks4://")
		return createSOCKS4Dialer(addr)
	} else if strings.HasPrefix(proxyURL, "socks5://") {
		addr := strings.TrimPrefix(proxyURL, "socks5://")
		return proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	} else if !strings.Contains(proxyURL, "://") {
		// Default to SOCKS5 if no scheme specified
		return proxy.SOCKS5("tcp", proxyURL, nil, proxy.Direct)
	}
	return nil, fmt.Errorf("unsupported proxy protocol: %s", proxyURL)
}

// createSOCKS4Dialer creates a SOCKS4 dialer
func createSOCKS4Dialer(proxyAddr string) (proxy.Dialer, error) {
	return &socks4Dialer{proxyAddr: proxyAddr}, nil
}

// socks4Dialer implements proxy.Dialer for SOCKS4
type socks4Dialer struct {
	proxyAddr string
}

func (d *socks4Dialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("SOCKS4 only supports TCP")
	}

	// Connect to SOCKS4 proxy
	conn, err := net.DialTimeout("tcp", d.proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS4 proxy: %w", err)
	}

	// Parse target address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Resolve hostname to IP if needed
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			conn.Close()
			return nil, fmt.Errorf("failed to resolve hostname: %w", err)
		}
		ip = ips[0].To4()
		if ip == nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS4 only supports IPv4")
		}
	}

	// Build SOCKS4 request
	req := make([]byte, 9)
	req[0] = 4                 // SOCKS version
	req[1] = 1                 // CONNECT command
	req[2] = byte(port >> 8)   // Port high byte
	req[3] = byte(port & 0xff) // Port low byte
	copy(req[4:8], ip.To4())   // IP address
	req[8] = 0                 // Null terminator for user ID

	// Send request
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send SOCKS4 request: %w", err)
	}

	// Read response
	resp := make([]byte, 8)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read SOCKS4 response: %w", err)
	}

	// Check response
	if resp[0] != 0 {
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS4 response")
	}
	if resp[1] != 90 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 connection failed (code: %d)", resp[1])
	}

	return conn, nil
}
