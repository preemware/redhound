package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// parsePorts parses port specifications like "80,443" or "1-1000" with enhanced validation
func parsePorts(portStr string) ([]uint16, error) {
	if strings.TrimSpace(portStr) == "" {
		return nil, fmt.Errorf("port specification cannot be empty")
	}

	var ports []uint16
	portMap := make(map[uint16]bool) // Avoid duplicates

	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue // Skip empty parts
		}
		
		if strings.Contains(part, "-") {
			// Handle range like "1-1000"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format '%s' (expected: start-end)", part)
			}
			
			startStr := strings.TrimSpace(rangeParts[0])
			endStr := strings.TrimSpace(rangeParts[1])
			
			if startStr == "" || endStr == "" {
				return nil, fmt.Errorf("invalid range format '%s' (start and end cannot be empty)", part)
			}
			
			start, err := strconv.Atoi(startStr)
			if err != nil {
				return nil, fmt.Errorf("invalid start port '%s' in range '%s'", startStr, part)
			}
			
			end, err := strconv.Atoi(endStr)
			if err != nil {
				return nil, fmt.Errorf("invalid end port '%s' in range '%s'", endStr, part)
			}
			
			if start < 1 || start > 65535 {
				return nil, fmt.Errorf("start port %d out of range (1-65535) in '%s'", start, part)
			}
			
			if end < 1 || end > 65535 {
				return nil, fmt.Errorf("end port %d out of range (1-65535) in '%s'", end, part)
			}
			
			if start > end {
				return nil, fmt.Errorf("start port %d cannot be greater than end port %d in '%s'", start, end, part)
			}
			
			// Prevent creating huge ranges that might cause memory issues
			if end-start > 10000 {
				return nil, fmt.Errorf("port range too large (%d ports) in '%s' (max 10000 ports per range)", end-start+1, part)
			}
			
			for i := start; i <= end; i++ {
				port := uint16(i)
				if !portMap[port] {
					ports = append(ports, port)
					portMap[port] = true
				}
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port '%s' (must be a number)", part)
			}
			
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port %d out of range (1-65535)", port)
			}
			
			portUint16 := uint16(port)
			if !portMap[portUint16] {
				ports = append(ports, portUint16)
				portMap[portUint16] = true
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports found in specification '%s'", portStr)
	}

	// Warn about very large port lists
	if len(ports) > 5000 {
		return nil, fmt.Errorf("too many ports specified (%d), maximum is 5000 for performance reasons", len(ports))
	}

	return ports, nil
}

// parseTarget parses a target specification which can be either:
// - A single IP address (e.g., "192.168.1.1")
// - A CIDR range (e.g., "192.168.0.0/24")
func parseTarget(target string) ([]string, error) {
	// Check if it's a CIDR range (contains '/')
	if strings.Contains(target, "/") {
		return cidrHosts(target)
	}

	// It's a single IP address - validate it
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", target)
	}

	// Return single IP as a slice
	return []string{target}, nil
}

// cidrHosts expands an IPv4 CIDR into individual host IP strings.
func cidrHosts(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		ips = append(ips, dup.String())
	}
	if len(ips) <= 2 {
		return nil, errors.New("CIDR too small or invalid")
	}
	return ips[1 : len(ips)-1], nil // drop network & broadcast
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func saveJSON(path string, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// validateProxyURL validates SOCKS proxy URL format
func validateProxyURL(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}

	if u.Scheme != "socks4" && u.Scheme != "socks5" {
		return fmt.Errorf("unsupported proxy type '%s', only socks4 and socks5 are supported", u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("proxy host is required")
	}

	// Validate host:port format
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("invalid host:port format: %v", err)
	}

	if host == "" {
		return fmt.Errorf("proxy host cannot be empty")
	}

	if port == "" {
		return fmt.Errorf("proxy port is required")
	}

	// Validate port range
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port number: %v", err)
	}

	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", portNum)
	}

	return nil
}

// printVersion displays version information
func printVersion() {
	fmt.Printf("redhound v1.2.0\n")
	fmt.Printf("A minimal concurrent network enumerator with SOCKS proxy support\n")
	fmt.Printf("Built with Go %s\n", "1.24+")
	fmt.Printf("https://github.com/preemware/redhound\n")
}

