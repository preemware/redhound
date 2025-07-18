package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// parsePorts parses port specifications like "80,443" or "1-1000"
func parsePorts(portStr string) ([]uint16, error) {
	var ports []uint16

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Handle range like "1-1000"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			for i := start; i <= end; i++ {
				if i > 0 && i <= 65535 {
					ports = append(ports, uint16(i))
				}
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port > 0 && port <= 65535 {
				ports = append(ports, uint16(port))
			}
		}
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
