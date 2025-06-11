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

// formatPortList creates a readable string of open ports with protocols
func formatPortList(services []Service) string {
	if len(services) == 0 {
		return "no open ports"
	}

	var ports []string
	for _, service := range services {
		portStr := fmt.Sprintf("%d/%s", service.Port, service.Protocol)
		if service.Name != "" && service.Name != "unknown" {
			portStr += fmt.Sprintf(" (%s)", service.Name)
		}
		ports = append(ports, portStr)
	}

	if len(services) == 1 {
		return fmt.Sprintf("1 port open: %s", ports[0])
	}
	return fmt.Sprintf("%d ports open: %s", len(services), strings.Join(ports, ", "))
}
