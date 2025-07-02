package main

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// enhanceSSHService enhances SSH service detection with version and algorithm info
func enhanceSSHService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read SSH banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	if strings.HasPrefix(banner, "SSH-") {
		service.Banner = banner
		parts := strings.Split(banner, "-")
		if len(parts) >= 3 {
			service.Version = parts[1] // SSH version (1.x or 2.x)
			if len(parts) > 2 {
				productInfo := strings.Join(parts[2:], "-")
				if strings.Contains(strings.ToLower(productInfo), "openssh") {
					service.Product = "OpenSSH"
				} else if strings.Contains(strings.ToLower(productInfo), "dropbear") {
					service.Product = "Dropbear"
				} else {
					service.Product = productInfo
				}
			}
		}
	}
}

// enhanceFTPService enhances FTP service detection with detailed banner analysis
func enhanceFTPService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read FTP banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	service.Banner = banner

	bannerLower := strings.ToLower(banner)
	switch {
	case strings.Contains(bannerLower, "vsftpd"):
		service.Product = "vsftpd"
	case strings.Contains(bannerLower, "proftpd"):
		service.Product = "ProFTPD"
	case strings.Contains(bannerLower, "pure-ftpd"):
		service.Product = "Pure-FTPd"
	case strings.Contains(bannerLower, "filezilla"):
		service.Product = "FileZilla Server"
	case strings.Contains(bannerLower, "microsoft ftp"):
		service.Product = "Microsoft FTP Service"
	case strings.Contains(bannerLower, "wu-ftpd"):
		service.Product = "WU-FTPD"
	}

	// Try anonymous login
	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err = conn.Read(buffer)
		if err == nil {
			response := strings.TrimSpace(string(buffer[:n]))
			if strings.Contains(response, "331") || strings.Contains(response, "230") {
				service.Banner += " | Anonymous login allowed"
			}
		}
	}
}

// enhanceTelnetService enhances telnet service detection
func enhanceTelnetService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read telnet negotiation
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	data := buffer[:n]
	// Look for telnet IAC (Interpret As Command) sequences
	if len(data) > 0 && data[0] == 0xFF {
		service.Banner = "Telnet negotiation detected"
	} else {
		// Might be login prompt
		banner := strings.TrimSpace(string(data))
		if len(banner) > 0 {
			service.Banner = banner
		}
	}
}

// enhanceVNCService enhances VNC service detection
func enhanceVNCService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read VNC version
	buffer := make([]byte, 12)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	vncVersion := strings.TrimSpace(string(buffer[:n]))
	if strings.HasPrefix(vncVersion, "RFB ") {
		service.Banner = vncVersion
		service.Version = strings.TrimPrefix(vncVersion, "RFB ")
	}
}

// enhanceRedisService enhances Redis service detection
func enhanceRedisService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send Redis INFO command
	_, err = conn.Write([]byte("*1\r\n$4\r\nINFO\r\n"))
	if err != nil {
		return
	}

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])
	if strings.Contains(response, "redis_version:") {
		service.Name = "redis"
		service.Product = "Redis"

		// Extract version
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "redis_version:") {
				service.Version = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
				break
			}
		}
		service.Banner = "Redis server"
	}
}

// enhanceMongoDBService enhances MongoDB service detection
func enhanceMongoDBService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// MongoDB wire protocol - try to send a simple isMaster command
	// This is a simplified check - full MongoDB protocol is complex
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		service.Banner = "MongoDB connection established"
	}
}

// enhanceSNMPService enhances SNMP service detection
func enhanceSNMPService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	// SNMP uses UDP, but we can still try basic detection on TCP port
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	service.Banner = "SNMP service detected"
}

// enhanceDockerService enhances Docker API service detection
func enhanceDockerService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, service.Port)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send HTTP request to Docker API
	httpRequest := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: redhound/1.0\r\nConnection: close\r\n\r\n", ip, service.Port)

	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return
	}

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])
	if strings.Contains(response, "Docker") || strings.Contains(response, "\"Version\":") {
		service.Name = "docker"
		service.Product = "Docker API"
		service.Banner = extractHTTPBanner(response)
	}
}
