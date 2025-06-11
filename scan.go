package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

func scanHost(ip string, ports []uint16, timeout time.Duration, proxyURL string) (Host, error) {
	host := Host{
		IP:       ip,
		Services: make([]Service, 0),
	}

	// Try to resolve hostname
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		host.Hostname = names[0]
	}

	// Create dialer (with or without proxy)
	var dialer proxy.Dialer = &net.Dialer{Timeout: timeout}
	if proxyURL != "" {
		proxyDialer, err := createProxyDialer(proxyURL)
		if err != nil {
			return host, fmt.Errorf("failed to create proxy dialer: %w", err)
		}
		dialer = proxyDialer
	}

	// Scan ports concurrently
	semPort := make(chan struct{}, 20) // Limit concurrent port scans per host
	var wg sync.WaitGroup
	var mux sync.Mutex

	for _, port := range ports {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			semPort <- struct{}{}
			defer func() { <-semPort }()

			service := scanPort(dialer, ip, port, timeout)
			if service != nil {
				mux.Lock()
				host.Services = append(host.Services, *service)
				mux.Unlock()
			}
		}()
	}

	wg.Wait()
	return host, nil
}

func scanPort(dialer proxy.Dialer, ip string, port uint16, timeout time.Duration) *Service {
	address := fmt.Sprintf("%s:%d", ip, port)

	// Create context with timeout for the connection
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// For direct connections, we can use DialContext
	var conn net.Conn
	var err error

	if netDialer, ok := dialer.(*net.Dialer); ok {
		conn, err = netDialer.DialContext(ctx, "tcp", address)
	} else {
		// For proxy connections, we use the proxy dialer
		conn, err = dialer.Dial("tcp", address)
	}

	if err != nil {
		return nil // Port closed or filtered
	}
	defer conn.Close()

	service := &Service{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
	}

	// Set timeout for banner reading
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Check if this is likely an HTTP port
	if isHTTPPort(port) {
		handleHTTPService(conn, service, ip, port)
	} else if port == 443 || port == 8443 || port == 9443 {
		// HTTPS ports - we can't easily get titles without TLS
		service.Name = "https"
		service.Banner = "SSL/TLS encrypted"
	} else {
		// Try to grab banner for other services
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			banner := strings.TrimSpace(string(buffer[:n]))
			if len(banner) > 0 && len(banner) < 500 {
				service.Banner = banner
				detectServiceFromBanner(service, banner)
			}
		}
	}

	// If no service detected, use port-based detection
	if service.Name == "" {
		service.Name = detectServiceByPort(service.Port)
	}

	// Perform SMB fingerprinting for SMB ports
	if service.Port == 445 || service.Port == 139 {
		enhanceSMBService(dialer, service, ip, timeout)
	}

	return service
}
