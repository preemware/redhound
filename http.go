package main

import (
	"fmt"
	"net"
	"strings"
)

// isHTTPPort checks if a port is commonly used for HTTP
func isHTTPPort(port uint16) bool {
	httpPorts := []uint16{80, 8000, 8008, 8080, 8081, 8090, 8181, 8888, 9000, 9090}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

// handleHTTPService makes an HTTP request and extracts title
func handleHTTPService(conn net.Conn, service *Service, ip string, port uint16) {
	service.Name = "http"

	// Send HTTP request
	httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: redhound/1.0\r\nConnection: close\r\n\r\n", ip, port)

	_, err := conn.Write([]byte(httpRequest))
	if err != nil {
		return
	}

	// Read HTTP response
	buffer := make([]byte, 4096) // Larger buffer for HTML content
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])
	service.Banner = extractHTTPBanner(response)
	service.Title = extractHTTPTitle(response)

	// Try to detect web server from headers
	detectWebServer(service, response)
}

// extractHTTPBanner extracts the HTTP status line and server header
func extractHTTPBanner(response string) string {
	lines := strings.Split(response, "\n")
	if len(lines) > 0 {
		statusLine := strings.TrimSpace(lines[0])

		// Look for Server header
		serverHeader := ""
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				serverHeader = strings.TrimSpace(line[7:]) // Remove "Server: "
				break
			}
		}

		if serverHeader != "" {
			return fmt.Sprintf("%s | Server: %s", statusLine, serverHeader)
		}
		return statusLine
	}
	return ""
}

// extractHTTPTitle extracts the HTML title from the response
func extractHTTPTitle(response string) string {
	// Find the HTML body (after headers)
	bodyStart := strings.Index(response, "\r\n\r\n")
	if bodyStart == -1 {
		bodyStart = strings.Index(response, "\n\n")
		if bodyStart == -1 {
			return ""
		}
		bodyStart += 2
	} else {
		bodyStart += 4
	}

	html := response[bodyStart:]

	// Look for <title> tag (case insensitive)
	htmlLower := strings.ToLower(html)
	titleStart := strings.Index(htmlLower, "<title")
	if titleStart == -1 {
		return ""
	}

	// Find the end of the opening tag
	titleTagEnd := strings.Index(html[titleStart:], ">")
	if titleTagEnd == -1 {
		return ""
	}
	titleTagEnd += titleStart + 1

	// Find the closing tag
	titleEnd := strings.Index(htmlLower[titleTagEnd:], "</title>")
	if titleEnd == -1 {
		return ""
	}
	titleEnd += titleTagEnd

	// Extract and clean title
	title := html[titleTagEnd:titleEnd]
	title = strings.TrimSpace(title)

	// Clean up common HTML entities
	title = strings.ReplaceAll(title, "&amp;", "&")
	title = strings.ReplaceAll(title, "&lt;", "<")
	title = strings.ReplaceAll(title, "&gt;", ">")
	title = strings.ReplaceAll(title, "&quot;", "\"")
	title = strings.ReplaceAll(title, "&#39;", "'")
	title = strings.ReplaceAll(title, "&nbsp;", " ")

	// Remove extra whitespace
	title = strings.Join(strings.Fields(title), " ")

	// Limit length
	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return title
}

// detectWebServer tries to identify the web server from HTTP headers
func detectWebServer(service *Service, response string) {
	responseLower := strings.ToLower(response)

	switch {
	case strings.Contains(responseLower, "server: apache"):
		service.Product = "Apache"
		// Try to extract version
		if idx := strings.Index(responseLower, "server: apache/"); idx != -1 {
			line := response[idx:]
			if end := strings.Index(line, "\r\n"); end != -1 {
				line = line[:end]
			}
			parts := strings.Fields(line)
			if len(parts) > 1 {
				service.Version = strings.TrimPrefix(parts[1], "Apache/")
			}
		}
	case strings.Contains(responseLower, "server: nginx"):
		service.Product = "nginx"
		if idx := strings.Index(responseLower, "server: nginx/"); idx != -1 {
			line := response[idx:]
			if end := strings.Index(line, "\r\n"); end != -1 {
				line = line[:end]
			}
			parts := strings.Fields(line)
			if len(parts) > 1 {
				service.Version = strings.TrimPrefix(parts[1], "nginx/")
			}
		}
	case strings.Contains(responseLower, "server: microsoft-iis"):
		service.Product = "Microsoft IIS"
		if idx := strings.Index(responseLower, "server: microsoft-iis/"); idx != -1 {
			line := response[idx:]
			if end := strings.Index(line, "\r\n"); end != -1 {
				line = line[:end]
			}
			parts := strings.Fields(line)
			if len(parts) > 1 {
				service.Version = strings.TrimPrefix(parts[1], "Microsoft-IIS/")
			}
		}
	case strings.Contains(responseLower, "server: lighttpd"):
		service.Product = "lighttpd"
	case strings.Contains(responseLower, "server: caddy"):
		service.Product = "Caddy"
	case strings.Contains(responseLower, "server: tomcat"):
		service.Product = "Apache Tomcat"
	case strings.Contains(responseLower, "server: jetty"):
		service.Product = "Jetty"
	}

	// Check for common web applications in headers
	if strings.Contains(responseLower, "x-powered-by: php") {
		if service.Product == "" {
			service.Product = "PHP"
		} else {
			service.Product += " + PHP"
		}
	} else if strings.Contains(responseLower, "x-powered-by: asp.net") {
		if service.Product == "" {
			service.Product = "ASP.NET"
		} else {
			service.Product += " + ASP.NET"
		}
	}
}
