package main

import (
	"strings"
)

func detectServiceFromBanner(service *Service, banner string) {
	bannerLower := strings.ToLower(banner)

	switch {
	case strings.Contains(bannerLower, "ssh"):
		service.Name = "ssh"
		if strings.Contains(bannerLower, "openssh") {
			service.Product = "OpenSSH"
		}
	case strings.Contains(bannerLower, "http"):
		service.Name = "http"
		if strings.Contains(bannerLower, "apache") {
			service.Product = "Apache"
		} else if strings.Contains(bannerLower, "nginx") {
			service.Product = "nginx"
		} else if strings.Contains(bannerLower, "iis") {
			service.Product = "IIS"
		}
	case strings.Contains(bannerLower, "ftp"):
		service.Name = "ftp"
		if strings.Contains(bannerLower, "vsftpd") {
			service.Product = "vsftpd"
		}
	case strings.Contains(bannerLower, "smtp"):
		service.Name = "smtp"
	case strings.Contains(bannerLower, "pop3"):
		service.Name = "pop3"
	case strings.Contains(bannerLower, "imap"):
		service.Name = "imap"
	case strings.Contains(bannerLower, "telnet"):
		service.Name = "telnet"
	case strings.Contains(bannerLower, "mysql"):
		service.Name = "mysql"
	case strings.Contains(bannerLower, "microsoft"):
		service.Product = "Microsoft"
	case strings.Contains(bannerLower, "220"):
		if service.Port == 21 {
			service.Name = "ftp"
		} else if service.Port == 25 {
			service.Name = "smtp"
		}
	}
}

func detectServiceByPort(port uint16) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 8080:
		return "http-proxy"
	default:
		return "unknown"
	}
}
