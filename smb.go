package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"golang.org/x/net/proxy"
)

// fingerprintSMB performs comprehensive SMB fingerprinting on the given connection
func fingerprintSMB(dialer proxy.Dialer, ip string, port uint16, timeout time.Duration) *SMBInfo {
	address := fmt.Sprintf("%s:%d", ip, port)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Establish connection
	var conn net.Conn
	var err error

	if netDialer, ok := dialer.(*net.Dialer); ok {
		conn, err = netDialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}

	if err != nil {
		return nil
	}
	defer conn.Close()

	smbInfo := &SMBInfo{}

	// First, try raw SMB negotiation to get protocol information
	smbInfo = performRawSMBNegotiation(conn, smbInfo, timeout)

	// Create new connection for authentication testing
	if netDialer, ok := dialer.(*net.Dialer); ok {
		conn, err = netDialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return smbInfo
	}
	defer conn.Close()

	// Test null authentication
	testNullAuthentication(conn, smbInfo, timeout)

	// Test guest authentication
	testGuestAuthentication(dialer, ip, port, smbInfo, timeout)

	// If ANY form of anonymous access works, enumerate shares and test access
	if smbInfo.NullSession || smbInfo.AnonymousAccess || smbInfo.GuestAccess {
		testAnonymousEnumeration(dialer, ip, port, smbInfo, timeout)
	}

	// Analyze security misconfigurations
	analyzeSecurityMisconfigs(smbInfo)

	return smbInfo
}

// testNullAuthentication tests for null/anonymous authentication
func testNullAuthentication(conn net.Conn, smbInfo *SMBInfo, timeout time.Duration) bool {
	// Try to negotiate SMB connection with null credentials
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "",
			Password: "",
			Domain:   "",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	session, err := d.DialContext(ctx, conn)
	if err != nil {
		return false
	}
	defer session.Logoff()

	smbInfo.NullSession = true
	smbInfo.AnonymousAccess = true
	smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, "Null authentication allowed")

	// Try to extract domain information from the session
	extractDomainInfo(session, smbInfo)

	// Immediately enumerate shares since we have a working session
	if shares, err := enumerateShares(session); err == nil && len(shares) > 0 {
		smbInfo.Shares = shares

		// Check if we successfully used the SMB share enumeration API
		if shareNames, enumErr := session.ListSharenames(); enumErr == nil && len(shareNames) > 0 {
			smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, "Share enumeration allowed via SMB protocol")
		}

		// Test share access
		testShareAccess(session, smbInfo)
	}

	return true
}

// testGuestAuthentication tests for guest authentication
func testGuestAuthentication(dialer proxy.Dialer, ip string, port uint16, smbInfo *SMBInfo, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", ip, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var conn net.Conn
	var err error

	if netDialer, ok := dialer.(*net.Dialer); ok {
		conn, err = netDialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return
	}
	defer conn.Close()

	// Test common guest credentials
	guestCredentials := []struct {
		user, pass, domain string
		desc               string
	}{
		{"guest", "", "", "guest_no_pass"},
		{"guest", "guest", "", "guest_weak_pass"},
		{"", "", "", "anonymous"},
		{"anonymous", "", "", "anonymous_user"},
		{"anonymous", "anonymous", "", "anonymous_weak_pass"},
	}

	for _, cred := range guestCredentials {
		d := &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:     cred.user,
				Password: cred.pass,
				Domain:   cred.domain,
			},
		}

		session, err := d.DialContext(ctx, conn)
		if err != nil {
			continue
		}
		defer session.Logoff()

		// Mark specific types of access
		if cred.user == "guest" {
			smbInfo.GuestAccess = true
			smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, fmt.Sprintf("Guest account accessible (%s)", cred.desc))
		} else {
			smbInfo.AnonymousAccess = true
			smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, fmt.Sprintf("Anonymous access allowed (%s)", cred.desc))
		}

		// Also set the general null session flag
		smbInfo.NullSession = true

		extractDomainInfo(session, smbInfo)

		// Enumerate shares immediately if we haven't done so already
		if len(smbInfo.Shares) == 0 {
			if shares, err := enumerateShares(session); err == nil && len(shares) > 0 {
				smbInfo.Shares = shares

				// Check if we successfully used the SMB share enumeration API
				if shareNames, enumErr := session.ListSharenames(); enumErr == nil && len(shareNames) > 0 {
					smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, "Share enumeration allowed via SMB protocol")
				}

				// Test share access
				testShareAccess(session, smbInfo)
			}
		}
		break
	}
}

// testAnonymousEnumeration performs comprehensive enumeration with anonymous access
func testAnonymousEnumeration(dialer proxy.Dialer, ip string, port uint16, smbInfo *SMBInfo, timeout time.Duration) {
	// If we already have shares enumerated, no need to do it again
	if len(smbInfo.Shares) > 0 {
		return
	}

	address := fmt.Sprintf("%s:%d", ip, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var conn net.Conn
	var err error

	if netDialer, ok := dialer.(*net.Dialer); ok {
		conn, err = netDialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return
	}
	defer conn.Close()

	// Try different authentication methods to enumerate shares
	authMethods := []struct {
		user, pass, domain string
		desc               string
	}{
		{"", "", "", "null"},
		{"guest", "", "", "guest"},
		{"anonymous", "", "", "anonymous"},
	}

	for _, auth := range authMethods {
		d := &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:     auth.user,
				Password: auth.pass,
				Domain:   auth.domain,
			},
		}

		session, err := d.DialContext(ctx, conn)
		if err != nil {
			continue
		}
		defer session.Logoff()

		// Enumerate shares using proper SMB protocol
		if shares, err := enumerateShares(session); err == nil && len(shares) > 0 {
			smbInfo.Shares = shares

			// Check if we successfully used the SMB share enumeration API
			if shareNames, enumErr := session.ListSharenames(); enumErr == nil && len(shareNames) > 0 {
				smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, "Share enumeration allowed via SMB protocol")
			}

			// Test share access
			testShareAccess(session, smbInfo)
			break // Found shares, no need to try other auth methods
		}
	}
}

// extractDomainInfo extracts domain and computer information from SMB session
func extractDomainInfo(session *smb2.Session, smbInfo *SMBInfo) {
	// Try to connect to IPC$ share to get server info
	share, err := session.Mount("IPC$")
	if err != nil {
		return
	}
	defer share.Umount()

	// TODO: Implement NTLM challenge parsing to extract domain info
	// For now, we mark that we have SMB access
	if smbInfo.SMBVersion == "" {
		smbInfo.SMBVersion = "SMB2+"
	}
}

// performRawSMBNegotiation performs low-level SMB negotiation to extract protocol information
func performRawSMBNegotiation(conn net.Conn, smbInfo *SMBInfo, timeout time.Duration) *SMBInfo {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// SMB2 negotiate request
	negotiateRequest := []byte{
		0x00, 0x00, 0x00, 0x2c, // NetBIOS Session Service header
		0xfe, 0x53, 0x4d, 0x42, // SMB2 header
		0x40, 0x00, 0x00, 0x00, // Protocol version
		0x00, 0x00, 0x00, 0x00, // Command (negotiate)
		0x00, 0x00, 0x00, 0x00, // NT Status
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next command
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved/Tree ID/Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x24, 0x00, // Structure size
		0x04, 0x00, // Dialect count (increased to 4)
		0x00, 0x00, // Security mode
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Negotiate context offset/count
		0x02, 0x02, // SMB 2.0.2
		0x10, 0x02, // SMB 2.1
		0x00, 0x03, // SMB 3.0
		0x02, 0x03, // SMB 3.0.2
	}

	// Send negotiate request
	_, err := conn.Write(negotiateRequest)
	if err != nil {
		return smbInfo
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return smbInfo
	}

	// Parse SMB response
	if n > 4 {
		// Check for SMB2 magic
		if n >= 8 && string(response[4:8]) == "\xfeSMB" {
			smbInfo.SMBVersion = "SMB2+"
			smbInfo.SupportedDialects = []string{"SMB2+"}

			// Try to extract more information from the negotiate response
			if n > 72 {
				// Parse dialect revision (offset 72-74 in negotiate response)
				if n > 74 {
					dialect := uint16(response[72]) | (uint16(response[73]) << 8)
					switch dialect {
					case 0x0202:
						smbInfo.Dialect = "SMB 2.0.2"
					case 0x0210:
						smbInfo.Dialect = "SMB 2.1"
					case 0x0300:
						smbInfo.Dialect = "SMB 3.0"
					case 0x0302:
						smbInfo.Dialect = "SMB 3.0.2"
					case 0x0311:
						smbInfo.Dialect = "SMB 3.1.1"
					default:
						smbInfo.Dialect = fmt.Sprintf("SMB %x", dialect)
					}
				}

				// Check for signing requirements (offset 70-71)
				if n > 71 {
					securityMode := uint16(response[70]) | (uint16(response[71]) << 8)
					smbInfo.Signing = (securityMode & 0x02) != 0 // SMB2_NEGOTIATE_SIGNING_REQUIRED
				}
			}
		} else if n >= 8 && string(response[4:8]) == "\xffSMB" {
			smbInfo.SMBVersion = "SMB1"
			smbInfo.SupportedDialects = []string{"SMB1"}
			smbInfo.Dialect = "SMB 1.0"
		}
	}

	return smbInfo
}

// enumerateShares attempts to enumerate available shares using proper SMB protocol
func enumerateShares(session *smb2.Session) ([]string, error) {
	var shares []string

	// First, try to use the proper SMB share enumeration API
	shareNames, err := session.ListSharenames()
	if err == nil {
		// Successfully got the actual share list from the server
		shares = shareNames
	} else {
		// Fallback to testing common share names if ListSharenames fails
		commonShares := []string{
			// Administrative shares
			"C$", "D$", "E$", "ADMIN$", "IPC$",
			// Domain shares
			"SYSVOL", "NETLOGON",
			// Common application shares
			"print$", "Users", "Public", "Shared", "Share", "Data",
			// Backup and temporary shares
			"Backup", "Backups", "Temp", "Tmp", "Transfer",
			// Common business shares
			"Finance", "HR", "IT", "Documents", "Files",
		}

		for _, shareName := range commonShares {
			share, err := session.Mount(shareName)
			if err == nil {
				shares = append(shares, shareName)
				share.Umount()
			}
		}
	}

	return shares, nil
}

// testShareAccess tests read/write access to discovered shares
func testShareAccess(session *smb2.Session, smbInfo *SMBInfo) {
	accessibleShares := make([]string, 0)

	for _, shareName := range smbInfo.Shares {
		share, err := session.Mount(shareName)
		if err != nil {
			continue
		}

		// Try to list directory contents
		if shareName != "IPC$" {
			_, err := share.ReadDir(".")
			if err == nil {
				accessibleShares = append(accessibleShares, shareName+"(R)")
			}
		} else {
			// IPC$ is always readable if we can mount it
			accessibleShares = append(accessibleShares, shareName+"(R)")
		}

		share.Umount()
	}

	// Update shares list with access information
	if len(accessibleShares) > 0 {
		smbInfo.Shares = accessibleShares
	}
}

// analyzeSecurityMisconfigs analyzes and reports security misconfigurations
func analyzeSecurityMisconfigs(smbInfo *SMBInfo) {
	// Check for SMB1 usage (deprecated and insecure)
	if smbInfo.SMBVersion == "SMB1" || smbInfo.Dialect == "SMB 1.0" {
		smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, "SMB1 enabled (deprecated and insecure)")
	}

	// Check for weak signing configuration
	if !smbInfo.Signing {
		smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, "SMB signing not required")
	}

	// Check for accessible administrative shares
	for _, share := range smbInfo.Shares {
		if strings.Contains(share, "C$(R)") || strings.Contains(share, "ADMIN$(R)") {
			smbInfo.SecurityMisconfigs = append(smbInfo.SecurityMisconfigs, fmt.Sprintf("Administrative share accessible: %s", share))
		}
	}
}

// enhanceSMBService adds SMB fingerprinting information to a service
func enhanceSMBService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	if service.Port != 445 && service.Port != 139 {
		return
	}

	// Perform comprehensive SMB fingerprinting
	smbInfo := fingerprintSMB(dialer, ip, service.Port, timeout)
	if smbInfo != nil {
		service.SMB = smbInfo

		// Update service information based on SMB info
		if smbInfo.SMBVersion != "" {
			service.Product = smbInfo.SMBVersion
		}

		if smbInfo.Dialect != "" {
			service.Version = smbInfo.Dialect
		}

		// Create a descriptive banner
		var bannerParts []string
		if smbInfo.SMBVersion != "" {
			bannerParts = append(bannerParts, smbInfo.SMBVersion)
		}
		if smbInfo.Dialect != "" {
			bannerParts = append(bannerParts, smbInfo.Dialect)
		}
		if smbInfo.Signing {
			bannerParts = append(bannerParts, "Signing: Required")
		} else {
			bannerParts = append(bannerParts, "Signing: Not Required")
		}
		if smbInfo.Domain != "" {
			bannerParts = append(bannerParts, fmt.Sprintf("Domain: %s", smbInfo.Domain))
		}
		if smbInfo.Computer != "" {
			bannerParts = append(bannerParts, fmt.Sprintf("Computer: %s", smbInfo.Computer))
		}

		// Anonymous access information
		if smbInfo.AnonymousAccess {
			bannerParts = append(bannerParts, "Anonymous access: ALLOWED")
		}
		if smbInfo.GuestAccess {
			bannerParts = append(bannerParts, "Guest access: ALLOWED")
		}
		if !smbInfo.NullSession {
			bannerParts = append(bannerParts, "Anonymous access: DENIED")
		}

		if len(smbInfo.Shares) > 0 {
			bannerParts = append(bannerParts, fmt.Sprintf("Shares: %s", strings.Join(smbInfo.Shares, ", ")))
		}

		// Security misconfigurations
		if len(smbInfo.SecurityMisconfigs) > 0 {
			bannerParts = append(bannerParts, fmt.Sprintf("Security Issues: %s", strings.Join(smbInfo.SecurityMisconfigs, ", ")))
		}

		if len(bannerParts) > 0 {
			service.Banner = strings.Join(bannerParts, " | ")
		}

		// Set service name based on findings
		if smbInfo.NullSession {
			service.Name = "microsoft-ds (anonymous)"
		} else {
			service.Name = "microsoft-ds"
		}
	}
}
