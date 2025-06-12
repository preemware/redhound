package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/net/proxy"
)

// fingerprintLDAP performs comprehensive LDAP fingerprinting using the go-ldap library
func fingerprintLDAP(dialer proxy.Dialer, ip string, port uint16, timeout time.Duration) *LDAPInfo {
	printVerbose("Starting LDAP fingerprinting on %s:%d", ip, port)

	ldapInfo := &LDAPInfo{}

	// Try regular LDAP connection first
	conn := establishLDAPConnection(dialer, ip, port, false, timeout)
	if conn != nil {
		defer conn.Close()
		performLDAPFingerprinting(conn, ldapInfo, ip, port)
	} else if port == 636 {
		// Try LDAPS (LDAP over SSL/TLS) for port 636
		printVerbose("Trying LDAPS connection on %s:%d", ip, port)
		conn = establishLDAPConnection(dialer, ip, port, true, timeout)
		if conn != nil {
			defer conn.Close()
			performLDAPFingerprinting(conn, ldapInfo, ip, port)
		}
	}

	// Analyze security misconfigurations
	analyzeLDAPSecurityMisconfigs(ldapInfo)

	return ldapInfo
}

// establishLDAPConnection creates a connection to the LDAP server using go-ldap
func establishLDAPConnection(dialer proxy.Dialer, ip string, port uint16, useTLS bool, timeout time.Duration) *ldap.Conn {
	address := fmt.Sprintf("%s:%d", ip, port)

	var conn *ldap.Conn
	var err error

	if useTLS {
		// LDAPS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // For security scanning, we skip cert verification
			ServerName:         ip,
		}

		// For LDAPS, we need to establish the connection manually and then use ldap.NewConn
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var rawConn net.Conn
		if netDialer, ok := dialer.(*net.Dialer); ok {
			rawConn, err = netDialer.DialContext(ctx, "tcp", address)
		} else {
			rawConn, err = dialer.Dial("tcp", address)
		}

		if err != nil {
			printVerbose("Failed to establish raw connection for LDAPS %s:%d: %v", ip, port, err)
			return nil
		}

		// Wrap with TLS
		tlsConn := tls.Client(rawConn, tlsConfig)
		tlsConn.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			printVerbose("TLS handshake failed for LDAPS %s:%d: %v", ip, port, err)
			return nil
		}

		conn = ldap.NewConn(tlsConn, true)
		conn.Start()
	} else {
		// Regular LDAP connection
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var rawConn net.Conn
		if netDialer, ok := dialer.(*net.Dialer); ok {
			rawConn, err = netDialer.DialContext(ctx, "tcp", address)
		} else {
			rawConn, err = dialer.Dial("tcp", address)
		}

		if err != nil {
			printVerbose("Failed to connect to LDAP server %s:%d: %v", ip, port, err)
			return nil
		}

		conn = ldap.NewConn(rawConn, false)
		conn.Start()
	}

	// Set timeout
	conn.SetTimeout(timeout)

	return conn
}

// performLDAPFingerprinting performs the actual LDAP fingerprinting
func performLDAPFingerprinting(conn *ldap.Conn, ldapInfo *LDAPInfo, ip string, port uint16) {
	// Test anonymous bind
	if testAnonymousBind(conn, ldapInfo) {
		printVerbose("Anonymous bind successful on %s:%d", ip, port)

		// Query root DSE for server information
		queryRootDSE(conn, ldapInfo)

		// Perform enumeration if anonymous access is allowed
		if ldapInfo.AnonymousBind {
			performEnumeration(conn, ldapInfo)
		}
	} else {
		printVerbose("Anonymous bind failed on %s:%d - server requires authentication", ip, port)

		// Still try to get basic server info without authentication
		// Some servers allow root DSE queries without authentication
		if err := conn.UnauthenticatedBind(""); err == nil {
			queryRootDSE(conn, ldapInfo)
		}
	}
}

// testAnonymousBind tests for anonymous LDAP bind using go-ldap
func testAnonymousBind(conn *ldap.Conn, ldapInfo *LDAPInfo) bool {
	// Try anonymous bind (empty username and password)
	err := conn.UnauthenticatedBind("")
	if err != nil {
		printVerbose("Anonymous bind failed: %v", err)
		return false
	}

	printVerbose("Anonymous bind succeeded, verifying read access...")

	// Verify that anonymous bind actually allows reading data
	if verifyAnonymousReadAccess(conn) {
		ldapInfo.AnonymousBind = true
		ldapInfo.AllowsAnonymousRead = true
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "Anonymous bind allowed")
		return true
	} else {
		printVerbose("Anonymous bind succeeded but read access is restricted")
		return false
	}
}

// verifyAnonymousReadAccess verifies that anonymous bind actually allows reading data
func verifyAnonymousReadAccess(conn *ldap.Conn) bool {
	// Try to search for the root DSE
	searchRequest := ldap.NewSearchRequest(
		"", // Empty base DN for root DSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,  // Size limit
		10, // Time limit
		false,
		"(objectClass=*)",
		[]string{"objectClass", "namingContexts", "defaultNamingContext"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		printVerbose("Failed to perform verification search: %v", err)
		return false
	}

	if len(sr.Entries) > 0 {
		printVerbose("Anonymous read access verified - found %d entries", len(sr.Entries))
		return true
	}

	printVerbose("Anonymous read access verification failed - no entries returned")
	return false
}

// queryRootDSE queries the LDAP root DSE for server information
func queryRootDSE(conn *ldap.Conn, ldapInfo *LDAPInfo) {
	searchRequest := ldap.NewSearchRequest(
		"", // Empty base DN for root DSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,  // No size limit
		30, // Time limit
		false,
		"(objectClass=*)",
		[]string{"*", "+"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		printVerbose("Failed to query root DSE: %v", err)
		return
	}

	if len(sr.Entries) > 0 {
		parseRootDSEAttributes(sr.Entries[0], ldapInfo)
	}
}

// parseRootDSEAttributes parses attributes from root DSE response
func parseRootDSEAttributes(entry *ldap.Entry, ldapInfo *LDAPInfo) {
	if ldapInfo.RootDSE == nil {
		ldapInfo.RootDSE = make(map[string]string)
	}

	for _, attr := range entry.Attributes {
		attrName := attr.Name
		attrLower := strings.ToLower(attrName)

		if len(attr.Values) > 0 {
			value := attr.Values[0]

			switch attrLower {
			case "defaultnamingcontext":
				ldapInfo.NamingContext = value
				ldapInfo.BaseDN = value
				if domain := extractDomainFromDN(value); domain != "" {
					ldapInfo.Domain = domain
				}
			case "dnshostname":
				ldapInfo.ServerName = value
			case "servername":
				if ldapInfo.ServerName == "" {
					ldapInfo.ServerName = value
				}
			case "forestfunctionality":
				ldapInfo.ForestName = value
			case "supportedldapversion":
				ldapInfo.SupportedLDAPVersion = strings.Join(attr.Values, ",")
			case "supportedsaslmechanisms":
				ldapInfo.SupportedSASLMechs = attr.Values
			case "supportedextension":
				ldapInfo.SupportedExtensions = attr.Values
			case "supportedcontrol":
				ldapInfo.SupportedControls = attr.Values
			case "domaincontrollerfunctionality":
				ldapInfo.DomainController = value
			case "rootdomainnamingcontext":
				if ldapInfo.ForestName == "" {
					if domain := extractDomainFromDN(value); domain != "" {
						ldapInfo.ForestName = domain
					}
				}
			}

			// Store all attributes in RootDSE map
			ldapInfo.RootDSE[attrName] = value
		}
	}
}

// extractDomainFromDN extracts domain name from a Distinguished Name
func extractDomainFromDN(dn string) string {
	parts := strings.Split(strings.ToLower(dn), ",")
	var domainParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "dc=") {
			domainParts = append(domainParts, strings.TrimPrefix(part, "dc="))
		}
	}

	if len(domainParts) > 0 {
		return strings.Join(domainParts, ".")
	}

	return ""
}

// performEnumeration performs comprehensive LDAP enumeration
func performEnumeration(conn *ldap.Conn, ldapInfo *LDAPInfo) {
	if ldapInfo.BaseDN == "" {
		printVerbose("No base DN available for enumeration")
		return
	}

	printVerbose("Starting LDAP enumeration with base DN: %s", ldapInfo.BaseDN)

	// Enumerate different object types
	enumerateUsers(conn, ldapInfo)
	enumerateGroups(conn, ldapInfo)
	enumerateComputers(conn, ldapInfo)
}

// enumerateUsers attempts to enumerate users from LDAP
func enumerateUsers(conn *ldap.Conn, ldapInfo *LDAPInfo) {
	filters := []string{
		"(objectClass=person)",
		"(objectClass=user)",
		"(objectClass=inetOrgPerson)",
	}

	for _, filter := range filters {
		users := searchLDAPObjects(conn, ldapInfo.BaseDN, filter, []string{"cn", "sAMAccountName", "userPrincipalName", "distinguishedName"})
		if len(users) > 0 {
			ldapInfo.Users = append(ldapInfo.Users, users...)
			ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, fmt.Sprintf("User enumeration allowed via anonymous bind (%d users found)", len(users)))
			printVerbose("Found %d users via anonymous bind", len(users))
			break // Found users, no need to try other filters
		}
	}
}

// enumerateGroups attempts to enumerate groups from LDAP
func enumerateGroups(conn *ldap.Conn, ldapInfo *LDAPInfo) {
	filters := []string{
		"(objectClass=group)",
		"(objectClass=groupOfNames)",
		"(objectClass=posixGroup)",
	}

	for _, filter := range filters {
		groups := searchLDAPObjects(conn, ldapInfo.BaseDN, filter, []string{"cn", "distinguishedName", "member"})
		if len(groups) > 0 {
			ldapInfo.Groups = append(ldapInfo.Groups, groups...)
			ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, fmt.Sprintf("Group enumeration allowed via anonymous bind (%d groups found)", len(groups)))
			printVerbose("Found %d groups via anonymous bind", len(groups))
			break
		}
	}
}

// enumerateComputers attempts to enumerate computers from LDAP
func enumerateComputers(conn *ldap.Conn, ldapInfo *LDAPInfo) {
	filters := []string{
		"(objectClass=computer)",
		"(objectClass=device)",
	}

	for _, filter := range filters {
		computers := searchLDAPObjects(conn, ldapInfo.BaseDN, filter, []string{"cn", "dNSHostName", "operatingSystem", "distinguishedName"})
		if len(computers) > 0 {
			ldapInfo.Computers = append(ldapInfo.Computers, computers...)
			ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, fmt.Sprintf("Computer enumeration allowed via anonymous bind (%d computers found)", len(computers)))
			printVerbose("Found %d computers via anonymous bind", len(computers))
			break
		}
	}
}

// searchLDAPObjects performs an LDAP search and returns found objects
func searchLDAPObjects(conn *ldap.Conn, baseDN, filter string, attributes []string) []string {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		100, // Size limit
		30,  // Time limit
		false,
		filter,
		attributes,
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		printVerbose("LDAP search failed for filter %s: %v", filter, err)
		return nil
	}

	var results []string
	for _, entry := range sr.Entries {
		if len(entry.Attributes) > 0 {
			// Try to get the most descriptive name
			var name string
			for _, attr := range entry.Attributes {
				switch strings.ToLower(attr.Name) {
				case "cn":
					name = attr.Values[0]
				case "samaccountname":
					if name == "" {
						name = attr.Values[0]
					}
				case "userprincipalname":
					if name == "" {
						name = attr.Values[0]
					}
				case "dnshostname":
					if name == "" {
						name = attr.Values[0]
					}
				}
			}
			if name == "" {
				name = entry.DN
			}
			results = append(results, name)
		}
	}

	return results
}

// analyzeLDAPSecurityMisconfigs analyzes LDAP configuration for security issues
func analyzeLDAPSecurityMisconfigs(ldapInfo *LDAPInfo) {
	if ldapInfo.AnonymousBind && ldapInfo.AllowsAnonymousRead {
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "Anonymous LDAP access enabled")
	}

	if len(ldapInfo.Users) > 0 {
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "Sensitive user information accessible")
	}

	if len(ldapInfo.Groups) > 0 {
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "Group membership information accessible")
	}

	if len(ldapInfo.Computers) > 0 {
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "Computer/machine accounts accessible")
	}

	// Check for weak authentication mechanisms
	if len(ldapInfo.SupportedSASLMechs) == 0 {
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "No SASL mechanisms advertised")
	}

	// Check LDAP version support
	if strings.Contains(ldapInfo.SupportedLDAPVersion, "2") {
		ldapInfo.SecurityMisconfigs = append(ldapInfo.SecurityMisconfigs, "LDAPv2 supported (deprecated)")
	}
}

// enhanceLDAPService enhances a detected LDAP service with detailed information
func enhanceLDAPService(dialer proxy.Dialer, service *Service, ip string, timeout time.Duration) {
	// Set service name based on port
	if service.Port == 636 {
		service.Name = "ldaps"
	} else {
		service.Name = "ldap"
	}

	printVerbose("Attempting LDAP enumeration on %s:%d", ip, service.Port)

	// Perform LDAP fingerprinting
	ldapInfo := fingerprintLDAP(dialer, ip, service.Port, timeout)
	if ldapInfo != nil {
		service.LDAP = ldapInfo

		// Update service information based on LDAP findings
		var productParts []string

		if service.Port == 636 {
			productParts = append(productParts, "LDAPS")
		} else {
			productParts = append(productParts, "LDAP")
		}

		if ldapInfo.Domain != "" {
			productParts = append(productParts, fmt.Sprintf("(%s)", ldapInfo.Domain))
		}

		service.Product = strings.Join(productParts, " ")

		// Create informative banner
		var bannerParts []string

		if ldapInfo.ServerName != "" {
			bannerParts = append(bannerParts, fmt.Sprintf("server:%s", ldapInfo.ServerName))
		}

		if ldapInfo.AnonymousBind {
			bannerParts = append(bannerParts, "anon-bind")
		}

		if ldapInfo.Domain != "" {
			bannerParts = append(bannerParts, fmt.Sprintf("domain:%s", ldapInfo.Domain))
		}

		if len(ldapInfo.SecurityMisconfigs) > 0 {
			bannerParts = append(bannerParts, fmt.Sprintf("issues:%d", len(ldapInfo.SecurityMisconfigs)))
		}

		if len(bannerParts) > 0 {
			service.Banner = strings.Join(bannerParts, " ")
		} else {
			service.Banner = "LDAP server detected"
		}

		if ldapInfo.SupportedLDAPVersion != "" {
			service.Version = fmt.Sprintf("v%s", ldapInfo.SupportedLDAPVersion)
		}
	} else {
		// Basic service information if detailed enumeration fails
		service.Product = "LDAP Server"
		service.Banner = "LDAP server detected"
	}
}
