package main

// Service represents a detected service on a host
type Service struct {
	Port     uint16    `json:"port"`
	Protocol string    `json:"protocol"`
	Name     string    `json:"name,omitempty"`
	Product  string    `json:"product,omitempty"`
	Version  string    `json:"version,omitempty"`
	State    string    `json:"state"`
	Banner   string    `json:"banner,omitempty"`
	Title    string    `json:"title,omitempty"`
	SMB      *SMBInfo  `json:"smb,omitempty"`
	LDAP     *LDAPInfo `json:"ldap,omitempty"`
}

// SMBInfo represents SMB/NTLM specific information
type SMBInfo struct {
	Domain             string   `json:"domain,omitempty"`
	Computer           string   `json:"computer,omitempty"`
	NetBIOSName        string   `json:"netbios_name,omitempty"`
	NetBIOSDomain      string   `json:"netbios_domain,omitempty"`
	DNSName            string   `json:"dns_name,omitempty"`
	DNSDomain          string   `json:"dns_domain,omitempty"`
	ForestName         string   `json:"forest_name,omitempty"`
	OSVersion          string   `json:"os_version,omitempty"`
	SMBVersion         string   `json:"smb_version,omitempty"`
	Dialect            string   `json:"dialect,omitempty"`
	Signing            bool     `json:"signing,omitempty"`
	Shares             []string `json:"shares,omitempty"`
	NullSession        bool     `json:"null_session,omitempty"`
	GuestAccess        bool     `json:"guest_access,omitempty"`
	AnonymousAccess    bool     `json:"anonymous_access,omitempty"`
	SupportedDialects  []string `json:"supported_dialects,omitempty"`
	SecurityMisconfigs []string `json:"security_misconfigs,omitempty"`
	MS17_010           bool     `json:"ms17_010,omitempty"`
}

// LDAPInfo represents LDAP specific information
type LDAPInfo struct {
	BaseDN               string            `json:"base_dn,omitempty"`
	Domain               string            `json:"domain,omitempty"`
	NamingContext        string            `json:"naming_context,omitempty"`
	ServerName           string            `json:"server_name,omitempty"`
	ForestName           string            `json:"forest_name,omitempty"`
	DomainController     string            `json:"domain_controller,omitempty"`
	SupportedLDAPVersion string            `json:"supported_ldap_version,omitempty"`
	SupportedSASLMechs   []string          `json:"supported_sasl_mechs,omitempty"`
	SupportedExtensions  []string          `json:"supported_extensions,omitempty"`
	SupportedControls    []string          `json:"supported_controls,omitempty"`
	RootDSE              map[string]string `json:"rootdse,omitempty"`
	AnonymousBind        bool              `json:"anonymous_bind,omitempty"`
	AllowsAnonymousRead  bool              `json:"allows_anonymous_read,omitempty"`
	SecurityMisconfigs   []string          `json:"security_misconfigs,omitempty"`
	Users                []string          `json:"users,omitempty"`
	Groups               []string          `json:"groups,omitempty"`
	Computers            []string          `json:"computers,omitempty"`
}

// Host represents a scanned host with its services
type Host struct {
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	Services []Service `json:"services"`
}

// Common ports to scan
var CommonPorts = []uint16{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
	// Additional common ports for internal networks
	88, 389, 445, 464, 636, 1433, 1521, 2049, 3268, 5985, 5986, 8443, 9200, 27017,
	// RDP, VNC, databases
	1434, 3050, 5984, 6379, 7001, 8000, 8008, 8081, 8090, 8181, 8888, 9000, 9043, 9090, 9443,
}
