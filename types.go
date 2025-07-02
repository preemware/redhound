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

// Common ports to scan - organized by service category
var CommonPorts = []uint16{
	// Basic network services
	21, 22, 23, 25, 49, 53, 67, 68, 69, 79, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 464, 514, 548, 636, 873, 993, 995,

	// Extended web services
	280, 591, 593, 631, 808, 832, 981, 1010, 1099, 1311, 2301, 2381, 2809, 3000, 3001, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5001, 5104, 5108, 5800, 6543, 7000, 7001, 7002, 7070, 7396, 7474, 8000, 8001, 8005, 8006, 8008, 8009, 8014, 8042, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9443, 9800, 9981, 9999, 10001, 11371, 34573, 55555,

	// Database services
	1433, 1434, 1521, 1830, 2100, 2483, 2484, 3050, 3306, 3351, 4505, 4506, 5432, 5433, 5984, 6379, 6380, 7474, 8086, 8087, 9042, 9160, 9200, 9300, 11211, 27017, 27018, 27019, 28017, 50070,

	// Remote access and management
	902, 903, 1723, 1801, 2000, 2049, 2121, 2375, 2376, 3389, 4440, 4848, 4899, 5040, 5060, 5061, 5357, 5480, 5500, 5631, 5666, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5938, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6080, 6346, 6347, 6443, 8649, 9001, 9030, 9990, 10000, 10250, 20000,

	// Mail services
	220, 465, 587, 1109, 2525, 4190,

	// Network infrastructure
	500, 1645, 1646, 1701, 1812, 1813, 4500, 5353, 10443,

	// File sharing and storage
	115, 3260,

	// Enterprise and directory services
	1024, 1025, 3268, 3269, 5722, 9389,

	// Monitoring and logging
	1514, 2003, 2004, 5044, 5140, 5601, 6514, 8125, 8126, 10050, 10051,

	// Gaming and media
	1935, 3478, 3479, 5004, 5005, 6970, 7777, 8767, 27015, 27016,

	// IoT and embedded devices
	81, 554, 1900, 8554, 49152,

	// Industrial and specialized
	102, 502, 789, 1089, 1091, 1911, 2222, 2404, 4000, 4840, 44818, 47808, 50000,
}
