package main

// Service represents a detected service on a host
type Service struct {
    Port     uint16 `json:"port"`
    Protocol string `json:"protocol"`
    Name     string `json:"name,omitempty"`
    Product  string `json:"product,omitempty"`
    Version  string `json:"version,omitempty"`
    State    string `json:"state"`
    Banner   string `json:"banner,omitempty"`
    Title    string `json:"title,omitempty"`
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