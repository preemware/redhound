package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Global output settings
var (
	colorsEnabled = true
	verboseMode   = false
)

// ANSI color codes
const (
	// Reset
	ColorReset = "\033[0m"

	// Regular colors
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorGray   = "\033[90m"

	// Bold colors
	ColorBoldRed    = "\033[1;31m"
	ColorBoldGreen  = "\033[1;32m"
	ColorBoldYellow = "\033[1;33m"
	ColorBoldBlue   = "\033[1;34m"
	ColorBoldPurple = "\033[1;35m"
	ColorBoldCyan   = "\033[1;36m"
	ColorBoldWhite  = "\033[1;37m"

	// Background colors
	ColorBgRed   = "\033[41m"
	ColorBgGreen = "\033[42m"
)

// Initialize output settings
func initOutput(noColor, verbose bool) {
	colorsEnabled = !noColor
	verboseMode = verbose
}

// Helper function to apply color if colors are enabled
func color(colorCode string) string {
	if colorsEnabled {
		return colorCode
	}
	return ""
}

// Output formatting functions
func printInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, color(ColorBoldBlue)+"[*]"+color(ColorReset)+" "+format+"\n", args...)
}

func printSuccess(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, color(ColorBoldGreen)+"[+]"+color(ColorReset)+" "+format+"\n", args...)
}

func printWarning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, color(ColorBoldYellow)+"[!]"+color(ColorReset)+" "+format+"\n", args...)
}

func printError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, color(ColorBoldRed)+"[!]"+color(ColorReset)+" "+format+"\n", args...)
}

func printVerbose(format string, args ...interface{}) {
	if verboseMode {
		fmt.Fprintf(os.Stderr, color(ColorGray)+"[~]"+color(ColorReset)+" "+format+"\n", args...)
	}
}

// Banner and header functions
func printBanner() {
	banner := `
   ╔═══════════════════════════════════════╗
   ║           ` + color(ColorBoldCyan) + `REDHOUND v1.0` + color(ColorReset) + `             ║
   ║    ` + color(ColorGray) + `Network Enumeration Tool` + color(ColorReset) + `          ║
   ╚═══════════════════════════════════════╝
`
	fmt.Print(banner)
}

func printScanSummary(cidr string, hostCount, portCount int, proxy string, rate int, timeout time.Duration) {
	fmt.Println()
	printInfo("Scan Configuration:")
	fmt.Printf("  └─ Target CIDR:    %s%s%s (%s%d%s hosts)\n",
		color(ColorBoldWhite), cidr, color(ColorReset), color(ColorCyan), hostCount, color(ColorReset))
	fmt.Printf("  └─ Port Range:     %s%d%s ports\n",
		color(ColorCyan), portCount, color(ColorReset))
	fmt.Printf("  └─ Concurrency:    %s%d%s concurrent scans\n",
		color(ColorCyan), rate, color(ColorReset))
	fmt.Printf("  └─ Timeout:        %s%v%s per connection\n",
		color(ColorCyan), timeout, color(ColorReset))

	if proxy != "" {
		fmt.Printf("  └─ Proxy:          %s%s%s\n",
			color(ColorBoldPurple), proxy, color(ColorReset))
	}

	fmt.Println()
	printInfo("Starting scan...")
	fmt.Println()
}

// Enhanced host discovery output
func printHostDiscovery(host Host) {
	if len(host.Services) == 0 {
		return
	}

	// Sort services by port number for consistent output
	sort.Slice(host.Services, func(i, j int) bool {
		return host.Services[i].Port < host.Services[j].Port
	})

	// Header with IP and hostname
	hostDisplay := host.IP
	if host.Hostname != "" && host.Hostname != host.IP {
		hostDisplay = fmt.Sprintf("%s (%s)", host.IP, strings.TrimSuffix(host.Hostname, "."))
	}

	fmt.Printf("%s┌─ %s%s%s%s\n", color(ColorGray), color(ColorBoldGreen), hostDisplay, color(ColorReset), color(ColorGray))

	// Group services by type for better presentation
	httpServices := []Service{}
	otherServices := []Service{}

	for _, service := range host.Services {
		if service.Name == "http" || service.Name == "https" {
			httpServices = append(httpServices, service)
		} else {
			otherServices = append(otherServices, service)
		}
	}

	// Display services
	totalServices := len(host.Services)
	current := 0

	// Show HTTP services first with enhanced info
	for _, service := range httpServices {
		current++
		isLast := current == totalServices

		connector := "├─"
		if isLast {
			connector = "└─"
		}

		portColor := getPortColor(service.Name)
		fmt.Printf("%s%s %s%d%s/%s (%s%s%s)",
			color(ColorGray), connector, color(portColor), service.Port, color(ColorReset),
			service.Protocol, color(ColorBoldCyan), service.Name, color(ColorReset))

		if service.Product != "" {
			fmt.Printf(" - %s%s%s", color(ColorYellow), service.Product, color(ColorReset))
			if service.Version != "" {
				fmt.Printf("/%s", service.Version)
			}
		}

		if service.Title != "" {
			fmt.Printf("\n%s│  └─ Title: %s%s%s", color(ColorGray), color(ColorWhite), service.Title, color(ColorReset))
		}

		if service.Banner != "" && !strings.Contains(service.Banner, service.Title) {
			// Truncate long banners
			banner := service.Banner
			if len(banner) > 80 {
				banner = banner[:77] + "..."
			}
			fmt.Printf("\n%s│  └─ Banner: %s%s%s", color(ColorGray), color(ColorGray), banner, color(ColorReset))
		}
		fmt.Println()
	}

	// Show other services
	for _, service := range otherServices {
		current++
		isLast := current == totalServices

		connector := "├─"
		if isLast {
			connector = "└─"
		}

		portColor := getPortColor(service.Name)
		fmt.Printf("%s%s %s%d%s/%s (%s%s%s)",
			color(ColorGray), connector, color(portColor), service.Port, color(ColorReset),
			service.Protocol, color(ColorBoldCyan), service.Name, color(ColorReset))

		if service.Product != "" {
			fmt.Printf(" - %s%s%s", color(ColorYellow), service.Product, color(ColorReset))
			if service.Version != "" {
				fmt.Printf("/%s", service.Version)
			}
		}

		if service.Banner != "" {
			banner := service.Banner
			if len(banner) > 80 {
				banner = banner[:77] + "..."
			}
			fmt.Printf("\n%s│  └─ Banner: %s%s%s", color(ColorGray), color(ColorGray), banner, color(ColorReset))
		}

		// Display SMB-specific information
		if service.SMB != nil {
			printSMBDetails(service.SMB, isLast)
		}

		// Display LDAP-specific information
		if service.LDAP != nil {
			printLDAPDetails(service.LDAP, isLast)
		}

		fmt.Println()
	}
	fmt.Println()
}

// printSMBDetails displays detailed SMB/NTLM information
func printSMBDetails(smb *SMBInfo, isLast bool) {
	prefix := "│  "
	if isLast {
		prefix = "   "
	}

	if smb.Domain != "" {
		fmt.Printf("\n%s%s├─ Domain: %s%s%s", color(ColorGray), prefix, color(ColorCyan), smb.Domain, color(ColorReset))
	}
	if smb.Computer != "" {
		fmt.Printf("\n%s%s├─ Computer: %s%s%s", color(ColorGray), prefix, color(ColorCyan), smb.Computer, color(ColorReset))
	}
	if smb.NetBIOSName != "" {
		fmt.Printf("\n%s%s├─ NetBIOS Name: %s%s%s", color(ColorGray), prefix, color(ColorCyan), smb.NetBIOSName, color(ColorReset))
	}
	if smb.OSVersion != "" {
		fmt.Printf("\n%s%s├─ OS Version: %s%s%s", color(ColorGray), prefix, color(ColorCyan), smb.OSVersion, color(ColorReset))
	}
	if smb.NullSession {
		fmt.Printf("\n%s%s├─ %sNull Session: Allowed%s", color(ColorGray), prefix, color(ColorBoldRed), color(ColorReset))
	}
	if len(smb.Shares) > 0 {
		fmt.Printf("\n%s%s└─ Accessible Shares: %s%s%s", color(ColorGray), prefix, color(ColorYellow), strings.Join(smb.Shares, ", "), color(ColorReset))
	}
}

// printLDAPDetails displays detailed LDAP information
func printLDAPDetails(ldap *LDAPInfo, isLast bool) {
	prefix := "│  "
	if isLast {
		prefix = "   "
	}

	if ldap.Domain != "" {
		fmt.Printf("\n%s%s├─ Domain: %s%s%s", color(ColorGray), prefix, color(ColorCyan), ldap.Domain, color(ColorReset))
	}
	if ldap.BaseDN != "" {
		fmt.Printf("\n%s%s├─ Base DN: %s%s%s", color(ColorGray), prefix, color(ColorCyan), ldap.BaseDN, color(ColorReset))
	}
	if ldap.ServerName != "" {
		fmt.Printf("\n%s%s├─ Server: %s%s%s", color(ColorGray), prefix, color(ColorCyan), ldap.ServerName, color(ColorReset))
	}
	if ldap.NamingContext != "" {
		fmt.Printf("\n%s%s├─ Naming Context: %s%s%s", color(ColorGray), prefix, color(ColorCyan), ldap.NamingContext, color(ColorReset))
	}
	if ldap.AnonymousBind {
		fmt.Printf("\n%s%s├─ %sAnonymous Bind: Allowed%s", color(ColorGray), prefix, color(ColorBoldRed), color(ColorReset))
	}
	if len(ldap.Users) > 0 && ldap.Users[0] != "enumeration_successful" {
		fmt.Printf("\n%s%s├─ Users Found: %s%d%s", color(ColorGray), prefix, color(ColorYellow), len(ldap.Users), color(ColorReset))
	} else if len(ldap.Users) > 0 {
		fmt.Printf("\n%s%s├─ %sUser Enumeration: Possible%s", color(ColorGray), prefix, color(ColorBoldRed), color(ColorReset))
	}
	if len(ldap.Groups) > 0 && ldap.Groups[0] != "enumeration_successful" {
		fmt.Printf("\n%s%s├─ Groups Found: %s%d%s", color(ColorGray), prefix, color(ColorYellow), len(ldap.Groups), color(ColorReset))
	} else if len(ldap.Groups) > 0 {
		fmt.Printf("\n%s%s├─ %sGroup Enumeration: Possible%s", color(ColorGray), prefix, color(ColorBoldRed), color(ColorReset))
	}
	if len(ldap.Computers) > 0 && ldap.Computers[0] != "enumeration_successful" {
		fmt.Printf("\n%s%s├─ Computers Found: %s%d%s", color(ColorGray), prefix, color(ColorYellow), len(ldap.Computers), color(ColorReset))
	} else if len(ldap.Computers) > 0 {
		fmt.Printf("\n%s%s├─ %sComputer Enumeration: Possible%s", color(ColorGray), prefix, color(ColorBoldRed), color(ColorReset))
	}
}

// Get color for port based on service type
func getPortColor(serviceName string) string {
	switch serviceName {
	case "http", "https":
		return ColorBoldGreen
	case "ssh":
		return ColorBoldBlue
	case "ftp":
		return ColorBoldYellow
	case "smb":
		return ColorBoldPurple
	case "ldap", "ldaps":
		return ColorBoldPurple
	case "dns":
		return ColorBoldCyan
	case "mysql", "postgresql", "mssql":
		return ColorBoldRed
	case "rdp", "vnc":
		return ColorBoldYellow
	default:
		return ColorWhite
	}
}

// Final scan results summary
func printScanComplete(results []Host, outputFile string, startTime time.Time) {
	duration := time.Since(startTime)
	fmt.Println()

	// Summary statistics
	totalHosts := len(results)
	totalServices := 0
	serviceTypes := make(map[string]int)

	for _, host := range results {
		totalServices += len(host.Services)
		for _, service := range host.Services {
			serviceTypes[service.Name]++
		}
	}

	printSuccess("Scan Results:")
	fmt.Printf("  └─ Duration:        %s%v%s\n", color(ColorCyan), duration.Round(time.Second), color(ColorReset))
	fmt.Printf("  └─ Hosts Found:     %s%d%s with open ports\n", color(ColorBoldGreen), totalHosts, color(ColorReset))
	fmt.Printf("  └─ Total Services:  %s%d%s services discovered\n", color(ColorCyan), totalServices, color(ColorReset))
	fmt.Printf("  └─ Output File:     %s%s%s\n", color(ColorYellow), outputFile, color(ColorReset))

	fmt.Println()
}

// Progress indicator for verbose mode
func printProgress(current, total int) {
	if total == 0 {
		return
	}

	percent := float64(current) / float64(total) * 100
	printVerbose("Progress: %d/%d hosts scanned (%.1f%%)", current, total, percent)
}
