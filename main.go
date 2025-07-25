// redhound - A minimal concurrent internal network enumerator in Go with SOCKS4 proxy support.
// -----------------------------------------------------------------------------
// ⚠️  USE ONLY AGAINST NETWORKS YOU HAVE EXPLICIT PERMISSION TO TEST.
// -----------------------------------------------------------------------------
// Requirements:
//   - Go ≥1.20
//   - No external dependencies (pure Go implementation)
//
// Build:   go build -o redhound .
// Examples:
//
//	# Scan a single host
//	./redhound 192.168.1.100 -o results.json
//
//	# Direct scan of a /24
//	./redhound 192.168.1.0/24 -o results.json -r 64
//
//	# Route all traffic through SOCKS4 proxy
//	./redhound 10.0.0.0/24 -p socks4://127.0.0.1:1080
//
//	# SOCKS5 proxy (also supported)
//	./redhound 10.0.0.0/24 -p socks5://127.0.0.1:9050
//
//	# Custom port range with timeout
//	./redhound 192.168.1.0/24 -P 1-1000 -t 10s
//
// -----------------------------------------------------------------------------
// Features:
//   - Expands a CIDR into individual hosts
//   - Concurrent per‑host scans (rate‑limited)
//   - SOCKS4/5 proxy support for internal network enumeration
//   - Basic service detection via banner grabbing
//   - JSON output: hostname, detected services
//
// -----------------------------------------------------------------------------
package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
)

// CLI represents the command-line interface configuration
type CLI struct {
	Target string `arg:"" help:"IP address or CIDR range to scan" type:"string"`

	// Output options
	Output   string `short:"o" help:"Output file for JSON results" default:"results.json" type:"path"`
	Quiet    bool   `short:"q" help:"Suppress banner and non-essential output"`
	Verbose  bool   `short:"v" help:"Enable detailed output and progress information"`
	NoColor  bool   `short:"n" help:"Disable colored terminal output"`

	// Scanning options
	Rate     int           `short:"r" help:"Maximum concurrent host scans (1-256)" default:"32" range:"1,256"`
	Timeout  time.Duration `short:"t" help:"Connection timeout per port" default:"5s"`
	Ports    string        `short:"P" help:"Ports to scan. Examples: '80,443', '1-1000', '22,80-90,443'"`
	AllPorts bool          `short:"A" help:"Scan all 65535 ports (equivalent to -P 1-65535)"`
	Proxy    string        `short:"p" help:"SOCKS proxy URL: socks4://host:port or socks5://host:port"`

}

func main() {
	// Handle version flag before Kong parsing to avoid target requirement
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			printVersion()
			return
		}
	}

	var cli CLI

	// Configure Kong with custom options
	_ = kong.Parse(&cli,
		kong.Name("redhound"),
		kong.Description("A minimal concurrent network enumerator with SOCKS proxy support"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: false,
			Summary: true,
		}),
		kong.Vars{
			"version": "1.2.0",
		},
	)

	// Execute the main scan
	runScan(&cli)
}

func runScan(cli *CLI) {

	// Initialize output settings
	initOutput(cli.NoColor, cli.Verbose)

	// Print banner unless quiet mode
	if !cli.Quiet {
		printBanner()
	}

	// Get and validate target (Kong handles the required argument validation)
	target := strings.TrimSpace(cli.Target)
	if target == "" {
		printError("Target cannot be empty")
		os.Exit(1)
	}

	// Validate configuration (Kong handles rate range validation)
	if cli.Timeout < time.Millisecond {
		printError("Timeout must be at least 1ms, got: %v", cli.Timeout)
		os.Exit(1)
	}

	// Parse and validate proxy URL if provided
	if cli.Proxy != "" {
		if err := validateProxyURL(cli.Proxy); err != nil {
			printError("Invalid proxy URL: %v", err)
			os.Exit(1)
		}
	}

	// Validate port options
	if cli.AllPorts && cli.Ports != "" {
		printError("Cannot specify both -A (all ports) and -P (port specification) at the same time")
		printError("Use either -A for all ports or -P for specific ports")
		os.Exit(1)
	}

	// Parse ports to scan
	ports := CommonPorts
	if cli.AllPorts {
		// Generate all ports 1-65535
		ports = make([]uint16, 65535)
		for i := 1; i <= 65535; i++ {
			ports[i-1] = uint16(i)
		}
		if !cli.Quiet {
			printWarning("Scanning all 65535 ports - this may take significant time")
			printWarning("Consider using -q flag to reduce output or -r to adjust concurrency")
		}
	} else if cli.Ports != "" {
		var err error
		ports, err = parsePorts(cli.Ports)
		if err != nil {
			printError("Invalid port specification: %v", err)
			printError("Examples: '80,443', '1-1000', '22,80-90,443'")
			os.Exit(1)
		}
		if len(ports) == 0 {
			printError("No valid ports specified")
			os.Exit(1)
		}
	}

	// Adjust defaults for proxy usage with better messaging
	if cli.Proxy != "" {
		originalRate := cli.Rate
		originalTimeout := cli.Timeout
		
		if cli.Rate > 10 {
			cli.Rate = 10
			if !cli.Quiet {
				printWarning("Proxy detected: reducing concurrency from %d to %d for stability", originalRate, cli.Rate)
			}
		}
		if cli.Timeout < 10*time.Second {
			cli.Timeout = 10 * time.Second
			if !cli.Quiet {
				printWarning("Proxy detected: increasing timeout from %v to %v for reliability", originalTimeout, cli.Timeout)
			}
		}
	}

	ips, err := parseTarget(target)
	if err != nil {
		printError("Invalid target '%s': %v", target, err)
		printError("")
		printError("Valid target formats:")
		printError("  Single IP:    192.168.1.100")
		printError("  CIDR range:   192.168.1.0/24")
		printError("  Subnet:       10.0.0.0/16")
		os.Exit(1)
	}

	if len(ips) == 0 {
		printError("No valid IP addresses found in target: %s", target)
		os.Exit(1)
	}

	// Warn about large scans
	if len(ips) > 1000 && !cli.Quiet {
		printWarning("Large scan detected: %d hosts. This may take significant time.", len(ips))
		printWarning("Consider using smaller CIDR ranges or increasing timeout values.")
	}

	// Track scan start time
	startTime := time.Now()

	// Print scan summary unless quiet
	if !cli.Quiet {
		printScanSummary(target, len(ips), len(ports), cli.Proxy, cli.Rate, cli.Timeout)
	}

	sem := make(chan struct{}, cli.Rate)
	var wg sync.WaitGroup
	results := make([]Host, 0)
	var mux sync.Mutex

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			host, err := scanHost(ip, ports, cli.Timeout, cli.Proxy)
			<-sem
			if err != nil {
				printVerbose("Error scanning %s: %v", ip, err)
				return
			}
			if len(host.Services) > 0 {
				mux.Lock()
				results = append(results, host)
				printHostDiscovery(host)
				mux.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	if err := saveJSON(cli.Output, results); err != nil {
		printError("Failed to save results: %v", err)
		os.Exit(1)
	}

	// Print final summary
	if !cli.Quiet {
		printScanComplete(results, cli.Output, startTime)
	} else {
		// In quiet mode, just print essential results
		fmt.Printf("Scan complete: %d hosts with open ports found in %v\n", len(results), time.Since(startTime).Round(time.Second))
		fmt.Printf("Results saved to: %s\n", cli.Output)
	}
}
