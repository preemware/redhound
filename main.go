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
	"flag"
	"os"
	"sync"
	"time"
)

func main() {
	out := flag.String("o", "results.json", "Output JSON file")

	rate := flag.Int("rate", 32, "Maximum concurrent host scans")
	flag.IntVar(rate, "r", 32, "Maximum concurrent host scans")

	timeout := flag.Duration("timeout", 5*time.Second, "Per‑port connection timeout")
	flag.DurationVar(timeout, "t", 5*time.Second, "Per‑port connection timeout")

	proxy := flag.String("proxy", "", "Proxy URL (socks4|socks5), e.g. socks4://127.0.0.1:1080")
	flag.StringVar(proxy, "p", "", "Proxy URL (socks4|socks5), e.g. socks4://127.0.0.1:1080")

	portRange := flag.String("ports", "", "Port range to scan (default: common ports), e.g. 1-1000 or 80,443,8080")
	flag.StringVar(portRange, "P", "", "Port range to scan (default: common ports), e.g. 1-1000 or 80,443,8080")

	noColor := flag.Bool("no-color", false, "Disable colored output")
	flag.BoolVar(noColor, "n", false, "Disable colored output")

	verbose := flag.Bool("v", false, "Enable verbose output")

	flag.Parse()

	// Initialize output settings
	initOutput(*noColor, *verbose)

	// Print banner
	printBanner()

	// Get target from positional arguments
	args := flag.Args()
	if len(args) != 1 {
		printError("you must specify exactly one target (IP address or CIDR range)")
		printError("Usage: %s [options] <target>", os.Args[0])
		printError("Examples:")
		printError("  %s 192.168.1.100", os.Args[0])
		printError("  %s 192.168.1.0/24", os.Args[0])
		flag.Usage()
		os.Exit(1)
	}
	target := args[0]

	// Parse ports to scan
	ports := CommonPorts
	if *portRange != "" {
		var err error
		ports, err = parsePorts(*portRange)
		if err != nil {
			printError("Invalid port range: %v", err)
			os.Exit(1)
		}
	}

	// Adjust defaults for proxy usage
	if *proxy != "" {
		if *rate > 10 {
			printWarning("Reducing rate from %d to 10 for proxy scan", *rate)
			*rate = 10
		}
		if *timeout < 10*time.Second {
			printWarning("Increasing timeout from %v to 10s for proxy scan", *timeout)
			*timeout = 10 * time.Second
		}
	}

	ips, err := parseTarget(target)
	if err != nil {
		printError("Failed to parse target: %v", err)
		os.Exit(1)
	}

	// Track scan start time
	startTime := time.Now()

	// Print scan summary
	printScanSummary(target, len(ips), len(ports), *proxy, *rate, *timeout)

	sem := make(chan struct{}, *rate)
	var wg sync.WaitGroup
	results := make([]Host, 0)
	var mux sync.Mutex

	for _, ip := range ips {
		ip := ip // capture for goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			host, err := scanHost(ip, ports, *timeout, *proxy)
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
		}()
	}

	wg.Wait()

	if err := saveJSON(*out, results); err != nil {
		printError("Failed to save results: %v", err)
		os.Exit(1)
	}

	// Print final summary
	printScanComplete(results, *out, startTime)
}
