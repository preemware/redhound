// netenum - A minimal concurrent internal network enumerator in Go with SOCKS4 proxy support.
// -----------------------------------------------------------------------------
// ⚠️  USE ONLY AGAINST NETWORKS YOU HAVE EXPLICIT PERMISSION TO TEST.
// -----------------------------------------------------------------------------
// Requirements:
//   - Go ≥1.20
//   - No external dependencies (pure Go implementation)
//
// Build:   go build -o netenum .
// Examples:
//
//	# Direct scan of a /24
//	./netenum -cidr 192.168.1.0/24 -o results.json -rate 64
//
//	# Route all traffic through SOCKS4 proxy
//	./netenum -cidr 10.0.0.0/24 -proxy socks4://127.0.0.1:1080
//
//	# SOCKS5 proxy (also supported)
//	./netenum -cidr 10.0.0.0/24 -proxy socks5://127.0.0.1:9050
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
	cidr := flag.String("cidr", "", "CIDR range to scan, e.g. 192.168.0.0/24")
	out := flag.String("o", "results.json", "Output JSON file")
	rate := flag.Int("rate", 32, "Maximum concurrent host scans")
	timeout := flag.Duration("timeout", 5*time.Second, "Per‑port connection timeout")
	proxy := flag.String("proxy", "", "Proxy URL (socks4|socks5), e.g. socks4://127.0.0.1:1080")
	portRange := flag.String("ports", "", "Port range to scan (default: common ports), e.g. 1-1000 or 80,443,8080")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	verbose := flag.Bool("v", false, "Enable verbose output")
	flag.Parse()

	// Initialize output settings
	initOutput(*noColor, *verbose)

	// Print banner
	printBanner()

	if *cidr == "" {
		printError("you must specify -cidr")
		flag.Usage()
		os.Exit(1)
	}

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

	ips, err := cidrHosts(*cidr)
	if err != nil {
		printError("Failed to parse CIDR: %v", err)
		os.Exit(1)
	}

	// Track scan start time
	startTime := time.Now()

	// Print scan summary
	printScanSummary(*cidr, len(ips), len(ports), *proxy, *rate, *timeout)

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
