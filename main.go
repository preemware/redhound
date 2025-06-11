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
	"fmt"
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
	flag.Parse()

	if *cidr == "" {
		fmt.Fprintln(os.Stderr, "[!] you must specify -cidr")
		flag.Usage()
		os.Exit(1)
	}

	// Parse ports to scan
	ports := CommonPorts
	if *portRange != "" {
		var err error
		ports, err = parsePorts(*portRange)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid port range: %v\n", err)
			os.Exit(1)
		}
	}

	// Adjust defaults for proxy usage
	if *proxy != "" {
		if *rate > 10 {
			fmt.Fprintf(os.Stderr, "[!] Reducing rate from %d to 10 for proxy scan\n", *rate)
			*rate = 10
		}
		if *timeout < 10*time.Second {
			fmt.Fprintf(os.Stderr, "[!] Increasing timeout from %v to 10s for proxy scan\n", *timeout)
			*timeout = 10 * time.Second
		}
		fmt.Fprintf(os.Stderr, "[*] Using proxy: %s\n", *proxy)
	}

	ips, err := cidrHosts(*cidr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[*] Scanning %d hosts on %d ports\n", len(ips), len(ports))

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
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", ip, err)
				return
			}
			if len(host.Services) > 0 {
				portList := formatPortList(host.Services)
				fmt.Printf("[+] %s: %s\n", ip, portList)
				mux.Lock()
				results = append(results, host)
				mux.Unlock()
			}
		}()
	}

	wg.Wait()

	if err := saveJSON(*out, results); err != nil {
		panic(err)
	}

	fmt.Printf("\n✔ Scan complete. %d hosts with services found. Results written to %s\n", len(results), *out)
}
