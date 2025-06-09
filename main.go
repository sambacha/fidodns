package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Pre-assigned tunnel server domains
var assignedTunnelServerDomains = []string{
	"cable.ua5v.com", // Google (index 0)
	"cable.auth.com", // Apple (index 1)
}

// Magic bytes for SHA-256 input: "caBLEv2 tunnel server domain"
var shaInputPrefix = []byte{
	0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,
	0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,
	0x6d, 0x61, 0x69, 0x6e,
}

// TLD options for generated domains
var tlds = []string{".com", ".org", ".net", ".info"}

// Base32 alphabet for domain encoding
const base32Chars = "abcdefghijklmnopqrstuvwxyz234567"

// DomainResult holds the result of domain generation
type DomainResult struct {
	Value      uint16 `json:"value"`
	Domain     string `json:"domain"`
	Type       string `json:"type"` // "assigned" or "generated"
	Available  *bool  `json:"available,omitempty"`
	CheckError string `json:"check_error,omitempty"`
}

// generateDomain generates a FIDO tunnel server domain for the given value
func generateDomain(value uint16) (string, string, error) {
	if value < 256 {
		if int(value) >= len(assignedTunnelServerDomains) {
			return "", "", fmt.Errorf("unassigned pre-defined domain index: %d", value)
		}
		return assignedTunnelServerDomains[value], "assigned", nil
	}

	// Construct SHA input
	shaInput := make([]byte, len(shaInputPrefix), len(shaInputPrefix)+3)
	copy(shaInput, shaInputPrefix)
	shaInput = append(shaInput, byte(value), byte(value>>8), 0)

	// Calculate SHA-256
	digest := sha256.Sum256(shaInput)

	// Extract first 8 bytes as little-endian uint64
	v := binary.LittleEndian.Uint64(digest[:8])

	// Bottom 2 bits select TLD
	tldIndex := v & 3
	v >>= 2

	// Build domain with base32 encoding
	domain := "cable."
	// Use a do-while equivalent loop to ensure at least one character is generated,
	// preventing an empty domain part if v is 0.
	for {
		domain += string(base32Chars[v&31])
		v >>= 5
		if v == 0 {
			break
		}
	}

	// Add TLD
	domain += tlds[tldIndex]

	return domain, "generated", nil
}

// checkDomainAvailability performs a DNS lookup to check if domain is registered
func checkDomainAvailability(domain string) (bool, error) {
	// Use a resolver with a timeout.
	// PreferGo: true avoids using the system's C-based resolver.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 2,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Try to resolve the domain's NS records as a more reliable check for registration.
	_, err := r.LookupNS(ctx, domain)
	if err != nil {
		// If the error is NXDOMAIN, the domain is available.
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return true, nil
		}
		// For other errors (e.g., timeout), we can't be sure.
		return false, err
	}

	// If NS records are found, the domain is registered and thus taken.
	return false, nil
}

// processValue generates domain and optionally checks availability
func processValue(value uint16, checkDNS bool) DomainResult {
	domain, domainType, err := generateDomain(value)
	result := DomainResult{
		Value:  value,
		Domain: domain,
		Type:   domainType,
	}

	if err != nil {
		result.CheckError = err.Error()
		return result
	}

	if checkDNS && domainType == "generated" {
		available, err := checkDomainAvailability(domain)
		if err != nil {
			// Don't set 'available' field, just note the error
			result.CheckError = fmt.Sprintf("DNS check error: %v", err)
		} else {
			result.Available = &available
		}
	}

	return result
}

// exportJSON exports results as JSON
func exportJSON(results []DomainResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// exportCSV exports results as CSV
func exportCSV(results []DomainResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Value", "Domain", "Type", "Available", "Error"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data
	for _, result := range results {
		available := "N/A"
		if result.Available != nil {
			if *result.Available {
				available = "Yes"
			} else {
				available = "No"
			}
		}

		record := []string{
			fmt.Sprintf("%d", result.Value),
			result.Domain,
			result.Type,
			available,
			result.CheckError,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	// Define flags
	var (
		generate     = flag.Uint("generate", 0, "Generate domain for a specific value (0-65535)")
		rangeStart   = flag.Int("range-start", 0, "Start of range for bulk generation")
		rangeEnd     = flag.Int("range-end", -1, "End of range for bulk generation (required for range mode)")
		listAssigned = flag.Bool("list-assigned", false, "List all assigned tunnel server domains")
		verify       = flag.String("verify", "", "Verify if a domain matches a value")
		verifyValue  = flag.Uint("verify-value", 0, "Value to verify against a domain")
		checkDNS     = flag.Bool("check-dns", false, "Check domain availability via DNS lookup")
		exportFormat = flag.String("export", "", "Export format: json or csv")
		outputFile   = flag.String("output", "", "Output filename for export")
		findPattern  = flag.String("find-pattern", "", "Find domains containing this pattern (used with range flags)")
		concurrent   = flag.Int("concurrent", 20, "Number of concurrent DNS checks")
		showHash     = flag.Bool("show-hash", false, "Show SHA-256 hash used for generation")
	)

	// Add usage information
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "FIDO Tunnel Server Domain Generator & Verifier\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate domain for value 256 and show its hash\n")
		fmt.Fprintf(os.Stderr, "  %s -generate 256 -show-hash\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Generate domains for a range with DNS checking and export to CSV\n")
		fmt.Fprintf(os.Stderr, "  %s -range-start 256 -range-end 500 -check-dns -export csv -output domains.csv\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Find available domains containing 'fido' in a range\n")
		fmt.Fprintf(os.Stderr, "  %s -range-start 256 -range-end 10000 -find-pattern fido -check-dns\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Verify a domain/value pair and find the correct value on mismatch\n")
		fmt.Fprintf(os.Stderr, "  %s -verify cable.lookup.com -verify-value 12345\n\n", os.Args[0])
	}

	flag.Parse()

	// If no flags are provided, show usage and exit
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}

	// Handle list assigned domains
	if *listAssigned {
		fmt.Println("Assigned FIDO Tunnel Server Domains:")
		for i, domain := range assignedTunnelServerDomains {
			fmt.Printf("  Index %d: %s\n", i, domain)
		}
		fmt.Printf("\nTotal assigned: %d\n", len(assignedTunnelServerDomains))
		fmt.Printf("Available for assignment: %d\n", 256-len(assignedTunnelServerDomains))
		return
	}

	// Handle single domain generation
	// The check `...Value.String() != "0"` is necessary because 0 is a valid value and the default.
	if flag.Lookup("generate").Value.String() != "0" || *generate == 0 {
		var isSet bool
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "generate" {
				isSet = true
			}
		})
		if isSet {
			result := processValue(uint16(*generate), *checkDNS)

			if *showHash && result.Type == "generated" {
				shaInput := make([]byte, len(shaInputPrefix), len(shaInputPrefix)+3)
				copy(shaInput, shaInputPrefix)
				shaInput = append(shaInput, byte(*generate), byte(*generate>>8), 0)
				digest := sha256.Sum256(shaInput)
				fmt.Printf("SHA-256 Input: %x\n", shaInput)
				fmt.Printf("SHA-256 Hash: %x\n", digest)
				fmt.Printf("First 8 bytes (LE): %x\n\n", digest[:8])
			}

			fmt.Printf("Value %d:\n", result.Value)
			fmt.Printf("  Domain: %s\n", result.Domain)
			fmt.Printf("  Type: %s\n", result.Type)
			if result.Available != nil {
				if *result.Available {
					fmt.Printf("  Available: ✓ YES\n")
				} else {
					fmt.Printf("  Available: ✗ NO\n")
				}
			}
			if result.CheckError != "" {
				fmt.Printf("  Error: %s\n", result.CheckError)
			}
			return
		}
	}

	// Handle range generation or pattern finding
	if *rangeEnd != -1 {
		if *rangeStart < 0 || *rangeEnd < 0 || *rangeStart > *rangeEnd || *rangeEnd > 65535 {
			fmt.Fprintf(os.Stderr, "Error: Invalid range. Ensure 0 <= range-start <= range-end <= 65535.\n")
			os.Exit(1)
		}

		var results []DomainResult
		total := *rangeEnd - *rangeStart + 1

		if *findPattern != "" {
			fmt.Printf("Searching for domains containing '%s' in range %d-%d...\n", *findPattern, *rangeStart, *rangeEnd)
		} else {
			fmt.Printf("Generating domains for range %d-%d...\n", *rangeStart, *rangeEnd)
		}
		if *checkDNS {
			fmt.Printf("DNS checking enabled (concurrency: %d)\n", *concurrent)
		}

		var wg sync.WaitGroup
		resultChan := make(chan DomainResult, total)
		semaphore := make(chan struct{}, *concurrent)

		// Producer: Starts a goroutine for each value, limited by the semaphore
		go func() {
			for i := *rangeStart; i <= *rangeEnd; i++ {
				wg.Add(1)
				semaphore <- struct{}{}
				go func(value uint16) {
					defer wg.Done()
					defer func() { <-semaphore }()
					resultChan <- processValue(value, *checkDNS)
				}(uint16(i))
			}
			wg.Wait()
			close(resultChan)
		}()

		// Collector: Gathers results and filters if necessary
		for result := range resultChan {
			if *findPattern == "" || strings.Contains(strings.ToLower(result.Domain), strings.ToLower(*findPattern)) {
				results = append(results, result)
			}
		}

		// Sort results by value for deterministic output
		sort.Slice(results, func(i, j int) bool {
			return results[i].Value < results[j].Value
		})

		// Display results
		availableCount := 0
		for _, result := range results {
			fmt.Printf("\nValue %-5d: %s", result.Value, result.Domain)
			if result.Type == "assigned" {
				fmt.Printf(" [ASSIGNED]")
			}
			if result.Available != nil {
				if *result.Available {
					fmt.Printf(" [AVAILABLE]")
					availableCount++
				} else {
					fmt.Printf(" [TAKEN]")
				}
			}
			if result.CheckError != "" {
				fmt.Printf(" [ERROR: %s]", result.CheckError)
			}
		}

		fmt.Println() // Newline after results
		if *findPattern != "" {
			fmt.Printf("\nSummary: Found %d matching domains in the range.\n", len(results))
		}
		if *checkDNS {
			fmt.Printf("Of those, %d are available for registration.\n", availableCount)
		}

		// Export if requested
		if *exportFormat != "" && *outputFile != "" {
			var err error
			switch strings.ToLower(*exportFormat) {
			case "json":
				err = exportJSON(results, *outputFile)
			case "csv":
				err = exportCSV(results, *outputFile)
			default:
				fmt.Fprintf(os.Stderr, "\nError: Unknown export format '%s'\n", *exportFormat)
				os.Exit(1)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nError exporting: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nExported %d results to %s\n", len(results), *outputFile)
		}

		return
	}

	// Handle domain verification
	if *verify != "" && flag.Lookup("verify-value").Value.String() != "0" {
		expectedDomain, _, err := generateDomain(uint16(*verifyValue))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating domain for verification: %v\n", err)
			os.Exit(1)
		}

		if expectedDomain == *verify {
			fmt.Printf("✓ MATCH: Domain '%s' correctly corresponds to value %d\n", *verify, *verifyValue)
		} else {
			fmt.Printf("✗ NO MATCH: Value %d generates '%s', not '%s'\n", *verifyValue, expectedDomain, *verify)
			fmt.Printf("\nSearching for value that generates '%s'...\n", *verify)

			// Concurrent reverse-lookup search
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup
			valueChan := make(chan uint16, 1024)
			foundChan := make(chan uint16, 1)

			// Start workers
			numWorkers := *concurrent * 2 // Use more workers for this CPU-bound task
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-ctx.Done():
							return
						case val, ok := <-valueChan:
							if !ok {
								return
							}
							domain, _, err := generateDomain(val)
							if err == nil && domain == *verify {
								select {
								case foundChan <- val:
									cancel() // Signal other workers to stop
								case <-ctx.Done():
								}
								return
							}
						}
					}
				}()
			}

			// Producer: Feed all possible values to workers
			go func() {
				for i := 0; i <= 65535; i++ {
					select {
					case valueChan <- uint16(i):
					case <-ctx.Done():
						break // Stop producing if found
					}
				}
				close(valueChan)
			}()

			// Wait for workers to finish, then close the found channel
			go func() {
				wg.Wait()
				close(foundChan)
			}()

			// Wait for a result or for the search to complete
			if foundValue, ok := <-foundChan; ok {
				fmt.Printf("✓ FOUND: Domain '%s' is generated by value %d\n", *verify, foundValue)
			} else {
				fmt.Printf("✗ NOT FOUND: No value in 0-65535 generates the domain '%s'\n", *verify)
			}
		}
		return
	}
}
