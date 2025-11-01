package dnscheck

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

// DoResolve performs a single DNS query
func DoResolve(target string, saferecord string) string {
	var resolvers []string
	// The target is expected to be an IP address, so we append the default DNS port
	resolvers = append(resolvers, target+":53")

	// retryabledns client with a low number of retries (2)
	dnsClient, _ := retryabledns.New(resolvers, 2)

	// Query for an A record
	dnsResponses, _ := dnsClient.Query(saferecord, dns.TypeA)

	// Check if we got any A records
	if len(dnsResponses.A) > 0 {
		return dnsResponses.A[0]
	} else {
		return "fail"
	}
}

// Start checks a single resolver for poisoning by sending multiple requests
// It now takes the number of requests as a parameter.
func Start(target string, requests int, verbose bool) {
	var poisoned = false
	var successfulRequests = 0
	const maxRetries = 5 // Max retries for a single query attempt

	// The goal is to get 'requests' number of successful, non-poisoned responses.
	for successfulRequests < requests {
		var a_record string
		var queryAttempt = 0
		var querySuccess = false

		// 1. Retry loop for transient failures
		for queryAttempt < maxRetries {
			a_record = DoResolve(target, "a.localtest.me")

			if a_record != "fail" {
				querySuccess = true
				break // Query succeeded, break out of retry loop
			}

			// Query failed, increment attempt and wait a bit before retrying
			queryAttempt++
			time.Sleep(100 * time.Millisecond)
		}

		// 2. Check for permanent failure or poisoning
		if !querySuccess {
			// If all retries failed, we consider the resolver permanently down for this check.
			// We do not print it, effectively dropping it.
			if verbose {
				fmt.Fprintf(os.Stderr, "[!] Resolver %s failed all %d query attempts.\n", target, maxRetries)
			}
			return
		}

		// 3. Check for poisoning
		if a_record != "127.0.0.1" {
			// Poisoning detected, drop the resolver immediately.
			if verbose {
				fmt.Fprintf(os.Stderr, "[!] Resolver %s is poisoned (response: %s). Dropping.\n", target, a_record)
			}
			poisoned = true
			break // Break out of the main loop
		}

		// If we reached here, the query was successful and not poisoned.
		successfulRequests++
	}

	// Only print the target if it is NOT poisoned AND we achieved the required number of successful requests.
	if !poisoned && successfulRequests == requests {
		fmt.Printf("%s\n", target)
	}
}
