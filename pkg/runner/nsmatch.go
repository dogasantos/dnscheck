package nsmatch

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

// This is a nice comment to make lint happy. hello lint, i'm here!
func DoResolve(target string) string {
	var resolvers []string
	
	resolvers = append(resolvers,target+":53")

	dnsClient := retryabledns.New(resolvers, 2)
	dnsResponses, _ := dnsClient.Query(target, dns.TypeA)
	return dnsResponses.A
}

func Start(target string, verbose bool, wg *sync.WaitGroup) {
	var resolver string

	defer wg.Done()
	a_record := DoResolve("a.localho.st") // a.localtest.me also works
	
	if verbose {
		fmt.Printf("  + Baseline: a.localho.st host has ip address %s\n", a_record)
	}
	
	
}
	