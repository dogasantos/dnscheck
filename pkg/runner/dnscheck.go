package dnscheck

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

func DoResolve(target string, saferecord string) string {
	var resolvers []string
	resolvers = append(resolvers,target+":53")
	dnsClient ,_:= retryabledns.New(resolvers, 2)

	dnsResponses, _ := dnsClient.Query(saferecord, dns.TypeA)
	if len(dnsResponses.A) > 0 {
		return dnsResponses.A[0]
	} else {
		return "fail"
	}
}

func Start(target string, verbose bool, wg *sync.WaitGroup) {
	var a_record string
	var poisoned = false

	defer wg.Done()
	a_record = DoResolve("8.8.8.8" ,"a.localho.st") // a.localtest.me also works
	
	if verbose {
		fmt.Printf("  + Baseline: a.localho.st host has ip address %s\n", a_record)
	}
	a_record = "" 

	for i:=0; i < 5; i++ { 
		a_record = DoResolve(target, "a.localho.st") 
		if a_record != "127.0.0.1" {
			poisoned = true
			break
		}
	}

	if poisoned == false {
		fmt.Printf("%s\n",target)
	}
}
	