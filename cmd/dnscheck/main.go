package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"strings"
	"sync"
	"time"

	dnscheck "github.com/dogasantos/dnscheck/pkg/runner"
)

type Options struct {
	TargetListFile		string
	SaneListFile		string
	TrustedRecord		string
	Iterations			int
	Verbose				bool
}

func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.TargetListFile, 		"l", "unvalidated-resolvers.txt", "Target file (domains)")
	flag.IntVar(&options.Iterations, 				"i", 20, "Number of iterations to run")
	flag.BoolVar(&options.Verbose, 					"v", false, "Verbose mode")
	flag.Parse()
	return options
}

func main() {

	options := parseOptions()
	
	if options.TargetListFile != "" {
		if options.Verbose == true {
			fmt.Printf("[+] dnscheck\n")
			fmt.Printf("  + Iterations: %d\n", options.Iterations)
		}
		TargetFilestream, _ := ioutil.ReadFile(options.TargetListFile)
		targetContent := string(TargetFilestream)
		targets := strings.Split(targetContent, "\n") // lista de dns servers publicos a testar
		
		if options.Verbose == true {
			fmt.Printf("  + Targets loaded: %d\n",len(targets))
			fmt.Printf("  + Starting routines\n")
		}

		// Run the specified number of iterations
		for iteration := 1; iteration <= options.Iterations; iteration++ {
			if options.Verbose == true {
				fmt.Printf("  + Running iteration %d/%d\n", iteration, options.Iterations)
			}
			
			wg := new(sync.WaitGroup)
			routinescounter := 0
			for _, target := range targets {
				target = strings.ReplaceAll(target, " ", "")
				if len(target) > 1 {
					wg.Add(1)
					go dnscheck.Start(target, options.Verbose, wg)
					if routinescounter == int(math.Round(float64(len(targets)) / 10))  {
						time.Sleep(5 * time.Second)
						routinescounter = 0
					} else {
						routinescounter = routinescounter+1
					}
				}
			}
			wg.Wait()
			
			// Add a small delay between iterations if not the last one
			if iteration < options.Iterations {
				time.Sleep(1 * time.Second)
			}
		}
		
		if options.Verbose == true {
			fmt.Printf("  + Completed all %d iterations\n", options.Iterations)
		}
	}
	
}

