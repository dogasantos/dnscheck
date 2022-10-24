package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	dnscheck "github.com/dogasantos/dnscheck/pkg/runner"
)

// This is a nice comment to make lint happy. hello lint, i'm here!
type Options struct {
	TargetListFile		string
	SaneListFile		string
	TrustedRecord		string
	Version				bool
	Verbose				bool
}

var version = "0.1"

func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.TargetListFile, 		"l", "unvalidated-resolvers.txt", "Target file (domains)")
	flag.BoolVar(&options.Version, 					"i", false, "Version info")
	flag.BoolVar(&options.Verbose, 					"v", false, "Verbose mode")
	flag.Parse()
	return options
}

func main() {

	options := parseOptions()
	if options.Version {
		fmt.Println(version)
	}
	
	if options.TargetListFile != "" {
		if options.Verbose == true {
			fmt.Printf("[+] dnscheck v%s\n",version)
		}
		TargetFilestream, _ := ioutil.ReadFile(options.TargetListFile)
		targetContent := string(TargetFilestream)
		targets := strings.Split(targetContent, "\n") // lista de dns servers publicos a testar
		
		if options.Verbose == true {
			fmt.Printf("  + Targets loaded: %d\n",len(targets))
			fmt.Printf("  + Starting routines\n")
		}

		wg := new(sync.WaitGroup)
		routinescounter := 0
		for _, target := range targets {
			target = strings.ReplaceAll(target, " ", "")
			if len(target) > 1 {
				wg.Add(1)
				go dnscheck.Start(target, options.Verbose, wg)
				if routinescounter == 10 {
					time.Sleep(5 * time.Second)
					routinescounter = 0
				} else {
					routinescounter = routinescounter+1
				}
			}
		}
		wg.Wait()
	}
	
}




