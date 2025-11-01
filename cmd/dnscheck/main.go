package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	dnscheck "github.com/dogasantos/dnscheck/pkg/runner"
)

// Options holds the command-line options

type Options struct {
	TargetListFile string
	Requests       int // New flag for number of requests per resolver
	Workers        int // New flag for number of concurrent workers
	Verbose        bool
}

// parseOptions parses the command-line options

func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.TargetListFile, "l", "", "File containing a list of resolvers to check (or stdin)")
	flag.IntVar(&options.Requests, "r", 100, "Number of requests to send to each resolver")
	flag.IntVar(&options.Workers, "w", 100, "Number of concurrent workers")
	flag.BoolVar(&options.Verbose, "v", false, "Verbose mode")
	flag.Parse()
	return options
}

func main() {
	options := parseOptions()

	var targets []string
	var err error

	// Read from file or stdin
	if options.TargetListFile != "" {
		targets, err = readLines(options.TargetListFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading target file: %v\n", err)
			return
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			targets = append(targets, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			return
		}
	}

	// Filter out empty lines
	var filteredTargets []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if len(target) > 0 {
			filteredTargets = append(filteredTargets, target)
		}
	}
	targets = filteredTargets

	if options.Verbose {
		fmt.Fprintf(os.Stderr, "[+] dnscheck\n")
		fmt.Fprintf(os.Stderr, "  + Requests per resolver: %d\n", options.Requests)
		fmt.Fprintf(os.Stderr, "  + Concurrent workers: %d\n", options.Workers)
		fmt.Fprintf(os.Stderr, "  + Targets loaded: %d\n", len(targets))
		fmt.Fprintf(os.Stderr, "  + Starting routines\n")
	}

	// Channel to feed targets to workers
	targetsChan := make(chan string, len(targets))
	for _, target := range targets {
		targetsChan <- target
	}
	close(targetsChan)

	// Use a WaitGroup to wait for all workers to finish
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < options.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetsChan {
				dnscheck.Start(target, options.Requests, options.Verbose)
			}
		}()
	}

	// Wait for all workers to complete
	wg.Wait()

	if options.Verbose {
		fmt.Fprintf(os.Stderr, "  + Completed checking all targets\n")
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
