package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"spfwalker/lib/spf"
)

func main() {
	outFilePtr := flag.String("outfile", "", "File to save JSON results to.")
	domainPtr := flag.String("domain", "", "Domain to walk and retrieve SPF records for.")
	flag.Parse()

	if *domainPtr == "" {
		fmt.Println("[-] Error: Not enough arguments given. Please pass a domain with the -domain flag.")
		os.Exit(1)
	}

	worker := spf.NewSPFWorker()
	worker.WalkAllSPFRecords(*domainPtr)
	// records := spf.WalkSPFRecord(*domainPtr)

	// err := spf.ResolveWhoisInfo(&records)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	for _, r := range worker.Results {
		fmt.Printf("Domain: %s (%d includes, %d ip4)\n", r.Domain, len(r.Include), len(r.IPv4))
		for _, d := range r.Include {
			fmt.Printf("\t[Include] %s\n", d)
		}
		for _, ip := range r.IPv4 {
			fmt.Printf("\t[IP4]     %s\n", ip)
		}
		fmt.Println()
		for _, rec := range r.WhoisRecords {
			fmt.Println("\tWhois Information")
			fmt.Printf("\t\t[CN]         %s\n", rec.CN)
			fmt.Printf("\t\t[IPv4]       %s\n", rec.IPv4)
			fmt.Printf("\t\t[Name]       %s\n", rec.Name)
			fmt.Printf("\t\t[HostName]   %s\n", rec.HostName)
			fmt.Printf("\t\t[SearchTerm] %s\n", rec.SearchTerm)
			fmt.Println()
		}
		fmt.Println()
	}

	if *outFilePtr != "" {
		file, _ := json.MarshalIndent(worker.Results, "", " ")
		_ = ioutil.WriteFile(*outFilePtr, file, 0644)
		fmt.Println("[+] Wrote results to", *outFilePtr)
	}
}
