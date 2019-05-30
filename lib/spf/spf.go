package spf

import (
	"log"
	"net"
	"spfwalker/lib/arin"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
)

type SPFRecord struct {
	Domain       string              `json:"Domain"`       // Root domain you looked up
	IPv4         []string            `json:"IPv4"`         // IPv4's returned that are allowed to send.
	Include      []string            `json:"Include"`      // List of domains that are allowed to send.
	WhoisRecords []*arin.WhoisResult `json:"WhoisRecords"` // Once SPF records are resolved, we do whois lookups
}

type SPFWorker struct {
	lock    *semaphore.Weighted
	mtx     sync.Mutex
	Results []*SPFRecord
}

// controls threads
func NewSPFWorker() SPFWorker {
	return SPFWorker{
		lock: semaphore.NewWeighted(20),
		mtx:  sync.Mutex{},
	}
}

func GetSPFRecord(domain string) *SPFRecord {
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}
	for _, r := range records {
		if strings.HasPrefix(r, "v=spf") {
			spfRec := new(SPFRecord)
			spfRec.Domain = domain
			parseSPFString(r, spfRec)

			return spfRec
		}
	}
	return nil
}

func parseSPFString(spfString string, spfRec *SPFRecord) {
	// v=spf1 include:dispatch-us.ppe-hosted.com include:spf.protection.outlook.com -all
	parts := strings.Split(spfString, " ")
	for _, part := range parts {
		spfInfoParts := strings.SplitN(part, ":", 2)
		if len(spfInfoParts) != 2 {
			continue
		}
		switch spfInfoParts[0] {
		case "include":
			spfRec.Include = append(spfRec.Include, spfInfoParts[1])
		case "ip4":
			spfRec.IPv4 = append(spfRec.IPv4, spfInfoParts[1])
		default:
			continue
		}
	}
}

func (worker *SPFWorker) WalkAllSPFRecords(domain string) {
	worker.WalkSPFRecord(domain)
	worker.ResolveWhoisInfo()
}

func (worker *SPFWorker) WalkSPFRecord(domain string) {
	rec := GetSPFRecord(domain)
	if rec == nil {
		return
	}
	worker.mtx.Lock()
	worker.Results = append(worker.Results, rec)
	worker.mtx.Unlock()
	// records = append(records, rec)
	if len(rec.Include) > 0 {
		ch := make(chan int)
		for i := 0; i < len(rec.Include); i++ {
			go func(domain *string, ch chan int) {
				worker.WalkSPFRecord(*domain)
				ch <- 0
			}(&rec.Include[i], ch)
			// records = append(records, res...)
		}
		for i := 0; i < len(rec.Include); i++ {
			<-ch
		}
	}
}

func (worker *SPFWorker) ResolveWhoisInfo() error {

	// ip: domainName
	domainIpMap := make(map[string]string)
	// ch := make(chan int)
	mtx := sync.Mutex{}
	for _, record := range worker.Results {
		var iplist []string
		wg := sync.WaitGroup{}
		for _, d := range record.Include {
			wg.Add(1)
			go func(domain string, domainIpMap *map[string]string, iplist *[]string) {
				defer wg.Done()
				ips, err := net.LookupIP(domain)
				if err != nil {
					// fmt.Println("Couldn't resolve ip for", d)
					return
				}
				mtx.Lock()
				(*domainIpMap)[ips[0].String()] = domain
				// fmt.Println("Added IP to the list:", ips[0])
				*iplist = append(*iplist, ips[0].String())
				mtx.Unlock()
			}(d, &domainIpMap, &iplist)
			wg.Wait()
			// ips, err := net.LookupIP(d)
			// if err != nil {
			// 	fmt.Println("Couldn't resolve ip for", d)
			// 	continue
			// }
			// domainIpMap[ips[0].String()] = d
			// fmt.Println("Added IP to the list:", ips[0])
			// iplist = append(iplist, ips[0].String())
		}
		for _, ipStr := range record.IPv4 {
			ipStr = strings.SplitN(ipStr, "/", 2)[0]
			iplist = append(iplist, ipStr)
		}
		whoisRecords, err := arin.WhoisLookup(iplist)
		if err != nil {
			log.Fatalln(err)
		}
		for _, whoisRecord := range whoisRecords {
			if val, ok := domainIpMap[whoisRecord.SearchTerm]; ok {
				whoisRecord.SearchTerm = val
			}
		}
		record.WhoisRecords = whoisRecords
	}
	return nil
}
