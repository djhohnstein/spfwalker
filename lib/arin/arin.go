package arin

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"spfwalker/lib/httputils"
	"strings"
	"time"

	"github.com/buger/jsonparser" // Progress bar
	"golang.org/x/sync/semaphore"
)

// Structure for the information valuable from ARIN
type WhoisResult struct {
	SearchTerm string `json:"SearchTerm"`
	IPv4       string `json:"IPv4"`
	Name       string `json:"Name"`
	HostName   string `json:"HostName"`
	CN         string `json:"CN"`
}

// Structure to ensure we throttle everything A-OKAY
type WhoisLookupObject struct {
	host string
	lock *semaphore.Weighted
}

// Retrieve the DNS name of an IP address via reverse lookup.
func ReverseLookup(ip string) (string, error) {
	addr, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	return addr[0], nil
}

// Run a query on the host/ip and return a WhoIsResult pointer
func (obj *WhoisLookupObject) Query() (*WhoisResult, error) {
	// Throttle the request
	obj.lock.Acquire(context.TODO(), 1)
	defer obj.lock.Release(1)
	_, err := net.DialTimeout("tcp", "whois.arin.net:80", 10*time.Second)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("http://whois.arin.net/rest/ip/%s.json", obj.host)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// Could not open
		return nil, errors.New("Invalid IP address or hostname given.")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// fmt.Println(string(body))
	value, _, _, err := jsonparser.Get(body, "net", "orgRef", "@name")
	if err != nil {
		value = nil
	}
	name := string(value)
	hostname, err := ReverseLookup(obj.host)
	if err != nil {
		hostname = ""
	}
	cert := httputils.GetSSLCertificate(obj.host)
	cn := ""
	if cert != nil {
		cn = cert.Subject.CommonName
	}
	result := &WhoisResult{
		IPv4:     obj.host,
		Name:     name,
		HostName: hostname,
		CN:       cn,
	}
	return result, nil
}

// Perform en-masse whoislookups
func WhoisLookup(ips []string) ([]*WhoisResult, error) {
	// NO work to do
	if len(ips) == 0 {
		return nil, nil
	}
	// bar := pb.StartNew(len(ips))

	ch := make(chan *WhoisResult)
	for i := 0; i < len(ips); i++ {
		go func( /*bar *pb.ProgressBar, */ ip string, ch chan *WhoisResult) {
			// defer bar.Increment()
			lookup := &WhoisLookupObject{
				host: ip,
				lock: semaphore.NewWeighted(100),
			}
			result, err := lookup.Query()
			if err != nil {
				// fmt.Println("err!")
				log.Fatalln(err)
				return
			}
			result.SearchTerm = ip
			// fmt.Println("Sending result to channel!")
			ch <- result
			// fmt.Println("done!")
		}( /*bar, */ ips[i], ch)
	}

	var results []*WhoisResult
	for i := 0; i < len(ips); i++ {
		// fmt.Println("Fetching from channel...")
		r := <-ch
		// fmt.Println("Done!")
		// fmt.Println("Got one from channel!")
		// fmt.Println(r)
		results = append(results, r)
	}
	return results, nil

}

// Convert the struct into a string slice
func (obj *WhoisResult) ToStringSlice() []string {
	result := []string{obj.IPv4, obj.Name, obj.HostName, obj.CN}
	return result
}

// Write results to csv file
func WriteWhoisResultCSV(filename string, data []*WhoisResult) error {
	if !strings.HasSuffix(filename, ".csv") {
		filename += ".csv"
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	// Write the headers
	writer.Write([]string{"IPv4", "Name", "HostName", "CN"})
	for _, result := range data {
		if err := writer.Write(result.ToStringSlice()); err != nil {
			log.Fatalln("error writing to csv:", err)
		}
	}
	return nil
}

func Test() {
	fmt.Println("Hello from ARIN!")
}
