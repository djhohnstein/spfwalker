package httputils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Retrieve the x509 cert from the remote server; times out otherwise.
func GetSSLCertificate(host string) *x509.Certificate {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", host), 5*time.Second)
	if err != nil {
		return nil
	}
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := tls.Client(conn, config)
	err = client.Handshake()
	if err != nil {
		return nil
	}
	certs := client.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	return certs[0]
}

// Given an html node, recursively find all tags and stuff into the results
func GetMatchingNodes(n *html.Node, tag string, results *[]*html.Node) {
	if n.Type == html.ElementNode && n.Data == tag {
		// fmt.Println("Found a table!")
		*results = append(*results, n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		GetMatchingNodes(c, tag, results)
	}
}

// Retrieve any text within a node, otherwise return nothing
func GetNodeText(n *html.Node) string {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		// fmt.Println("Type:", c.Type)
		// fmt.Println("Data", c.Data)
		if c.Type == html.TextNode && strings.TrimSpace(c.Data) != "" {
			return strings.TrimSpace(c.Data)
		}
	}
	return ""
}

func GetAttrValue(n *html.Node, target string) string {
	for _, r := range n.Attr {
		if r.Key == target {
			return r.Val
		}
	}
	return ""
}

// func FilterSetCookieForCookie(resp *http.Response, target string) {
// 	// Filters the cookies of the request for a specific key (target)
// 	cookies := resp.Cookies()
// 	for _, cookie := range cookies {
// 		// split the strings
// 		parts := strings.Split(cookie, ",")
// 	}

// }
