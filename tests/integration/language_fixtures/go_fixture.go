package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		panic("url scratch certificate")
	}
	u, err := url.Parse(os.Args[1])
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "connectivity.macdbg.invalid") {
		panic("local fixture only")
	}
	path := os.Args[2] + "/go-analyst-marker.txt"
	if err = os.WriteFile(path, []byte("benign-go-file-content"), 0600); err != nil {
		panic(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	fmt.Printf("FILE:%s\n", b)
	roots := x509.NewCertPool()
	if os.Args[3] != "-" {
		pem, e := os.ReadFile(os.Args[3])
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			panic("certificate")
		}
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: false}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, _ := http.NewRequest("POST", os.Args[1], strings.NewReader("language=go&marker=benign-analyst-payload"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Macdbg-Fixture", "benign-go")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("NETWORK-ERROR:", err)
		os.Exit(2)
	}
	defer resp.Body.Close()
	b, err = io.ReadAll(resp.Body)
	fmt.Printf("RESULT:%d %s error=%v\n", resp.StatusCode, b, err)
	if resp.StatusCode != 200 || string(b) != "fixture-online" || err != nil {
		os.Exit(3)
	}
}
