package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	file := flag.String("file", "", "file containing list of zones, one per line")
	flag.Parse()

	if *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	zones := []string{}

	f, err := os.Open(*file)
	if err != nil {
		log.Fatal(err)
	}

	r := bufio.NewReader(f)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		zones = append(zones, scanner.Text())
	}

	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}

	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal(err)
	}

	for _, zone := range zones {

		m := new(dns.Msg)
		m.SetEdns0(4096, true)
		m.Id = dns.Id()
		m.RecursionDesired = true
		m.Question = make([]dns.Question, 1)
		m.Question[0] = dns.Question{Name: dns.Fqdn(zone), Qtype: dns.TypeSOA, Qclass: dns.ClassINET}

		c := new(dns.Client)
		in, _, err := c.Exchange(m, cc.Servers[0]+":"+cc.Port)
		if err != nil {
			log.Fatal(err)
		}

		if in.MsgHdr.Rcode != dns.RcodeSuccess {
			fmt.Printf("%s: %s\n", zone, dns.RcodeToString[in.MsgHdr.Rcode])
			continue
		}

		//fmt.Println(in)

		rrsigFound := false
		for _, rr := range in.Answer {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				rrsigFound = true
				inceptionTime := time.Unix(int64(rrsig.Inception), 0)
				expirationTime := time.Unix(int64(rrsig.Expiration), 0)
				validDuration := expirationTime.Sub(inceptionTime)
				fmt.Printf("%s: %.0f\n", zone, validDuration.Seconds())
			}
		}

		if !rrsigFound {
			fmt.Printf("%s: RRSIG missing\n", zone)
		}
	}
}
