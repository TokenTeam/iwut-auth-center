package main

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Production App URL policy is exercised with deterministic public DNS answers.
// No request is sent to the synthetic callback or launch host.
func oauthTestDNS(t *testing.T) string {
	t.Helper()
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, e := conn.ReadFrom(buf)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: q.Questions}
			for _, question := range q.Questions {
				if question.Type == dnsmessage.TypeA {
					answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}})
				}
			}
			b, e := answer.Pack()
			if e == nil {
				_, _ = conn.WriteTo(b, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}
