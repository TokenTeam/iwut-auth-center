// Package smtpcapture provides an isolated loopback TLS SMTP receiver for tests.
package smtpcapture

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type Message struct{ Recipient, Body string }
type Server struct {
	Address  string
	CAPEM    []byte
	Roots    *x509.CertPool
	Messages chan Message
	listener net.Listener
	stop     chan struct{}
	wg       sync.WaitGroup
	tls      *tls.Config
	mode     string
}

// mode: implicit_tls, starttls, auth_login, reject, timeout, or lost_ack.
func New(t testing.TB, mode string) *Server {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP capture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemCert)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := &Server{Address: ln.Addr().String(), CAPEM: pemCert, Roots: roots, Messages: make(chan Message, 100), listener: ln, stop: make(chan struct{}), tls: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, mode: mode}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			s.wg.Add(1)
			go func() { defer s.wg.Done(); s.serve(c) }()
		}
	}()
	t.Cleanup(func() { close(s.stop); ln.Close(); s.wg.Wait() })
	return s
}
func (s *Server) serve(raw net.Conn) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	var conn net.Conn = raw
	if s.mode != "starttls" {
		secure := tls.Server(raw, s.tls)
		if secure.Handshake() != nil {
			return
		}
		conn = secure
	}
	if s.mode == "timeout" {
		select {
		case <-s.stop:
		case <-time.After(2 * time.Second):
		}
		return
	}
	reader := bufio.NewReader(conn)
	send := func(line string) { fmt.Fprint(conn, line+"\r\n") }
	send("220 capture ESMTP")
	recipient := ""
	authStep := 0
	authenticated := false
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			if s.mode == "starttls" {
				send("250-capture\r\n250 STARTTLS")
			} else if s.mode == "auth_login" {
				send("250-capture\r\n250 AUTH LOGIN")
			} else {
				send("250 capture")
			}
		case line == "STARTTLS":
			send("220 begin TLS")
			secure := tls.Server(raw, s.tls)
			if secure.Handshake() != nil {
				return
			}
			conn = secure
			reader = bufio.NewReader(conn)
		case s.mode == "auth_login" && line == "AUTH LOGIN":
			authStep = 1
			send("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
		case s.mode == "auth_login" && authStep == 1:
			value, err := base64.StdEncoding.DecodeString(line)
			if err != nil || string(value) != "user" {
				send("535 authentication failed")
				return
			}
			authStep = 2
			send("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
		case s.mode == "auth_login" && authStep == 2:
			value, err := base64.StdEncoding.DecodeString(line)
			if err != nil || string(value) != "password" {
				send("535 authentication failed")
				return
			}
			authStep = 0
			authenticated = true
			send("235 authenticated")
		case strings.HasPrefix(line, "MAIL FROM:"):
			if s.mode == "auth_login" && !authenticated {
				send("530 authentication required")
			} else {
				send("250 OK")
			}
		case strings.HasPrefix(line, "RCPT TO:"):
			recipient = strings.TrimPrefix(line, "RCPT TO:")
			if s.mode == "reject" {
				send("550 rejected")
			} else {
				send("250 OK")
			}
		case line == "DATA":
			send("354 data")
			var body strings.Builder
			for {
				part, e := reader.ReadString('\n')
				if e != nil {
					return
				}
				if part == ".\r\n" {
					break
				}
				body.WriteString(part)
			}
			s.Messages <- Message{recipient, body.String()}
			if s.mode == "lost_ack" {
				return
			}
			send("250 accepted")
		case line == "QUIT":
			send("221 bye")
			return
		default:
			send("250 OK")
		}
	}
}
func (s *Server) Next(t testing.TB) Message {
	t.Helper()
	select {
	case m := <-s.Messages:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP message not received")
		return Message{}
	}
}
