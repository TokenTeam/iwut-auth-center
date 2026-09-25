package smtpmail

import (
	"context"
	d "iwut-auth-center/internal/emailbinding/domain"
	login "iwut-auth-center/internal/emaillogin/domain"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"strings"
	"testing"
	"time"
)

func TestProductionSMTP(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls", "reject", "timeout", "lost_ack"} {
		t.Run(mode, func(t *testing.T) {
			capture := smtpcapture.New(t, mode)
			tlsMode := "implicit_tls"
			if mode == "starttls" {
				tlsMode = mode
			}
			sender, e := New(Config{Address: capture.Address, From: "auth@example.test", TLSMode: tlsMode, Roots: capture.Roots, Timeout: 300 * time.Millisecond})
			if e != nil {
				t.Fatal(e)
			}
			e = sender.Send(context.Background(), "a@example.test", d.RegistrationPurpose, "00001234", time.Now().Add(time.Minute))
			if mode == "implicit_tls" || mode == "starttls" {
				if e != nil {
					t.Fatal(e)
				}
				m := capture.Next(t)
				if !strings.Contains(m.Body, "00001234") || strings.Contains(m.Body, "association") {
					t.Fatal("message template")
				}
			} else if e == nil {
				t.Fatal("failure reported successful")
			}
			if mode == "lost_ack" {
				capture.Next(t)
			}
		})
	}
}
func TestTLSCertificateValidationAndHeaderInjection(t *testing.T) {
	capture := smtpcapture.New(t, "implicit_tls")
	sender, e := New(Config{Address: capture.Address, From: "auth@example.test", TLSMode: "implicit_tls", Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if sender.Send(context.Background(), "a@example.test", d.BindingPurpose, "00001234", time.Now()) == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if sender.Send(context.Background(), "a@example.test\r\nBcc: b@example.test", d.BindingPurpose, "00001234", time.Now()) == nil {
		t.Fatal("header injection accepted")
	}
}

func TestEmailLoginSMTPPurposeAndFailure(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls", "reject", "lost_ack"} {
		t.Run(mode, func(t *testing.T) {
			capture := smtpcapture.New(t, mode)
			tlsMode := "implicit_tls"
			if mode == "starttls" {
				tlsMode = mode
			}
			sender, e := New(Config{Address: capture.Address, From: "auth@example.test", TLSMode: tlsMode, Roots: capture.Roots, Timeout: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			e = sender.Send(t.Context(), "unknown@example.test", login.Purpose, "00005678", time.Now().Add(time.Minute))
			if mode == "reject" || mode == "lost_ack" {
				if e == nil {
					t.Fatal("uncertain delivery successful")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			message := capture.Next(t)
			if !strings.Contains(message.Body, "sign in and authorize this device") || strings.Contains(message.Body, "register a new account") || strings.Contains(message.Body, "account exists") {
				t.Fatal("login template")
			}
		})
	}
}
