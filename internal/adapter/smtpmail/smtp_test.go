package smtpmail

import (
	"context"
	d "iwut-auth-center/internal/emailbinding/domain"
	login "iwut-auth-center/internal/emaillogin/domain"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"net/smtp"
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

func TestSMTPAuthenticationNegotiation(t *testing.T) {
	plain, err := smtpAuthentication("smtp.example.test", "LOGIN PLAIN", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	mechanism, initial, err := plain.Start(&smtp.ServerInfo{Name: "smtp.example.test", TLS: true, Auth: []string{"LOGIN", "PLAIN"}})
	if err != nil || mechanism != "PLAIN" || len(initial) == 0 {
		t.Fatalf("PLAIN negotiation = %q, %x, %v", mechanism, initial, err)
	}

	selected, err := smtpAuthentication("smtp.example.test", "LOGIN XOAUTH2", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	auth, ok := selected.(*loginAuth)
	if !ok {
		t.Fatalf("LOGIN negotiation selected %T", selected)
	}
	mechanism, initial, err = auth.Start(&smtp.ServerInfo{Name: "smtp.example.test", TLS: true, Auth: []string{"LOGIN", "XOAUTH2"}})
	if err != nil || mechanism != "LOGIN" || initial != nil {
		t.Fatalf("LOGIN start = %q, %x, %v", mechanism, initial, err)
	}
	username, err := auth.Next([]byte("Username:"), true)
	if err != nil || string(username) != "user" {
		t.Fatalf("LOGIN username = %q, %v", username, err)
	}
	password, err := auth.Next([]byte("Password:"), true)
	if err != nil || string(password) != "password" {
		t.Fatalf("LOGIN password = %q, %v", password, err)
	}
	if final, err := auth.Next(nil, false); err != nil || final != nil {
		t.Fatalf("LOGIN completion = %x, %v", final, err)
	}

	if _, err := smtpAuthentication("smtp.example.test", "XOAUTH2", "user", "password"); err == nil {
		t.Fatal("unsupported authentication mechanism accepted")
	}
	insecure := &loginAuth{username: "user", password: "password"}
	if _, _, err := insecure.Start(&smtp.ServerInfo{Name: "smtp.example.test", Auth: []string{"LOGIN"}}); err == nil {
		t.Fatal("LOGIN credentials allowed without TLS")
	}
}

func TestSMTPLoginDelivery(t *testing.T) {
	capture := smtpcapture.New(t, "auth_login")
	sender, err := New(Config{Address: capture.Address, From: "auth@example.test", TLSMode: "implicit_tls", Username: "user", Password: "password", Roots: capture.Roots, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(t.Context(), "recipient@example.test", d.BindingPurpose, "00001234", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	message := capture.Next(t)
	if message.Recipient != "<recipient@example.test>" || !strings.Contains(message.Body, "00001234") {
		t.Fatalf("authenticated message = %#v", message)
	}
}
