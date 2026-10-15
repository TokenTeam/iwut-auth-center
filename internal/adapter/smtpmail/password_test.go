package smtpmail

import (
	"github.com/google/uuid"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"strings"
	"testing"
	"time"
)

func TestPasswordNotificationSMTP(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls", "lost_ack", "reject"} {
		t.Run(mode, func(t *testing.T) {
			capture := smtpcapture.New(t, mode)
			tlsMode := "implicit_tls"
			if mode == "starttls" {
				tlsMode = mode
			}
			sender, err := New(Config{Address: capture.Address, From: "auth@example.test", TLSMode: tlsMode, Roots: capture.Roots, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			event := uuid.NewString()
			err = sender.SendPasswordNotification(t.Context(), "user@example.test", "PASSWORD_RESET", event, time.Now())
			if mode == "reject" || mode == "lost_ack" {
				if err == nil {
					t.Fatal("uncertain delivery claimed success")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mail := capture.Next(t)
			if !strings.Contains(mail.Body, "Message-ID: <"+event+"@iwut-password-notifications>") || strings.Contains(mail.Body, "Verification code") || strings.Contains(mail.Body, "Session") {
				t.Fatal("unsafe notification template")
			}
			if sender.SendPasswordNotification(t.Context(), "user@example.test", "PASSWORD_RESET", event+"\r\nBcc: evil@example.test", time.Now()) == nil {
				t.Fatal("notification header injection")
			}
		})
	}
}
