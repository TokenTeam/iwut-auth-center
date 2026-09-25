// Package smtpmail sends a single fixed-purpose message over verified TLS.
package smtpmail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	d "iwut-auth-center/internal/emailbinding/domain"
	login "iwut-auth-center/internal/emaillogin/domain"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address, From, TLSMode, Username, Password string
	Roots                                      *x509.CertPool
	Timeout                                    time.Duration
}
type Sender struct {
	c    Config
	host string
}

var errDelivery = errors.New("email delivery unavailable")

func New(c Config) (*Sender, error) {
	host, port, e := net.SplitHostPort(c.Address)
	portNumber, portErr := strconv.Atoi(port)
	from, e2 := d.NormalizeEmail(c.From)
	if e != nil || host == "" || strings.ContainsAny(host, " \t\r\n/\\") || portErr != nil || portNumber < 1 || portNumber > 65535 || e2 != nil || from != c.From || c.Timeout <= 0 || (c.Username == "") != (c.Password == "") || (c.TLSMode != "implicit_tls" && c.TLSMode != "starttls") {
		return nil, errDelivery
	}
	return &Sender{c, host}, nil
}
func (s *Sender) Send(ctx context.Context, to, purpose, code string, expires time.Time) error {
	address, e := d.NormalizeEmail(to)
	if e != nil || address != to || !d.ValidCode(code) || (purpose != d.RegistrationPurpose && purpose != d.BindingPurpose && purpose != login.Purpose) {
		return errDelivery
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.Timeout)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", s.c.Address)
	if e != nil {
		return errDelivery
	}
	defer conn.Close()
	rawConnection := conn
	stop := context.AfterFunc(ctx, func() { rawConnection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return errDelivery
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.host, RootCAs: s.c.Roots}
	if s.c.TLSMode == "implicit_tls" {
		secure := tls.Client(conn, tc)
		if secure.HandshakeContext(ctx) != nil {
			return errDelivery
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, s.host)
	if e != nil {
		return errDelivery
	}
	defer client.Close()
	if s.c.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errDelivery
		}
		if client.StartTLS(tc) != nil {
			return errDelivery
		}
	}
	if s.c.Username != "" {
		if client.Auth(smtp.PlainAuth("", s.c.Username, s.c.Password, s.host)) != nil {
			return errDelivery
		}
	}
	if client.Mail(s.c.From) != nil || client.Rcpt(to) != nil {
		return errDelivery
	}
	writer, e := client.Data()
	if e != nil {
		return errDelivery
	}
	action := "set your email"
	if purpose == d.RegistrationPurpose {
		action = "register a new account"
	}
	if purpose == login.Purpose {
		action = "sign in and authorize this device"
	}
	// All dynamic headers are validated addresses; code and purpose never enter a header.
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: iWUT email verification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nYou requested to %s.\r\nVerification code: %s\r\nExpires at: %s\r\nIf you did not request this, ignore this message.\r\n", s.c.From, to, action, code, expires.UTC().Format(time.RFC3339))
	if _, e = strings.NewReader(body).WriteTo(writer); e != nil {
		return errDelivery
	}
	if writer.Close() != nil {
		return errDelivery
	}
	if client.Quit() != nil {
		return errDelivery
	}
	return nil
}
