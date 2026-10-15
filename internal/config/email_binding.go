package config

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	emaildomain "iwut-auth-center/internal/emailbinding/domain"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type EmailBinding struct {
	HMACKey                                                        []byte
	SMTPAddress, SMTPFrom, SMTPTLSMode, SMTPUsername, SMTPPassword string
	SMTPRoots                                                      *x509.CertPool
	SMTPTimeout                                                    time.Duration
	OwnerHourly, EmailHourly, SourceHourly, MaxBuckets             int
}

func loadEmailBinding(lookup LookupEnv, user *UserEndpoints) (*EmailBinding, error) {
	return loadEmailCapability(lookup, user, "AUTH_EMAIL_BINDING_ENABLED", "AUTH_EMAIL_BINDING_HMAC_KEY")
}
func loadEmailCapability(lookup LookupEnv, user *UserEndpoints, enabledKey, keyName string) (*EmailBinding, error) {
	raw, found := lookup(enabledKey)
	if !found {
		return nil, nil
	}
	enabled, e := strconv.ParseBool(raw)
	if e != nil {
		return nil, fmt.Errorf("%w: invalid email enabled flag", ErrInvalidConfiguration)
	}
	if !enabled {
		return nil, nil
	}
	if user == nil {
		return nil, fmt.Errorf("%w: email requires user endpoints", ErrInvalidConfiguration)
	}
	c := &EmailBinding{SMTPTimeout: 10 * time.Second, OwnerHourly: 5, EmailHourly: 5, SourceHourly: 20, MaxBuckets: 10000}
	raw, _ = lookup(keyName)
	c.HMACKey, e = base64.StdEncoding.Strict().DecodeString(raw)
	if e != nil || len(c.HMACKey) != 32 || base64.StdEncoding.EncodeToString(c.HMACKey) != raw {
		return nil, fmt.Errorf("%w: invalid email HMAC key", ErrInvalidConfiguration)
	}
	c.SMTPAddress, _ = lookup("AUTH_SMTP_ADDR")
	c.SMTPFrom, _ = lookup("AUTH_SMTP_FROM")
	c.SMTPTLSMode, _ = lookup("AUTH_SMTP_TLS_MODE")
	c.SMTPUsername, _ = lookup("AUTH_SMTP_USERNAME")
	c.SMTPPassword, _ = lookup("AUTH_SMTP_PASSWORD")
	host, port, e := net.SplitHostPort(c.SMTPAddress)
	portNumber, portErr := strconv.Atoi(port)
	sender, senderErr := emaildomain.NormalizeEmail(c.SMTPFrom)
	if e != nil || host == "" || strings.ContainsAny(host, " \t\r\n/\\") || portErr != nil || portNumber < 1 || portNumber > 65535 || senderErr != nil || sender != c.SMTPFrom || (c.SMTPTLSMode != "implicit_tls" && c.SMTPTLSMode != "starttls") || (c.SMTPUsername == "") != (c.SMTPPassword == "") || c.SMTPFrom == "" {
		return nil, fmt.Errorf("%w: invalid SMTP configuration", ErrInvalidConfiguration)
	}
	if raw, ok := lookup("AUTH_SMTP_TIMEOUT"); ok {
		c.SMTPTimeout, e = time.ParseDuration(raw)
		if e != nil || c.SMTPTimeout <= 0 {
			return nil, fmt.Errorf("%w: invalid SMTP timeout", ErrInvalidConfiguration)
		}
	}
	if path, ok := lookup("AUTH_SMTP_CA_FILE"); ok {
		pem, e := os.ReadFile(path)
		if e != nil {
			return nil, fmt.Errorf("%w: SMTP CA unavailable", ErrInvalidConfiguration)
		}
		c.SMTPRoots = x509.NewCertPool()
		if !c.SMTPRoots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: invalid SMTP CA", ErrInvalidConfiguration)
		}
	}
	for key, dest := range map[string]*int{"AUTH_EMAIL_OWNER_HOURLY": &c.OwnerHourly, "AUTH_EMAIL_ADDRESS_HOURLY": &c.EmailHourly, "AUTH_EMAIL_SOURCE_HOURLY": &c.SourceHourly, "AUTH_EMAIL_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, ok := lookup(key); ok {
			*dest, e = strconv.Atoi(raw)
			if e != nil || *dest <= 0 || *dest > 1000000 {
				return nil, fmt.Errorf("%w: invalid email quota", ErrInvalidConfiguration)
			}
		}
	}
	return c, nil
}
