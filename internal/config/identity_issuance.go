package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const IdentityIssuanceEnabledEnv = "AUTH_IDENTITY_ISSUANCE_ENABLED"
const IdentityIssuePermission = "auth.identity.issue"

type IdentityIssuance struct {
	Kid, Issuer string
	PrivateKey  *rsa.PrivateKey
	TTL         time.Duration
}

func knownIdentityAudience(a string) bool { return a == "iwut-auth-center" || a == "iwut-app-center" }
func loadIdentityIssuance(lookup LookupEnv, users *UserEndpoints, callers []ServiceCallerRegistration) (*IdentityIssuance, error) {
	raw, found := lookup(IdentityIssuanceEnabledEnv)
	if !found {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: identity issuance enabled must be boolean", ErrInvalidConfiguration)
	}
	if !enabled {
		return nil, nil
	}
	if users == nil {
		return nil, fmt.Errorf("%w: identity issuance requires user endpoints", ErrInvalidConfiguration)
	}
	kid, _ := lookup("AUTH_USER_IDENTITY_SIGNING_KID")
	encoded, _ := lookup("AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64")
	invalid := func() (*IdentityIssuance, error) {
		return nil, fmt.Errorf("%w: invalid or mismatched identity signing configuration", ErrInvalidConfiguration)
	}
	if kid == "" || strings.TrimSpace(kid) != kid {
		return invalid()
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(data) != encoded {
		return invalid()
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return invalid()
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return invalid()
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return invalid()
	}
	ttl := 60 * time.Second
	if raw, found := lookup("AUTH_USER_IDENTITY_TTL"); found {
		ttl, err = time.ParseDuration(raw)
		if err != nil {
			return invalid()
		}
	}
	if ttl < time.Second || ttl > 300*time.Second || ttl%time.Second != 0 || ttl > users.UserIdentity.MaxTTL {
		return invalid()
	}
	public, err := identityPublicKey(users.UserIdentity.PublicKeyPEMByKID[kid])
	if err != nil || !public.Equal(&key.PublicKey) {
		return invalid()
	}
	for _, caller := range callers {
		for _, data := range caller.PublicKeyPEMByKID {
			other, err := identityPublicKey(data)
			if err != nil || other.Equal(&key.PublicKey) {
				return invalid()
			}
		}
	}
	return &IdentityIssuance{Kid: kid, Issuer: users.UserIdentity.Issuer, PrivateKey: key, TTL: ttl}, nil
}
func identityPublicKey(data []byte) (*rsa.PublicKey, error) {
	b, rest := pem.Decode(data)
	if b == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrInvalidConfiguration
	}
	if b.Type == "RSA PUBLIC KEY" {
		return x509.ParsePKCS1PublicKey(b.Bytes)
	}
	if b.Type != "PUBLIC KEY" {
		return nil, ErrInvalidConfiguration
	}
	p, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := p.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	return k, nil
}
func validateIdentityAudiences(permissions, audiences []string) error {
	has := false
	for _, p := range permissions {
		if p == IdentityIssuePermission {
			has = true
		}
	}
	if has != (len(audiences) > 0) {
		return fmt.Errorf("%w: identity audiences require issue permission and vice versa", ErrInvalidConfiguration)
	}
	unique, err := uniqueNonEmpty(audiences)
	if err != nil {
		return fmt.Errorf("%w: identity audiences invalid", ErrInvalidConfiguration)
	}
	for _, a := range unique {
		if !knownIdentityAudience(a) {
			return fmt.Errorf("%w: identity audience unknown", ErrInvalidConfiguration)
		}
	}
	return nil
}
