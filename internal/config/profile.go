package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// ProfileConfig retains raw deployment data; catalog adapters validate domain rules.
type ProfileConfig struct {
	JSON []byte
}

func LoadProfileConfig() (ProfileConfig, error) {
	return ParseProfileConfig(os.LookupEnv)
}
func ParseProfileConfig(lookup LookupEnv) (ProfileConfig, error) {
	path, _ := lookup("AUTH_PROFILE_CATALOG_FILE")
	if strings.TrimSpace(path) == "" {
		return ProfileConfig{}, errors.New("AUTH_PROFILE_CATALOG_FILE is required")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return ProfileConfig{}, errors.New("cannot read profile catalog")
	}
	return ProfileConfig{JSON: data}, nil
}

type UserIdentityConfig struct {
	Issuer            string
	PublicKeyPEMByKID map[string][]byte
	MaxTTL            time.Duration
	ClockSkew         time.Duration
}

func LoadUserIdentityConfig() (UserIdentityConfig, error) {
	return ParseUserIdentityConfig(os.LookupEnv)
}
func ParseUserIdentityConfig(lookup LookupEnv) (UserIdentityConfig, error) {
	issuer, _ := lookup("AUTH_USER_IDENTITY_ISSUER")
	c := UserIdentityConfig{Issuer: issuer, MaxTTL: 5 * time.Minute, ClockSkew: 30 * time.Second, PublicKeyPEMByKID: map[string][]byte{}}
	if strings.TrimSpace(c.Issuer) == "" {
		return c, errors.New("AUTH_USER_IDENTITY_ISSUER is required")
	}
	paths := map[string]string{}
	rawKeys, _ := lookup("AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON")
	dec := json.NewDecoder(strings.NewReader(rawKeys))
	opening, e := dec.Token()
	if e != nil || opening != json.Delim('{') {
		return c, errors.New("AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON must map kid to PEM file")
	}
	for dec.More() {
		token, e := dec.Token()
		if e != nil {
			return c, errors.New("invalid user key configuration")
		}
		kid := token.(string)
		if _, exists := paths[kid]; exists {
			return c, errors.New("duplicate user identity kid")
		}
		var path string
		if dec.Decode(&path) != nil {
			return c, errors.New("invalid user key path")
		}
		paths[kid] = path
	}
	if _, e = dec.Token(); e != nil || len(paths) == 0 {
		return c, errors.New("invalid user key configuration")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, errors.New("invalid user key configuration")
	}
	for kid, path := range paths {
		if strings.TrimSpace(kid) == "" {
			return c, errors.New("empty user identity kid")
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return c, errors.New("cannot read user identity public key")
		}
		c.PublicKeyPEMByKID[kid] = data
	}
	for _, item := range []struct {
		name   string
		target *time.Duration
	}{{"AUTH_USER_IDENTITY_MAX_TTL", &c.MaxTTL}, {"AUTH_USER_IDENTITY_CLOCK_SKEW", &c.ClockSkew}} {
		if raw, ok := lookup(item.name); ok {
			d, e := time.ParseDuration(raw)
			if e != nil {
				return c, errors.New("invalid user identity duration")
			}
			*item.target = d
		}
	}
	if c.MaxTTL <= 0 || c.ClockSkew < 0 {
		return c, errors.New("invalid user identity timing")
	}
	return c, nil
}
