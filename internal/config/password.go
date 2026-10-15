package config

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"iwut-auth-center/internal/password/domain"
	"strconv"
)

type Password struct {
	OperationKey                                                      []byte
	BlocklistFile, BlocklistVersion, BlocklistSource, BlocklistSHA256 string
	Parameters                                                        domain.Parameters
}

func loadPassword(lookup LookupEnv, user *UserEndpoints, email *EmailBinding, login *EmailBinding) (*Password, error) {
	raw, exists := lookup("AUTH_PASSWORD_ENABLED")
	if !exists {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid password enabled flag", ErrInvalidConfiguration)
	}
	if !enabled {
		return nil, nil
	}
	if user == nil || email == nil {
		return nil, fmt.Errorf("%w: password/email-account endpoints require user and email delivery", ErrInvalidConfiguration)
	}
	p := &Password{Parameters: domain.DefaultParameters()}
	raw, _ = lookup("AUTH_PASSWORD_OPERATION_HMAC_KEY")
	p.OperationKey, err = base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(p.OperationKey) != 32 || base64.StdEncoding.EncodeToString(p.OperationKey) != raw || hmac.Equal(p.OperationKey, email.HMACKey) || (login != nil && hmac.Equal(p.OperationKey, login.HMACKey)) {
		return nil, fmt.Errorf("%w: invalid or reused password operation key", ErrInvalidConfiguration)
	}
	p.BlocklistFile, _ = lookup("AUTH_PASSWORD_BLOCKLIST_FILE")
	p.BlocklistVersion, _ = lookup("AUTH_PASSWORD_BLOCKLIST_VERSION")
	p.BlocklistSource, _ = lookup("AUTH_PASSWORD_BLOCKLIST_SOURCE")
	p.BlocklistSHA256, _ = lookup("AUTH_PASSWORD_BLOCKLIST_SHA256")
	digest, err := hex.DecodeString(p.BlocklistSHA256)
	if p.BlocklistFile == "" || p.BlocklistVersion == "" || len(p.BlocklistVersion) > 128 || p.BlocklistSource == "" || len(p.BlocklistSource) > 256 || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != p.BlocklistSHA256 {
		return nil, fmt.Errorf("%w: pinned password blocklist required", ErrInvalidConfiguration)
	}
	ready, _ := lookup("AUTH_PASSWORD_READINESS_CONFIRMED")
	if ready != "true" {
		return nil, fmt.Errorf("%w: password deployment readiness must be explicitly confirmed", ErrInvalidConfiguration)
	}
	for key, dst := range map[string]*uint32{"AUTH_PASSWORD_ARGON_MEMORY_KIB": &p.Parameters.MemoryKiB, "AUTH_PASSWORD_ARGON_ITERATIONS": &p.Parameters.Iterations} {
		if raw, ok := lookup(key); ok {
			n, err := strconv.ParseUint(raw, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid password work factor", ErrInvalidConfiguration)
			}
			*dst = uint32(n)
		}
	}
	if raw, ok := lookup("AUTH_PASSWORD_ARGON_PARALLELISM"); ok {
		n, err := strconv.ParseUint(raw, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid password parallelism", ErrInvalidConfiguration)
		}
		p.Parameters.Parallelism = uint8(n)
	}
	if !p.Parameters.Valid() {
		return nil, fmt.Errorf("%w: password work factor outside reviewed bounds", ErrInvalidConfiguration)
	}
	return p, nil
}
