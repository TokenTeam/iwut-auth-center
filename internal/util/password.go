package util

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2Params = Argon2Params{
	Memory:      65536,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

type PasswordUtil struct {
	sha256Util *Sha256Util
	params     Argon2Params
}

func NewPasswordUtil(sha256Util *Sha256Util) *PasswordUtil {
	return &PasswordUtil{
		sha256Util: sha256Util,
		params:     DefaultArgon2Params,
	}
}

// HashPassword hashes a plain-text password with Argon2id and returns a PHC-format string.
func (p *PasswordUtil) HashPassword(password string) (string, error) {
	salt := make([]byte, p.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password), salt,
		p.params.Iterations, p.params.Memory, p.params.Parallelism, p.params.KeyLength,
	)

	return encodePHC(p.params, salt, hash), nil
}

// VerifyPassword checks a plain-text password against a stored hash.
// Automatically detects Argon2id (PHC prefix) vs legacy SHA-256 format.
func (p *PasswordUtil) VerifyPassword(plainPassword, storedHash string) (bool, error) {
	if strings.HasPrefix(storedHash, "$argon2id$") {
		return p.verifyArgon2id(plainPassword, storedHash)
	}
	legacyHash := p.sha256Util.HashPassword(plainPassword)
	return subtle.ConstantTimeCompare([]byte(legacyHash), []byte(storedHash)) == 1, nil
}

// NeedsRehash returns true when the stored hash is not in Argon2id format
// (i.e. it is a legacy SHA-256 hash that should be upgraded).
func (p *PasswordUtil) NeedsRehash(storedHash string) bool {
	return !strings.HasPrefix(storedHash, "$argon2id$")
}

func (p *PasswordUtil) verifyArgon2id(plainPassword, encoded string) (bool, error) {
	params, salt, hash, err := decodePHC(encoded)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(plainPassword), salt,
		params.Iterations, params.Memory, params.Parallelism, params.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// encodePHC produces a PHC string: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
func encodePHC(params Argon2Params, salt, hash []byte) string {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism,
		b64Salt, b64Hash,
	)
}

// decodePHC parses a PHC-format Argon2id string back into its components.
func decodePHC(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return Argon2Params{}, nil, nil, fmt.Errorf("invalid argon2id hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("invalid argon2id version: %w", err)
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("unsupported argon2id version: %d", version)
	}

	var params Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("invalid argon2id params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("invalid argon2id salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("invalid argon2id hash: %w", err)
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
