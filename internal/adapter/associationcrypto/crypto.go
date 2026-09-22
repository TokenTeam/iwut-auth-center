// Package associationcrypto implements the versioned association encoding.
package associationcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"regexp"

	"github.com/google/uuid"
	"iwut-auth-center/internal/registration/domain"
)

var ErrInvalid = errors.New("association cryptographic validation failed")
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type Key struct {
	Version         string
	Encrypt, Lookup []byte
}

// Crypto retains only the current and optional immediately previous key group.
// Do not format this value or its keys into diagnostics.
type Crypto struct {
	current  Key
	previous *Key
	random   io.Reader
}

func New(current Key, previous *Key) (*Crypto, error) {
	valid := func(k Key) bool {
		return versionPattern.MatchString(k.Version) && len(k.Encrypt) == 32 && len(k.Lookup) == 32 && !hmac.Equal(k.Encrypt, k.Lookup)
	}
	if !valid(current) {
		return nil, ErrInvalid
	}
	current = copyKey(current)
	if previous != nil {
		if !valid(*previous) || previous.Version == current.Version || hmac.Equal(previous.Encrypt, current.Encrypt) || hmac.Equal(previous.Lookup, current.Lookup) || hmac.Equal(previous.Encrypt, current.Lookup) || hmac.Equal(previous.Lookup, current.Encrypt) {
			return nil, ErrInvalid
		}
		p := copyKey(*previous)
		previous = &p
	}
	return &Crypto{current: current, previous: previous, random: rand.Reader}, nil
}

func copyKey(k Key) Key {
	return Key{k.Version, append([]byte(nil), k.Encrypt...), append([]byte(nil), k.Lookup...)}
}
func (c *Crypto) CurrentVersion() string { return c.current.Version }
func (c *Crypto) PreviousVersion() string {
	if c.previous == nil {
		return ""
	}
	return c.previous.Version
}

func frame(parts ...[]byte) []byte {
	var result []byte
	for _, p := range parts {
		result = binary.BigEndian.AppendUint32(result, uint32(len(p)))
		result = append(result, p...)
	}
	return result
}

func (c *Crypto) key(version string) (Key, error) {
	if version == c.current.Version {
		return c.current, nil
	}
	if c.previous != nil && version == c.previous.Version {
		return *c.previous, nil
	}
	return Key{}, ErrInvalid
}

func lookup(k Key, scheme string, token []byte) []byte {
	m := hmac.New(sha256.New, k.Lookup)
	m.Write(frame([]byte("iwut-association-lookup-v1"), []byte(scheme), token))
	return m.Sum(nil)
}

func Digest(scheme string, token []byte) ([]byte, error) {
	if scheme != domain.AssociationScheme || len(token) != 32 {
		return nil, ErrInvalid
	}
	h := sha256.Sum256(frame([]byte(scheme), token))
	return h[:], nil
}

func aad(kind, id, scheme, version string) ([]byte, error) {
	u, err := uuid.Parse(id)
	if err != nil || u.Version() != 4 || u.Variant() != uuid.RFC4122 || u.String() != id || (kind != "group" && kind != "operation") || scheme != domain.AssociationScheme {
		return nil, ErrInvalid
	}
	return frame([]byte("iwut-association-"+kind+"-v1"), []byte(id), []byte(scheme), []byte(version)), nil
}

// Seal always encrypts with a new random nonce and the current key group.
func (c *Crypto) Seal(kind, id, scheme string, token []byte) (domain.SealedAssociation, error) {
	if len(token) != 32 {
		return domain.SealedAssociation{}, ErrInvalid
	}
	a, err := aad(kind, id, scheme, c.current.Version)
	if err != nil {
		return domain.SealedAssociation{}, err
	}
	block, err := aes.NewCipher(c.current.Encrypt)
	if err != nil {
		return domain.SealedAssociation{}, ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return domain.SealedAssociation{}, ErrInvalid
	}
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(c.random, nonce); err != nil {
		return domain.SealedAssociation{}, ErrInvalid
	}
	return domain.SealedAssociation{SchemeVersion: scheme, KeyVersion: c.current.Version, LookupKey: lookup(c.current, scheme, token), Nonce: nonce, Ciphertext: gcm.Seal(nil, nonce, token, a)}, nil
}

// Open authenticates both ciphertext and lookup key before exposing plaintext.
func (c *Crypto) Open(kind, id string, s domain.SealedAssociation) ([]byte, error) {
	k, err := c.key(s.KeyVersion)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(s.Nonce) != 12 || len(s.Ciphertext) != 48 || len(s.LookupKey) != 32 {
		return nil, ErrInvalid
	}
	a, err := aad(kind, id, s.SchemeVersion, s.KeyVersion)
	if err != nil {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(k.Encrypt)
	if err != nil {
		return nil, ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	plain, err := gcm.Open(nil, s.Nonce, s.Ciphertext, a)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(plain) != 32 || !hmac.Equal(lookup(k, s.SchemeVersion, plain), s.LookupKey) {
		clear(plain)
		return nil, ErrInvalid
	}
	return plain, nil
}

func (c *Crypto) AssociationDigest(scheme string, token []byte) ([]byte, error) {
	return Digest(scheme, token)
}
