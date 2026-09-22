package associationcrypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"iwut-auth-center/internal/registration/domain"
	"os"
	"testing"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestAuthoritativeStorageVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/auth-device-session-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		AssociationStorage struct {
			Lookup     string `json:"lookupKeySecret_hex"`
			Encrypt    string `json:"encryptionKeySecret_hex"`
			LookupKey  string `json:"lookupKey_hex"`
			Encryption []struct {
				Kind, Identifier, KeyVersion string
				Nonce                        string `json:"nonce_hex"`
				AAD                          string `json:"aad_hex"`
				Plaintext                    string `json:"plaintext_hex"`
				Ciphertext                   string `json:"ciphertextAndTag_hex"`
			}
		} `json:"associationStorage"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.AssociationStorage.Encryption {
		t.Run(v.Kind, func(t *testing.T) {
			c, err := New(Key{v.KeyVersion, hexBytes(t, f.AssociationStorage.Encrypt), hexBytes(t, f.AssociationStorage.Lookup)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c.random = bytes.NewReader(hexBytes(t, v.Nonce))
			s, err := c.Seal(v.Kind, v.Identifier, domain.AssociationScheme, hexBytes(t, v.Plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.Ciphertext, hexBytes(t, v.Ciphertext)) || !bytes.Equal(s.LookupKey, hexBytes(t, f.AssociationStorage.LookupKey)) {
				t.Fatal("storage vector mismatch")
			}
			a, err := aad(v.Kind, v.Identifier, domain.AssociationScheme, v.KeyVersion)
			if err != nil || !bytes.Equal(a, hexBytes(t, v.AAD)) {
				t.Fatal("AAD mismatch")
			}
			got, err := c.Open(v.Kind, v.Identifier, s)
			if err != nil || !bytes.Equal(got, hexBytes(t, v.Plaintext)) {
				t.Fatal("open failed")
			}
			for _, field := range []string{"nonce", "ciphertext", "lookup", "scheme", "version", "id", "kind", "wrong-encryption-key", "wrong-lookup-key"} {
				t.Run(field, func(t *testing.T) {
					tampered := domain.SealedAssociation{SchemeVersion: s.SchemeVersion, KeyVersion: s.KeyVersion, Nonce: append([]byte(nil), s.Nonce...), Ciphertext: append([]byte(nil), s.Ciphertext...), LookupKey: append([]byte(nil), s.LookupKey...)}
					kind, id := v.Kind, v.Identifier
					reader := c
					switch field {
					case "nonce":
						tampered.Nonce[0] ^= 1
					case "ciphertext":
						tampered.Ciphertext[0] ^= 1
					case "lookup":
						tampered.LookupKey[0] ^= 1
					case "scheme":
						tampered.SchemeVersion = "wrong"
					case "version":
						tampered.KeyVersion = "unknown"
					case "id":
						id = "33333333-3333-4333-8333-333333333333"
					case "kind":
						if kind == "group" {
							kind = "operation"
						} else {
							kind = "group"
						}
					case "wrong-encryption-key", "wrong-lookup-key":
						k := copyKey(c.current)
						if field == "wrong-encryption-key" {
							k.Encrypt[0] ^= 1
						} else {
							k.Lookup[0] ^= 1
						}
						reader, _ = New(k, nil)
					}
					if plain, err := reader.Open(kind, id, tampered); err == nil || plain != nil {
						t.Fatal("unauthenticated plaintext released")
					}
				})
			}
		})
	}
}

func TestIndependentRandomSealingAndKeyValidation(t *testing.T) {
	k := Key{"v1", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
	c, err := New(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "33333333-3333-4333-8333-333333333333"
	a, _ := c.Seal("group", id, domain.AssociationScheme, bytes.Repeat([]byte{3}, 32))
	b, _ := c.Seal("group", id, domain.AssociationScheme, bytes.Repeat([]byte{3}, 32))
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("nonce reused")
	}
	for _, bad := range []Key{{"", k.Encrypt, k.Lookup}, {"bad version", k.Encrypt, k.Lookup}, {"v1", k.Encrypt, k.Encrypt}, {"v1", k.Encrypt[:31], k.Lookup}} {
		if _, err := New(bad, nil); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, err := New(k, &k); err == nil {
		t.Fatal("same generation accepted")
	}
}
