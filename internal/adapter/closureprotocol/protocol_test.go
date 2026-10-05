package closureprotocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	closure "iwut-auth-center/internal/accountclosure/domain"
	"iwut-auth-center/internal/adapter/deviceprotocol"
)

func TestPublicClosureVectors(t *testing.T) {
	var vectors struct {
		DeviceKey struct {
			PublicKey string `json:"publicKey65_hex"`
		}
		Proofs []struct {
			Name, ServiceID, ApplicationID, OperationID, LocatorKind, PolicyVersion string
			Challenge                                                               string `json:"challenge_hex"`
			LocatorValue                                                            string `json:"locatorValue_hex"`
			ExpiresAt                                                               int64  `json:"expiresAtUnixMs"`
			Payload                                                                 string `json:"signingPayload_hex"`
			Signature                                                               string `json:"signature_der_hex"`
			Equivalent                                                              string `json:"equivalentS_signature_der_hex"`
		}
		NegativeProofs []struct {
			Name, Kind string
			Payload    string `json:"payload_hex"`
			Signature  string `json:"signature_der_hex"`
		}
		Tokens []struct {
			Purpose closure.TokenPurpose
			Token   string
			Digest  string `json:"tokenDigest_hex"`
		}
		InvalidTokens []string
	}
	data, err := os.ReadFile("testdata/auth-account-closure-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		t.Helper()
		v, e := hex.DecodeString(value)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	p, err := New("iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	key := decode(vectors.DeviceKey.PublicKey)
	for _, v := range vectors.Proofs {
		t.Run(v.Name, func(t *testing.T) {
			proof := closure.Proof{ServiceID: v.ServiceID, ApplicationID: v.ApplicationID, OperationID: v.OperationID,
				Challenge: decode(v.Challenge), ExpiresAt: time.UnixMilli(v.ExpiresAt), LocatorKind: v.LocatorKind,
				LocatorValue: decode(v.LocatorValue), PolicyVersion: v.PolicyVersion}
			payload, err := p.SigningPayload(proof)
			if err != nil || !bytes.Equal(payload, decode(v.Payload)) {
				t.Fatalf("payload mismatch: %v", err)
			}
			if !p.Verify(key, payload, decode(v.Signature)) || !p.Verify(key, payload, decode(v.Equivalent)) {
				t.Fatal("valid signature rejected")
			}
			proof.PolicyVersion = "future-policy"
			if _, err := p.SigningPayload(proof); err == nil {
				t.Fatal("unknown policy accepted")
			}
		})
	}
	for _, v := range vectors.NegativeProofs {
		t.Run(v.Name, func(t *testing.T) {
			payload := decode(v.Payload)
			switch v.Kind {
			case "SIGNATURE":
				if p.Verify(key, payload, decode(v.Signature)) {
					t.Fatal("invalid signature accepted")
				}
			case "FRAME":
				if _, err := deviceprotocol.ParseFrame(payload, 10); err == nil {
					t.Fatal("malformed frame accepted")
				}
			case "CONTEXT":
				// Other protocol proofs remain cryptographically valid, but can
				// never equal the closure payload reconstructed from its operation.
				if bytes.Equal(payload, decode(vectors.Proofs[0].Payload)) {
					t.Fatal("cross-purpose collision")
				}
			default:
				t.Fatal("unknown negative vector kind")
			}
		})
	}
	for _, v := range vectors.Tokens {
		digest, err := p.TokenDigest(v.Purpose, v.Token)
		if err != nil || !bytes.Equal(digest, decode(v.Digest)) {
			t.Fatalf("token digest mismatch: %v", err)
		}
		for _, bad := range vectors.InvalidTokens {
			if _, err := p.TokenDigest(v.Purpose, bad); err == nil {
				t.Fatal("noncanonical token accepted")
			}
		}
		generated, want, err := p.NewToken(v.Purpose)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := p.TokenDigest(v.Purpose, generated)
		if err != nil || !bytes.Equal(want, actual) {
			t.Fatal("token generation mismatch")
		}
	}
	if _, _, err := p.NewToken("session"); err == nil {
		t.Fatal("wrong token purpose accepted")
	}
}
