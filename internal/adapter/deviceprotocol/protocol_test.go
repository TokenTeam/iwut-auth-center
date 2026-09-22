package deviceprotocol

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"iwut-auth-center/internal/authentication/domain"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestAcceptedProtocolVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/auth-device-session-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		DeviceKey map[string]string `json:"deviceKey"`
		Proofs    []struct {
			Name, Purpose, ServiceID, ApplicationID, OperationID, LocatorKind string
			Challenge                                                         string `json:"challenge_hex"`
			ExpiresAt                                                         int64  `json:"expiresAtUnixMs"`
			LocatorValue                                                      string `json:"locatorValue_hex"`
			AssociationDigest                                                 string `json:"associationDigest_hex"`
			Payload                                                           string `json:"signingPayload_hex"`
			Signature                                                         string `json:"signature_der_hex"`
			DoubleHash                                                        string `json:"doubleHash_signature_der_hex"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	protocol, err := New("iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	key := decodeHex(t, fixture.DeviceKey["publicKey65_hex"])
	fingerprint, err := protocol.Fingerprint(key)
	if err != nil || !bytes.Equal(fingerprint, decodeHex(t, fixture.DeviceKey["fingerprint_hex"])) {
		t.Fatal("fingerprint vector mismatch", err)
	}
	for _, vector := range fixture.Proofs {
		t.Run(vector.Name, func(t *testing.T) {
			op := domain.Operation{OperationID: vector.OperationID, Purpose: vector.Purpose, ServiceID: vector.ServiceID, ApplicationID: vector.ApplicationID, ProtocolVersion: domain.ProtocolVersion, Challenge: decodeHex(t, vector.Challenge), ExpiresAt: time.UnixMilli(vector.ExpiresAt), LocatorKind: vector.LocatorKind, LocatorValue: decodeHex(t, vector.LocatorValue)}
			payload, err := protocol.SigningPayload(op, decodeHex(t, vector.AssociationDigest))
			if err != nil || !bytes.Equal(payload, decodeHex(t, vector.Payload)) {
				t.Fatal("payload vector mismatch", err)
			}
			sig := decodeHex(t, vector.Signature)
			if !protocol.Verify(key, payload, sig) {
				t.Fatal("valid vector rejected")
			}
			if protocol.Verify(key, payload, decodeHex(t, vector.DoubleHash)) {
				t.Fatal("double hash accepted")
			}
			if protocol.Verify(key, payload, append(bytes.Clone(sig), 0)) {
				t.Fatal("DER trailing byte accepted")
			}
			var rs struct{ R, S *big.Int }
			if _, err := asn1.Unmarshal(sig, &rs); err != nil {
				t.Fatal(err)
			}
			rs.S.Sub(elliptic.P256().Params().N, rs.S)
			opposite, err := asn1.Marshal(rs)
			if err != nil || !protocol.Verify(key, payload, opposite) {
				t.Fatal("valid complementary S rejected", err)
			}
			for _, field := range []int{2, 3, 5, 9} {
				fields, err := ParseFrame(payload, 11)
				if err != nil {
					t.Fatal(err)
				}
				fields[field][0] ^= 1
				if protocol.Verify(key, Frame(fields...), sig) {
					t.Fatalf("changed field %d accepted", field)
				}
			}
			if _, err := ParseFrame(append(bytes.Clone(payload), 0), 11); err == nil {
				t.Fatal("payload trailing byte accepted")
			}
			if _, err := ParseFrame(payload[:len(payload)-1], 11); err == nil {
				t.Fatal("truncated payload accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, key[1:], append([]byte{2}, key[1:33]...), append([]byte{4}, make([]byte, 64)...), append(bytes.Clone(key), 0)} {
		if protocol.ValidatePublicKey(bad) == nil {
			t.Fatal("malformed public key accepted")
		}
	}
}

func TestTokenCanonicalEncoding(t *testing.T) {
	p, _ := New("test")
	token, digest, err := p.NewSessionToken()
	if err != nil || len(token) != 43 || len(digest) != 32 {
		t.Fatal(err)
	}
	if got, err := p.TokenDigest(token); err != nil || !bytes.Equal(got, digest) {
		t.Fatal("token roundtrip", err)
	}
	for _, bad := range []string{"", token + "=", token + " ", " " + token, strings.Repeat("/", 43), strings.Repeat("A", 42) + "B", strings.Repeat("+", 43)} {
		if _, err := p.TokenDigest(bad); err == nil {
			t.Fatalf("noncanonical token accepted: %q", bad)
		}
	}
	zeroDigest := sha256.Sum256(make([]byte, 32))
	if got, err := p.TokenDigest(strings.Repeat("A", 43)); err != nil || !bytes.Equal(got, zeroDigest[:]) {
		t.Fatal("hash must cover raw 32 bytes", err)
	}
}

func TestLimiterBoundsAndUnknownOperations(t *testing.T) {
	l, err := NewLimiter(RateLimits{BeginGlobal: 20, CompleteGlobal: 3, BeginSource: 2, CompleteLocator: 2, MaxBuckets: 2})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(120, 0)
	if !l.AllowBegin("a", now) || !l.AllowBegin("a", now) || l.AllowBegin("a", now) {
		t.Fatal("source limit")
	}
	if !l.AllowBegin("b", now) || l.AllowBegin("c", now) || len(l.buckets) != 2 {
		t.Fatal("bounded source table")
	}
	if !l.AllowBegin("c", now.Add(time.Minute)) {
		t.Fatal("expired bucket not reclaimed")
	}
	for range 3 {
		if !l.AllowComplete("", now) {
			t.Fatal("global capacity")
		}
	}
	if l.AllowComplete("new-unknown", now) {
		t.Fatal("unknown operation bypassed global limit")
	}
	if !l.AllowLocator("credential:a", now.Add(2*time.Minute)) || !l.AllowLocator("credential:a", now.Add(2*time.Minute)) || l.AllowLocator("credential:a", now.Add(2*time.Minute)) {
		t.Fatal("locator limit")
	}
}
