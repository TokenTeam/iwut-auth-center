package credentialprotocol

import (
	"encoding/hex"
	"encoding/json"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"os"
	"testing"
	"time"
)

func TestPublicCredentialVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/auth-credential-management-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	type item struct {
		Name, ServiceID, OperationID, SessionID, CallerCredentialID, TargetCredentialID string
		Challenge                                                                       string `json:"challenge_hex"`
		ExpiresAtUnixMs                                                                 int64
		Payload                                                                         string `json:"signingPayload_hex"`
		Signature                                                                       string `json:"signature_der_hex"`
		Alternate                                                                       string `json:"alternateS_signature_der_hex"`
	}
	var vectors struct {
		PublicKey          string `json:"publicKey_hex"`
		Positive, Negative []item
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p, _ := New("iwut-auth-center:test")
	key := decode(vectors.PublicKey)
	for _, v := range vectors.Positive {
		op := d.Operation{OperationID: v.OperationID, SessionID: v.SessionID, CallerCredentialID: v.CallerCredentialID, TargetCredentialID: v.TargetCredentialID, ServiceID: v.ServiceID, ApplicationID: "iwut-client", Purpose: d.Purpose, Challenge: decode(v.Challenge), ExpiresAt: time.UnixMilli(v.ExpiresAtUnixMs)}
		payload, err := p.SigningPayload(op)
		if err != nil || hex.EncodeToString(payload) != v.Payload {
			t.Fatal(v.Name, err)
		}
		for _, sig := range []string{v.Signature, v.Alternate} {
			if !p.ValidSignature(decode(sig)) || !p.Verify(key, payload, decode(sig)) {
				t.Fatal(v.Name)
			}
		}
	}
	for _, v := range vectors.Negative {
		if p.Verify(key, decode(v.Payload), decode(v.Signature)) {
			t.Fatal("negative accepted", v.Name)
		}
	}
}
