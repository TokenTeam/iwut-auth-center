package emailloginprotocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	emaildomain "iwut-auth-center/internal/emailbinding/domain"
	"iwut-auth-center/internal/emaillogin/domain"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func fixtureNormalize(s string) (string, error) { return emaildomain.NormalizeEmail(s) }
func TestPublicVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/auth-email-login-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	type vector struct {
		Name, Kind, Purpose, ServiceID, ApplicationID, OperationID, NormalizedEmail string
		ExpiresAt                                                                   int64  `json:"expiresAtUnixMs"`
		Challenge                                                                   string `json:"challenge_hex"`
		PublicKey                                                                   string `json:"publicKey65_hex"`
		Payload                                                                     string `json:"payload_hex"`
		SigningPayload                                                              string `json:"signingPayload_hex"`
		Signature                                                                   string `json:"signature_der_hex"`
		OtherS                                                                      string `json:"equivalentS_signature_der_hex"`
	}
	var f struct{ Proofs, CrossProtocolProofs, NegativeProofs []vector }
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	p, e := New("iwut-auth-center:test", make([]byte, 32), fixtureNormalize)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range f.Proofs {
		t.Run(v.Name, func(t *testing.T) {
			op := domain.Operation{OperationID: v.OperationID, Purpose: v.Purpose, ProtocolVersion: domain.ProtocolVersion, ServiceID: v.ServiceID, ApplicationID: v.ApplicationID, Challenge: unhex(t, v.Challenge), ExpiresAt: time.UnixMilli(v.ExpiresAt), PublicKey: unhex(t, v.PublicKey), Email: v.NormalizedEmail}
			payload, e := p.Payload(op)
			if e != nil || !bytes.Equal(payload, unhex(t, v.SigningPayload)) {
				t.Fatal("payload differs", e)
			}
			if _, e := p.ParsePayload(payload); e != nil {
				t.Fatal(e)
			}
			for _, sig := range []string{v.Signature, v.OtherS} {
				if !p.Verify(op.PublicKey, payload, unhex(t, sig)) {
					t.Fatal("valid signature rejected")
				}
			}
		})
	}
	for _, v := range f.NegativeProofs {
		t.Run(v.Name, func(t *testing.T) {
			payload := unhex(t, v.Payload)
			if v.Kind == "FRAME" || v.Kind == "CONTEXT" {
				if _, e := p.ParsePayload(payload); e == nil {
					t.Fatal("invalid payload accepted")
				}
				return
			}
			if p.Verify(unhex(t, v.PublicKey), payload, unhex(t, v.Signature)) {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	for _, v := range f.CrossProtocolProofs {
		t.Run(v.Name, func(t *testing.T) {
			if p.Verify(unhex(t, v.PublicKey), unhex(t, v.Payload), unhex(t, v.Signature)) {
				t.Fatal("cross-protocol proof accepted")
			}
		})
	}
	if len(f.NegativeProofs) != 28 || len(f.Proofs) != 2 {
		t.Fatal("fixture coverage unexpectedly changed")
	}
}
func TestMACDomainsAndRotation(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	p, _ := New("test", key, fixtureNormalize)
	request := domain.Begin{RequestID: "77777777-7777-4777-8777-000000000001", Email: "student+login@example.test", ProtocolVersion: auth.ProtocolVersion, PublicKey: []byte("public-test-key")}
	mac := func(fields ...[]byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(deviceprotocol.Frame(fields...))
		return h.Sum(nil)
	}
	expected := mac([]byte("iwut-email-login-request-v1"), []byte(request.RequestID), []byte(request.Email), []byte("test"), []byte(auth.ApplicationID), []byte(auth.ProtocolVersion), request.PublicKey)
	if !hmac.Equal(expected, p.RequestMAC(request)) {
		t.Fatal("request MAC framing differs")
	}
	op := domain.Operation{OperationID: request.RequestID, ExpiresAt: time.UnixMilli(1800000600000), RequestMAC: expected}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], 1800000600000)
	expectedCode := mac([]byte("iwut-email-login-code-v1"), []byte(domain.Purpose), []byte(op.OperationID), expiry[:], expected, []byte("00000001"))
	if !hmac.Equal(expectedCode, p.CodeMAC(op, "00000001")) {
		t.Fatal("code MAC framing differs")
	}
	id := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-email-login-key-id-v1"), key))
	if p.KeyID() != hex.EncodeToString(id[:]) {
		t.Fatal("key id framing differs")
	}
	key[0] ^= 1 // caller mutation cannot rotate the live adapter.
	if !hmac.Equal(expected, p.RequestMAC(request)) {
		t.Fatal("key alias")
	}
	rotated, _ := New("test", key, fixtureNormalize)
	if rotated.KeyID() == p.KeyID() || hmac.Equal(rotated.CodeMAC(op, "00000001"), expectedCode) {
		t.Fatal("rotation ineffective")
	}
	for _, s := range []string{"", "0000000", "000000000", " 0000001", "１２３４５６７８", "0000001\n"} {
		if p.ValidCode(s) {
			t.Fatal("invalid code accepted")
		}
	}
	for range 50 {
		code, e := p.NewCode()
		if e != nil || !p.ValidCode(code) {
			t.Fatal("invalid generated code", e)
		}
	}
}
