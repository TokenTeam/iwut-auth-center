package emailprotocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/emailbinding/domain"
	emailport "iwut-auth-center/internal/emailbinding/port"
	"os"
	"testing"
	"time"
)

func TestPublicVectors(t *testing.T) {
	data, e := os.ReadFile("testdata/auth-email-binding-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		EmailNormalization []struct{ Input, Normalized string }
		InvalidEmailInputs []struct{ Input string }
		Proofs             []map[string]json.RawMessage
		NegativeProofs     []map[string]json.RawMessage
		ExpiryChecks       []struct {
			NowUnixMs int64
			Expected  string
		}
	}
	if e = json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
	for _, x := range v.EmailNormalization {
		actual, e := d.NormalizeEmail(x.Input)
		if e != nil || actual != x.Normalized {
			t.Fatalf("normalization %q: %q %v", x.Input, actual, e)
		}
	}
	for _, x := range v.InvalidEmailInputs {
		if _, e := d.NormalizeEmail(x.Input); e == nil {
			t.Fatalf("accepted %q", x.Input)
		}
	}
	str := func(m map[string]json.RawMessage, k string) string {
		var s string
		if e := json.Unmarshal(m[k], &s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	unhex := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	canonical := map[string][]byte{}
	for _, x := range v.Proofs {
		p, _ := New(bytes.Repeat([]byte{3}, 32), str(x, "serviceId"))
		device, _ := deviceprotocol.New(str(x, "serviceId"))
		var expiry int64
		json.Unmarshal(x["expiresAtUnixMs"], &expiry)
		op := emailport.Operation{Mode: d.Register, Email: str(x, "normalizedEmail"), Proof: auth.Operation{OperationID: str(x, "operationId"), Purpose: d.RegistrationPurpose, ProtocolVersion: auth.ProtocolVersion, ServiceID: str(x, "serviceId"), ApplicationID: auth.ApplicationID, Challenge: unhex(str(x, "challenge_hex")), PublicKey: unhex(str(x, "publicKey65_hex")), ExpiresAt: time.UnixMilli(expiry)}}
		payload, e := p.Payload(op, unhex(str(x, "associationDigest_hex")))
		if e != nil || !bytes.Equal(payload, unhex(str(x, "signingPayload_hex"))) {
			t.Fatalf("payload mismatch: %v", e)
		}
		canonical[str(x, "name")] = payload
		for _, key := range []string{"signature_der_hex", "equivalentS_signature_der_hex"} {
			if !device.Verify(op.Proof.PublicKey, payload, unhex(str(x, key))) {
				t.Fatal("valid proof rejected")
			}
		}
	}
	for _, x := range v.NegativeProofs {
		device, _ := deviceprotocol.New("iwut-auth-center:test")
		payload := unhex(str(x, "payload_hex"))
		if bytes.Equal(payload, canonical[str(x, "referenceProof")]) && device.Verify(unhex(str(x, "publicKey65_hex")), payload, unhex(str(x, "signature_der_hex"))) {
			t.Fatalf("negative accepted: %s", str(x, "name"))
		}
	}
	for _, x := range v.ExpiryChecks {
		valid := time.UnixMilli(x.NowUnixMs).Before(time.UnixMilli(1800000600000))
		if valid != (x.Expected == "ACCEPT") {
			t.Fatal("expiry boundary")
		}
	}
}
func TestHMACDomains(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	p, _ := New(key, "test")
	revision := int64(0)
	b := d.Begin{Mode: d.Bind, RequestID: "55555555-5555-4555-8555-000000000001", Email: "a@example.test", Revision: &revision}
	actual := p.RequestMAC(b, "user")
	h := hmac.New(sha256.New, key)
	h.Write(deviceprotocol.Frame([]byte("iwut-email-request-v1"), []byte("BIND"), []byte(b.RequestID), []byte(b.Email), []byte("test"), []byte("iwut-client"), []byte("user"), make([]byte, 8)))
	if !hmac.Equal(actual, h.Sum(nil)) {
		t.Fatal("request HMAC encoding")
	}
	op := emailport.Operation{RequestMAC: actual, Proof: auth.Operation{Purpose: d.BindingPurpose, OperationID: b.RequestID, ExpiresAt: time.UnixMilli(10000)}}
	first := p.CodeMAC(op, "00000001")
	op.Proof.Purpose = d.RegistrationPurpose
	if hmac.Equal(first, p.CodeMAC(op, "00000001")) {
		t.Fatal("purpose collision")
	}
	op.Proof.Purpose = d.BindingPurpose
	if hmac.Equal(first, p.CodeMAC(op, "00000002")) {
		t.Fatal("code collision")
	}
	for range 100 {
		code, e := p.NewCode()
		if e != nil || !d.ValidCode(code) {
			t.Fatal("invalid generated code")
		}
	}
}
