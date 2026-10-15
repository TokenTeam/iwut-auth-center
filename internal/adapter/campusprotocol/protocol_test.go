package campusprotocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/campuscertification/domain"
	"iwut-auth-center/internal/campuscertification/port"
	"testing"
	"time"
)

func TestCampusHMACExactFieldsAndDomainSeparation(t *testing.T) {
	key := bytes.Repeat([]byte{0x71}, 32)
	p, err := New(key, "iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	b := d.Begin{RequestID: "00000000-0000-4000-8000-000000000001", Email: "name@whut.edu.cn"}
	revision := make([]byte, 8)
	binary.BigEndian.PutUint64(revision, 7)
	h := hmac.New(sha256.New, key)
	h.Write(deviceprotocol.Frame([]byte("iwut-campus-request-v1"), []byte(b.RequestID), []byte("auth-one"), revision, []byte(b.Email), []byte("iwut-auth-center:test"), []byte("iwut-client")))
	request := p.RequestMAC(b, "auth-one", 7)
	if !hmac.Equal(request, h.Sum(nil)) {
		t.Fatal("request framing differs from accepted byte protocol")
	}
	op := port.Operation{Proof: auth.Operation{OperationID: "00000000-0000-4000-8000-000000000002", ExpiresAt: time.UnixMilli(1791799800000)}, RequestMAC: request}
	expires := make([]byte, 8)
	binary.BigEndian.PutUint64(expires, uint64(op.Proof.ExpiresAt.UnixMilli()))
	h.Reset()
	h.Write(deviceprotocol.Frame([]byte("iwut-campus-code-v1"), []byte("CERTIFY_CAMPUS_WHUT"), []byte(op.Proof.OperationID), expires, request, []byte("00001234")))
	if !hmac.Equal(p.CodeMAC(op, "00001234"), h.Sum(nil)) {
		t.Fatal("code framing differs")
	}
	keyID := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-campus-key-id-v1"), key))
	if p.KeyID() != hex.EncodeToString(keyID[:]) {
		t.Fatal("key id framing differs")
	}
	for _, other := range [][]byte{p.RequestMAC(b, "auth-two", 7), p.RequestMAC(b, "auth-one", 8), p.RequestMAC(d.Begin{RequestID: b.RequestID, Email: "other@whut.edu.cn"}, "auth-one", 7)} {
		if hmac.Equal(other, request) {
			t.Fatal("request not bound to account/revision/address")
		}
	}
	if hmac.Equal(p.CodeMAC(op, "00001234"), p.CodeMAC(op, "00001235")) {
		t.Fatal("code not bound")
	}
	copy(key, bytes.Repeat([]byte{2}, 32))
	if p.KeyID() != hex.EncodeToString(keyID[:]) {
		t.Fatal("caller changed retained secret")
	}
}
func TestCampusProtocolValidationAndCodeShape(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := New(make([]byte, n), "auth"); err == nil {
			t.Fatal("bad key accepted")
		}
	}
	if _, err := New(make([]byte, 32), ""); err == nil {
		t.Fatal("bad service accepted")
	}
	p, _ := New(make([]byte, 32), "auth")
	for i := 0; i < 32; i++ {
		code, err := p.NewCode()
		if err != nil || len(code) != 8 {
			t.Fatal("bad code", err)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatal("not ascii digits")
			}
		}
	}
}
