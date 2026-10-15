package passwordcrypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/password/domain"
	"os"
	"testing"
	"time"
)

func TestPublicPasswordVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/auth-password-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		OperationKey string `json:"operationKey_hex"`
		KeyID        string `json:"keyId_hex"`
		Context      struct {
			AuthID, RequestID, OperationID, SessionID, ServiceID                  string
			AccountRevision, PasswordRevision, LoginRoleRevision, ExpiresAtUnixMs int64
			NormalizedLoginEmail, Code, CurrentPassword, NewPassword              string
		}
		Login struct {
			Key        string `json:"publicKey65_hex"`
			Challenge  string `json:"challenge_hex"`
			Payload    string `json:"signingPayload_hex"`
			Signature  string `json:"signature_der_hex"`
			Equivalent string `json:"equivalentS_signature_der_hex"`
		}
		MACs map[string]struct {
			MAC string `json:"mac_hex"`
		}
		Argon2id struct {
			Vectors []struct {
				Input, Normalized string
				Salt              string `json:"salt_hex"`
				Hash              string `json:"hash_hex"`
			}
		}
		Negatives []struct {
			Name      string
			Payload   string `json:"payload_hex"`
			Signature string `json:"signature_der_hex"`
		} `json:"negativeProofs"`
	}
	if err = json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c := v.Context
	p, err := NewProtocol(decode(v.OperationKey), c.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	if p.KeyID() != v.KeyID {
		t.Fatal("key ID mismatch")
	}
	expires := time.UnixMilli(c.ExpiresAtUnixMs)
	payload, err := p.LoginPayload(c.OperationID, c.NormalizedLoginEmail, decode(v.Login.Key), decode(v.Login.Challenge), expires)
	if err != nil || !bytes.Equal(payload, decode(v.Login.Payload)) {
		t.Fatal("payload mismatch", err)
	}
	d, _ := deviceprotocol.New(c.ServiceID)
	for _, s := range []string{v.Login.Signature, v.Login.Equivalent} {
		if !d.Verify(decode(v.Login.Key), payload, decode(s)) {
			t.Fatal("positive signature rejected")
		}
	}
	for _, n := range v.Negatives {
		if d.Verify(decode(v.Login.Key), decode(n.Payload), decode(n.Signature)) {
			t.Fatal("negative proof accepted", n.Name)
		}
	}
	change, err := p.ChangeMAC(c.AuthID, c.RequestID, c.SessionID, c.AccountRevision, c.PasswordRevision, c.CurrentPassword, c.NewPassword)
	if err != nil || !bytes.Equal(change, decode(v.MACs["change"].MAC)) {
		t.Fatal("change MAC mismatch", err)
	}
	request, err := p.ResetRequestMAC(c.RequestID, c.NormalizedLoginEmail)
	if err != nil || !bytes.Equal(request, decode(v.MACs["resetRequest"].MAC)) {
		t.Fatal("reset request MAC mismatch", err)
	}
	code, err := p.ResetCodeMAC(c.OperationID, c.AuthID, c.LoginRoleRevision, c.PasswordRevision, c.AccountRevision, expires, request, c.Code)
	if err != nil || !bytes.Equal(code, decode(v.MACs["resetCode"].MAC)) {
		t.Fatal("reset code MAC mismatch", err)
	}
	completion, err := p.ResetCompletionMAC(c.OperationID, code, c.NewPassword)
	if err != nil || !bytes.Equal(completion, decode(v.MACs["resetCompletion"].MAC)) {
		t.Fatal("reset completion MAC mismatch", err)
	}
	e := testEngine(t)
	for _, hash := range v.Argon2id.Vectors {
		normalized, err := e.Normalize(hash.Input)
		if err != nil || normalized != hash.Normalized {
			t.Fatal("NFC mismatch")
		}
		m := domain.Material{Algorithm: domain.Algorithm, FormatVersion: 1, NormalizationVersion: domain.NormalizationVersion, Parameters: domain.DefaultParameters(), Salt: decode(hash.Salt), Hash: decode(hash.Hash)}
		if ok, err := e.Verify(context.Background(), hash.Input, m); err != nil || !ok {
			t.Fatal("independent Argon2id hash mismatch", err)
		}
	}
}
