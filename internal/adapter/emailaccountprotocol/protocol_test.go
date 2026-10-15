package emailaccountprotocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/emailaccount/domain"
	p "iwut-auth-center/internal/emailaccount/port"
	"os"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestPublicV3IndependentSignatureAndMACVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/auth-email-account-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Proofs []struct {
			Name, ServiceID, ApplicationID, OperationID, NormalizedEmail string
			Challenge                                                    string `json:"challenge_hex"`
			PublicKey                                                    string `json:"publicKey65_hex"`
			Payload                                                      string `json:"signingPayload_hex"`
			Signature                                                    string `json:"signature_der_hex"`
			EquivalentS                                                  string `json:"equivalentS_signature_der_hex"`
			Expires                                                      int64  `json:"expiresAtUnixMs"`
		}
		NegativeProofs []struct {
			Name, ReferenceProof string
			Key                  string `json:"publicKey65_hex"`
			Payload              string `json:"payload_hex"`
			Signature            string `json:"signature_der_hex"`
		}
		MacVectors struct {
			EmailKey                       string `json:"emailKey_hex"`
			PasswordKey                    string `json:"passwordKey_hex"`
			RequestID, BindingID, Password string
			Entries                        []struct {
				Name string
				MAC  string `json:"mac_hex"`
			}
		}
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Proofs) == 0 || len(vectors.NegativeProofs) < 20 || len(vectors.MacVectors.Entries) != 6 {
		t.Fatal("incomplete public fixtures")
	}
	reference := map[string][]byte{}
	for _, v := range vectors.Proofs {
		protocol, err := New(unhex(t, vectors.MacVectors.EmailKey), unhex(t, vectors.MacVectors.PasswordKey), v.ServiceID)
		if err != nil {
			t.Fatal(err)
		}
		o := p.Operation{Purpose: d.Register, OperationID: v.OperationID, ServiceID: v.ServiceID, Email: v.NormalizedEmail, PublicKey: unhex(t, v.PublicKey), Challenge: unhex(t, v.Challenge), ExpiresAt: time.UnixMilli(v.Expires)}
		payload, err := protocol.Payload(o)
		if err != nil || !bytes.Equal(payload, unhex(t, v.Payload)) {
			t.Fatal(v.Name, "payload", err)
		}
		if !protocol.device.Verify(o.PublicKey, payload, unhex(t, v.Signature)) || !protocol.device.Verify(o.PublicKey, payload, unhex(t, v.EquivalentS)) {
			t.Fatal(v.Name, "signature")
		}
		reference[v.Name] = payload
	}
	device, _ := deviceprotocol.New(vectors.Proofs[0].ServiceID)
	for _, v := range vectors.NegativeProofs {
		payload := unhex(t, v.Payload)
		if bytes.Equal(payload, reference[v.ReferenceProof]) && device.Verify(unhex(t, v.Key), payload, unhex(t, v.Signature)) {
			t.Fatal("negative accepted", v.Name)
		}
	}
	v := vectors.Proofs[0]
	m := vectors.MacVectors
	protocol, _ := New(unhex(t, m.EmailKey), unhex(t, m.PasswordKey), v.ServiceID)
	o := p.Operation{RequestID: m.RequestID, Purpose: d.Register, Email: v.NormalizedEmail, ServiceID: v.ServiceID, PublicKey: unhex(t, v.PublicKey), OperationID: v.OperationID, ExpiresAt: time.UnixMilli(v.Expires)}
	register, err := protocol.RequestMAC(o)
	if err != nil {
		t.Fatal(err)
	}
	o.RequestMAC = register
	code, err := protocol.CodeMAC(o, "00001234")
	if err != nil {
		t.Fatal(err)
	}
	o.Purpose = d.Add
	o.AuthID = "fixture-owner"
	o.AccountRevision = 7
	o.DirectoryRevision = 3
	add, err := protocol.RequestMAC(o)
	if err != nil {
		t.Fatal(err)
	}
	o.RequestMAC = add
	addCode, err := protocol.CodeMAC(o, "00001234")
	if err != nil {
		t.Fatal(err)
	}
	mutation := p.Mutation{Purpose: d.Switch, AuthID: "fixture-owner", RequestID: m.RequestID, BindingID: m.BindingID, DirectoryRevision: 3, RoleRevision: 2, PasswordRevision: 4, AccountRevision: 7}
	switched, err := protocol.MutationMAC(mutation, m.Password)
	if err != nil {
		t.Fatal(err)
	}
	mutation.Purpose = d.Remove
	mutation.RoleRevision = 0
	mutation.PasswordRevision = 0
	removed, err := protocol.MutationMAC(mutation, "")
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string][]byte{"register_request": register, "registration_code": code, "add_request": add, "add_code": addCode, "switch_request": switched, "remove_request": removed}
	for _, entry := range m.Entries {
		if !bytes.Equal(actual[entry.Name], unhex(t, entry.MAC)) {
			t.Fatal("MAC differs from Python", entry.Name)
		}
	}
	o.Purpose = d.Register
	o.AuthID = ""
	o.AccountRevision = 0
	o.DirectoryRevision = 0
	o.PublicKey = []byte{1}
	if _, err = protocol.RequestMAC(o); err == nil {
		t.Fatal("invalid proposal accepted")
	}
	if _, err = New(unhex(t, m.EmailKey), unhex(t, m.EmailKey), auth.ApplicationID); err == nil {
		t.Fatal("key purpose reuse accepted")
	}
}
