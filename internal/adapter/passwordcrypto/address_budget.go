package passwordcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/password/domain"
)

// Mail configuration supplies the shared address protection key. Rotating the
// independent password operation key cannot replenish anonymous work budgets.
type AddressBudget struct{ key []byte }

func NewAddressBudget(key []byte) (*AddressBudget, error) {
	if len(key) != 32 {
		return nil, domain.ErrUnavailable
	}
	return &AddressBudget{append([]byte(nil), key...)}, nil
}
func (b *AddressBudget) Key(address string) string {
	h := hmac.New(sha256.New, b.key)
	h.Write(deviceprotocol.Frame([]byte("iwut-password-address-budget-v1"), []byte(address)))
	return "email:" + hex.EncodeToString(h.Sum(nil))
}
