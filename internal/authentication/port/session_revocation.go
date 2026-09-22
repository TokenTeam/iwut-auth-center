package port

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidSessionToken = errors.New("invalid session token")

// SessionRevocationRepository must treat absent, expired and already revoked
// sessions identically and preserve the first revocation timestamp.
type SessionRevocationRepository interface {
	RevokeCurrentSession(context.Context, []byte, time.Time) error
}

type SessionTokenDigester interface {
	TokenDigest(string) ([]byte, error)
}
