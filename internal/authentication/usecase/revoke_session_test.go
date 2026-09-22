package usecase

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"iwut-auth-center/internal/authentication/port"
)

type revocationRepository struct {
	calls  int
	digest []byte
	now    time.Time
	err    error
}

func (r *revocationRepository) RevokeCurrentSession(_ context.Context, digest []byte, now time.Time) error {
	r.calls++
	r.digest = digest
	r.now = now
	return r.err
}

type revocationTokenDigester struct {
	digest []byte
	err    error
}

func (d revocationTokenDigester) TokenDigest(string) ([]byte, error) { return d.digest, d.err }

func TestRevokeSessionRejectsMalformedBeforeStorage(t *testing.T) {
	for _, protocol := range []revocationTokenDigester{{err: errors.New("malformed")}, {digest: make([]byte, 31)}} {
		repository := &revocationRepository{}
		uc, _ := NewRevokeCurrentSession(repository, protocol)
		if err := uc.Handle(t.Context(), "malformed"); !errors.Is(err, port.ErrInvalidSessionToken) || repository.calls != 0 {
			t.Fatalf("malformed token: err=%v calls=%d", err, repository.calls)
		}
	}
}

func TestRevokeSessionDigestsAndSanitizesFailures(t *testing.T) {
	token, digest := "transient-token", bytes.Repeat([]byte{1}, 32)
	protocol := revocationTokenDigester{digest: digest}
	repository := &revocationRepository{}
	uc, _ := NewRevokeCurrentSession(repository, protocol)
	now := time.Now().UTC().Truncate(time.Millisecond)
	uc.clock = func() time.Time { return now }
	if err := uc.Handle(t.Context(), token); err != nil || !bytes.Equal(digest, repository.digest) || !repository.now.Equal(now) {
		t.Fatalf("revocation err=%v digest=%v now=%v", err, repository.digest, repository.now)
	}
	repository.err = errors.New("backend error containing " + token)
	if err := uc.Handle(t.Context(), token); !errors.Is(err, port.ErrUnavailable) || strings.Contains(err.Error(), token) {
		t.Fatalf("storage error was not sanitized: %v", err)
	}
}
