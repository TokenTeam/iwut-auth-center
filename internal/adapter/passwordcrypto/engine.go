package passwordcrypto

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
	"iwut-auth-center/internal/password/domain"
	"iwut-auth-center/internal/password/port"
)

type Engine struct {
	parameters domain.Parameters
	blocklist  *Blocklist
	executor   *Executor
}

func New(parameters domain.Parameters, blocklist *Blocklist, executor *Executor) (*Engine, error) {
	if !parameters.Valid() || blocklist == nil || len(blocklist.hashes) == 0 || executor == nil || norm.Version != "15.0.0" || argon2.Version != 19 {
		return nil, domain.ErrUnavailable
	}
	return &Engine{parameters, blocklist, executor}, nil
}

func (*Engine) Normalize(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 1024 || !utf8.ValidString(raw) {
		return "", domain.ErrInvalidInput
	}
	normalized := norm.NFC.String(raw)
	if len(normalized) > 512 || utf8.RuneCountInString(normalized) > 128 {
		return "", domain.ErrInvalidInput
	}
	return normalized, nil
}

func (e *Engine) ValidateNew(raw string) (string, error) {
	v, err := e.Normalize(raw)
	if err != nil {
		return "", err
	}
	if utf8.RuneCountInString(v) < 15 || e.blocklist.Contains(v) {
		return "", domain.ErrPolicy
	}
	return v, nil
}

func (e *Engine) Hash(ctx context.Context, raw string) (domain.Material, error) {
	normalized, err := e.ValidateNew(raw)
	if err != nil {
		return domain.Material{}, err
	}
	return e.hashNormalized(ctx, normalized)
}

// Rehash verifies existing input without applying the current new-password
// blocklist/minimum again. It must only be used after successful verification.
func (e *Engine) Rehash(ctx context.Context, raw string) (domain.Material, error) {
	normalized, err := e.Normalize(raw)
	if err != nil {
		return domain.Material{}, err
	}
	return e.hashNormalized(ctx, normalized)
}

func (e *Engine) hashNormalized(ctx context.Context, normalized string) (domain.Material, error) {
	m := domain.Material{Algorithm: domain.Algorithm, FormatVersion: domain.FormatVersion, NormalizationVersion: domain.NormalizationVersion, Parameters: e.parameters, Salt: make([]byte, 16)}
	if _, err := rand.Read(m.Salt); err != nil {
		return domain.Material{}, domain.ErrUnavailable
	}
	err := e.executor.Do(ctx, func() {
		m.Hash = argon2.IDKey([]byte(normalized), m.Salt, m.Parameters.Iterations, m.Parameters.MemoryKiB, m.Parameters.Parallelism, 32)
	})
	if err != nil {
		return domain.Material{}, err
	}
	return m, nil
}

func (e *Engine) Verify(ctx context.Context, raw string, m domain.Material) (bool, error) {
	// Validate stored costs before an attacker-controlled allocation/computation.
	if !m.Valid() {
		return false, domain.ErrUnavailable
	}
	normalized, err := e.Normalize(raw)
	if err != nil {
		return false, err
	}
	matched := false
	err = e.executor.Do(ctx, func() {
		computed := argon2.IDKey([]byte(normalized), m.Salt, m.Parameters.Iterations, m.Parameters.MemoryKiB, m.Parameters.Parallelism, 32)
		matched = subtle.ConstantTimeCompare(computed, m.Hash) == 1
		clear(computed)
	})
	return matched, err
}

func (e *Engine) NeedsUpgrade(m domain.Material) bool {
	return m.Valid() && m.Parameters.MemoryKiB <= e.parameters.MemoryKiB && m.Parameters.Iterations <= e.parameters.Iterations && (m.Parameters.MemoryKiB < e.parameters.MemoryKiB || m.Parameters.Iterations < e.parameters.Iterations)
}

var _ port.Engine = (*Engine)(nil)
