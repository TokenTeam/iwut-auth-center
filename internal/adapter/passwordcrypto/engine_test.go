package passwordcrypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"iwut-auth-center/internal/password/domain"
	"strings"
	"testing"
	"time"
)

func testBlocklist(t testing.TB) *Blocklist {
	t.Helper()
	sum := sha256.Sum256([]byte("a blocked password"))
	data := hex.EncodeToString(sum[:]) + "\n"
	digest := sha256.Sum256([]byte(data))
	b, err := LoadBlocklist(strings.NewReader(data), "test-fixture-v1", "TEST ONLY", hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testEngine(t testing.TB) *Engine {
	t.Helper()
	executor, err := NewExecutor(4, 32, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(domain.DefaultParameters(), testBlocklist(t), executor)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestPolicyAndNormalization(t *testing.T) {
	e := testEngine(t)
	for _, v := range []string{"", strings.Repeat("x", 14), strings.Repeat("x", 129), strings.Repeat("x", 1025), "a blocked password", string([]byte{0xff})} {
		if _, err := e.ValidateNew(v); err == nil {
			t.Fatal("invalid policy input accepted")
		}
	}
	for _, v := range []string{strings.Repeat("x", 15), strings.Repeat("x", 128), strings.Repeat("𐐀", 128), "  a long password  ", strings.Repeat("e\u0301", 15)} {
		if _, err := e.ValidateNew(v); err != nil {
			t.Fatal(err)
		}
	}
	n, err := e.Normalize("  e\u0301AbC  ")
	if err != nil || n != "  éAbC  " {
		t.Fatal("normalization altered spaces/case")
	}
	if _, err := e.Normalize("short"); err != nil {
		t.Fatal("verification applied new minimum")
	}
}
func TestHashVerifyRandomSaltAndCorruption(t *testing.T) {
	e := testEngine(t)
	a, err := e.Hash(context.Background(), "a unique password é")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Hash(context.Background(), "a unique password é")
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Salt) == string(b.Salt) || string(a.Hash) == string(b.Hash) {
		t.Fatal("salt reused")
	}
	for _, v := range []string{"a unique password é", "a unique password e\u0301"} {
		ok, err := e.Verify(context.Background(), v, a)
		if err != nil || !ok {
			t.Fatal("equivalent input rejected")
		}
	}
	if ok, err := e.Verify(context.Background(), "not the same password", a); err != nil || ok {
		t.Fatal("wrong input accepted")
	}
	for _, mutate := range []func(*domain.Material){func(m *domain.Material) { m.Algorithm = "sha256" }, func(m *domain.Material) { m.FormatVersion = 0 }, func(m *domain.Material) { m.NormalizationVersion = "NFKC" }, func(m *domain.Material) { m.Parameters.MemoryKiB = 1 << 31 }, func(m *domain.Material) { m.Parameters.Iterations = 0 }, func(m *domain.Material) { m.Salt = m.Salt[:15] }, func(m *domain.Material) { m.Hash = m.Hash[:31] }} {
		m := a
		mutate(&m)
		if _, err := e.Verify(context.Background(), "a unique password é", m); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatal("corrupt record computed")
		}
	}
	// Verification/rehash intentionally ignores newly blocked passwords.
	legacy, err := e.Rehash(context.Background(), "a blocked password")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Verify(context.Background(), "a blocked password", legacy); err != nil || !ok {
		t.Fatal("existing blocked secret cannot verify")
	}
}
func TestBlocklistFailClosed(t *testing.T) {
	for _, data := range []string{"", strings.Repeat("0", 64), strings.Repeat("z", 64) + "\n", strings.Repeat("0", 64) + "\n" + strings.Repeat("0", 64) + "\n", strings.Repeat("0", 64) + "\r\n"} {
		sum := sha256.Sum256([]byte(data))
		if _, err := LoadBlocklist(strings.NewReader(data), "v1", "test", hex.EncodeToString(sum[:])); err == nil {
			t.Fatal("bad blocklist accepted")
		}
	}
	if _, err := LoadBlocklist(strings.NewReader(strings.Repeat("0", 64)+"\n"), "v1", "test", strings.Repeat("1", 64)); err == nil {
		t.Fatal("pin mismatch accepted")
	}
}
func TestExecutorCancellationKeepsRunningSlot(t *testing.T) {
	e, _ := NewExecutor(1, 0, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.Do(ctx, func() { close(started); <-release }) }()
	<-started
	cancel()
	if err := e.Do(context.Background(), func() { t.Error("slot released before work ended") }); !errors.Is(err, domain.ErrLimited) {
		t.Fatal("canceled running work released slot")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := e.Do(context.Background(), func() {}); err != nil {
		t.Fatal("slot leaked")
	}
}
func TestExecutorQueueBoundsAndTimeout(t *testing.T) {
	e, _ := NewExecutor(1, 1, 10*time.Millisecond)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.Do(context.Background(), func() { close(started); <-release }) }()
	<-started
	if err := e.Do(context.Background(), func() { t.Error("timed-out work ran") }); !errors.Is(err, domain.ErrLimited) {
		t.Fatal(err)
	}
	close(release)
	<-done
}
func BenchmarkArgon2idDefault(b *testing.B) {
	e := testEngine(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := e.Hash(context.Background(), "benchmark unique password"); err != nil {
			b.Fatal(err)
		}
	}
}
