package usecase

import (
	"context"
	d "iwut-auth-center/internal/account/domain"
	"iwut-auth-center/internal/account/port"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	at    time.Time
	count int
}
type Service struct {
	readLimit, writeLimit, maxBuckets int
	repo                              port.Repository
	mu                                sync.Mutex
	buckets                           map[string]bucket
	now                               func() time.Time
}

func New(repo port.Repository) *Service {
	return &Service{readLimit: 60, writeLimit: 10, maxBuckets: 4096, repo: repo, buckets: map[string]bucket{}, now: time.Now}
}
func (s *Service) allow(actor string, write bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	limit := s.readLimit
	key := "read:" + actor
	if write {
		limit = s.writeLimit
		key = "write:" + actor
	}
	for k, b := range s.buckets {
		if now.Sub(b.at) >= time.Minute {
			delete(s.buckets, k)
		}
	}
	b, exists := s.buckets[key]
	if !exists && len(s.buckets) >= s.maxBuckets {
		return false
	}
	if b.count >= limit {
		return false
	}
	if !exists {
		b.at = now
	}
	b.count++
	s.buckets[key] = b
	return true
}
func (s *Service) Get(ctx context.Context, actor, subject string) (d.State, error) {
	if !d.ValidSubject(actor) || !d.ValidSubject(subject) {
		return d.State{}, d.ErrInvalid
	}
	if !s.allow(actor, false) {
		return d.State{}, d.ErrRate
	}
	return s.repo.Get(ctx, actor, subject)
}
func (s *Service) Manage(ctx context.Context, c d.Command) (d.State, error) {
	c.Reason = strings.TrimSpace(c.Reason)
	if err := c.Validate(); err != nil {
		return d.State{}, err
	}
	if !s.allow(c.ActorAuthID, true) {
		return d.State{}, d.ErrRate
	}
	return s.repo.Manage(ctx, c)
}

func NewConfigured(repo port.Repository, readLimit, writeLimit, maxBuckets int) *Service {
	s := New(repo)
	s.readLimit = readLimit
	s.writeLimit = writeLimit
	s.maxBuckets = maxBuckets
	return s
}
