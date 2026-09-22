package deviceprotocol

import (
	"errors"
	"sync"
	"time"
)

type RateLimits struct{ BeginGlobal, CompleteGlobal, BeginSource, CompleteLocator, MaxBuckets int }

func DefaultRateLimits() RateLimits { return RateLimits{600, 1200, 30, 60, 4096} }

type rateBucket struct {
	minute int64
	used   int
}
type Limiter struct {
	mu              sync.Mutex
	limits          RateLimits
	begin, complete rateBucket
	buckets         map[string]rateBucket
}

func NewLimiter(limits RateLimits) (*Limiter, error) {
	if limits.BeginGlobal <= 0 || limits.CompleteGlobal <= 0 || limits.BeginSource <= 0 || limits.CompleteLocator <= 0 || limits.MaxBuckets <= 0 {
		return nil, errors.New("authentication rate limits must be positive")
	}
	return &Limiter{limits: limits, buckets: make(map[string]rateBucket)}, nil
}
func take(bucket *rateBucket, minute int64, limit int) bool {
	if bucket.minute != minute {
		*bucket = rateBucket{minute: minute}
	}
	if bucket.used >= limit {
		return false
	}
	bucket.used++
	return true
}
func (l *Limiter) allow(key string, now time.Time, begin bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	minute := now.Unix() / 60
	limit := l.limits.CompleteLocator
	if begin {
		if !take(&l.begin, minute, l.limits.BeginGlobal) {
			return false
		}
		limit = l.limits.BeginSource
	} else {
		if !take(&l.complete, minute, l.limits.CompleteGlobal) {
			return false
		}
	}
	// Unknown operation IDs consume the global bucket even without a resolved locator.
	if key == "" {
		return true
	}
	if len(key) > 256 {
		return false
	}
	if begin {
		key = "B:" + key
	} else {
		key = "C:" + key
	}
	bucket, exists := l.buckets[key]
	if !exists && len(l.buckets) >= l.limits.MaxBuckets {
		for k, b := range l.buckets {
			if b.minute != minute {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) >= l.limits.MaxBuckets {
			return false
		}
	}
	allowed := take(&bucket, minute, limit)
	l.buckets[key] = bucket
	return allowed
}
func (l *Limiter) AllowBegin(source string, now time.Time) bool { return l.allow(source, now, true) }
func (l *Limiter) AllowComplete(locator string, now time.Time) bool {
	return l.allow(locator, now, false)
}
func (l *Limiter) AllowLocator(locator string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if locator == "" || len(locator) > 256 {
		return false
	}
	key := "C:" + locator
	minute := now.Unix() / 60
	bucket, exists := l.buckets[key]
	if !exists && len(l.buckets) >= l.limits.MaxBuckets {
		for k, b := range l.buckets {
			if b.minute != minute {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) >= l.limits.MaxBuckets {
			return false
		}
	}
	allowed := take(&bucket, minute, l.limits.CompleteLocator)
	l.buckets[key] = bucket
	return allowed
}
