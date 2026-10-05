package sessionmanagementrate

import (
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"time"
)

// One shared bounded map counts socket sources and authenticated account IDs.
// The account stage consumes no second global/source allowance on retries.
type Limiter struct{ limiter *deviceprotocol.Limiter }

func New(global, source, account, buckets int) (*Limiter, error) {
	l, e := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: global, CompleteGlobal: global, BeginSource: source, CompleteLocator: account, MaxBuckets: buckets})
	if e != nil {
		return nil, e
	}
	return &Limiter{l}, nil
}
func (l *Limiter) AllowSource(source string, now time.Time) bool {
	return l.limiter.AllowBegin(source, now)
}
func (l *Limiter) AllowAccount(authID string, now time.Time) bool {
	return l.limiter.AllowLocator(authID, now)
}
