package config

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

type Authentication struct {
	ServiceID                                                                                                       string
	SessionTTL                                                                                                      time.Duration
	MaxPending, MaxFailures, BeginGlobal, CompleteGlobal, BeginSource, CompleteLocator, MaxBuckets, MaxMessageBytes int
}

// LoadAuthentication is separate from the legacy internal-service configuration.
// The composition root must require it before enabling any authentication RPC.
func LoadAuthentication(lookup LookupEnv) (Authentication, error) {
	if lookup == nil {
		return Authentication{}, ErrInvalidConfiguration
	}
	serviceID, ok := lookup("AUTH_AUTHENTICATION_SERVICE_ID")
	if !ok || !regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`).MatchString(serviceID) {
		return Authentication{}, fmt.Errorf("%w: AUTH_AUTHENTICATION_SERVICE_ID is required and must be a valid service identifier", ErrInvalidConfiguration)
	}
	raw, ok := lookup("AUTH_SESSION_TTL")
	ttl, err := time.ParseDuration(raw)
	if !ok || err != nil || ttl < time.Millisecond || ttl%time.Millisecond != 0 {
		return Authentication{}, fmt.Errorf("%w: AUTH_SESSION_TTL is required and must be a positive whole-millisecond duration", ErrInvalidConfiguration)
	}
	c := Authentication{ServiceID: serviceID, SessionTTL: ttl, MaxPending: 10000, MaxFailures: 5, BeginGlobal: 600, CompleteGlobal: 1200, BeginSource: 30, CompleteLocator: 60, MaxBuckets: 4096, MaxMessageBytes: 16 * 1024}
	values := map[string]*int{"AUTH_MAX_PENDING_OPERATIONS": &c.MaxPending, "AUTH_MAX_FAILED_ATTEMPTS": &c.MaxFailures, "AUTH_BEGIN_GLOBAL_PER_MINUTE": &c.BeginGlobal, "AUTH_COMPLETE_GLOBAL_PER_MINUTE": &c.CompleteGlobal, "AUTH_BEGIN_SOURCE_PER_MINUTE": &c.BeginSource, "AUTH_COMPLETE_LOCATOR_PER_MINUTE": &c.CompleteLocator, "AUTH_RATE_MAX_BUCKETS": &c.MaxBuckets, "AUTH_MAX_MESSAGE_BYTES": &c.MaxMessageBytes}
	for key, target := range values {
		if raw, ok := lookup(key); ok {
			value, err := strconv.Atoi(raw)
			if err != nil || value <= 0 || value > 10000000 {
				return Authentication{}, fmt.Errorf("%w: %s must be a bounded positive integer", ErrInvalidConfiguration, key)
			}
			*target = value
		}
	}
	return c, nil
}
