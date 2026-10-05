package config

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type AccountClosure struct {
	Enabled, DataPolicyReady                  bool
	LedgerDir                                 string
	ReadPerMinute, WritePerMinute, MaxBuckets int
	WorkerInterval                            time.Duration
}

// The ledger configuration enables the durable runtime independently of the
// public mutation flag. Disabling new requests must not stop committed cleanup.
func loadAccountClosure(lookup LookupEnv, user *UserEndpoints) (*AccountClosure, error) {
	c := &AccountClosure{ReadPerMinute: 30, WritePerMinute: 10, MaxBuckets: 4096, WorkerInterval: time.Second}
	for key, dst := range map[string]*bool{"AUTH_ACCOUNT_CLOSURE_ENABLED": &c.Enabled, "AUTH_CLOSURE_DATA_POLICY_READY": &c.DataPolicyReady} {
		if raw, ok := lookup(key); ok {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, key)
			}
			*dst = v
		}
	}
	if raw, ok := lookup("AUTH_TERMINATION_LEDGER_DIR"); ok {
		if strings.TrimSpace(raw) != raw || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
			return nil, fmt.Errorf("%w: invalid termination ledger directory", ErrInvalidConfiguration)
		}
		c.LedgerDir = raw
	}
	for key, dst := range map[string]*int{"AUTH_ACCOUNT_CLOSURE_READ_PER_MINUTE": &c.ReadPerMinute, "AUTH_ACCOUNT_CLOSURE_WRITE_PER_MINUTE": &c.WritePerMinute, "AUTH_ACCOUNT_CLOSURE_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, ok := lookup(key); ok {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || v > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, key)
			}
			*dst = v
		}
	}
	if raw, ok := lookup("AUTH_ACCOUNT_CLOSURE_WORKER_INTERVAL"); ok {
		v, err := time.ParseDuration(raw)
		if err != nil || v < 10*time.Millisecond || v > time.Minute {
			return nil, fmt.Errorf("%w: invalid closure worker interval", ErrInvalidConfiguration)
		}
		c.WorkerInterval = v
	}
	if c.Enabled && (!c.DataPolicyReady || c.LedgerDir == "") {
		return nil, fmt.Errorf("%w: public account closure requires data policy readiness and termination ledger", ErrInvalidConfiguration)
	}
	if c.LedgerDir == "" {
		return nil, nil
	}
	if user == nil {
		return nil, fmt.Errorf("%w: closure runtime requires user authentication configuration", ErrInvalidConfiguration)
	}
	return c, nil
}
