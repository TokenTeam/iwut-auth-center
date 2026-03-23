package util

import (
	"context"
	"sync"
)

type requestAuditKey struct{}

// RequestAuditValue stores request-scoped fields that may be resolved during business handling.
type RequestAuditValue struct {
	mu       sync.RWMutex
	userID   string
	clientID string
}

func WithRequestAudit(ctx context.Context) context.Context {
	if RequestAuditFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, requestAuditKey{}, &RequestAuditValue{})
}

func RequestAuditFrom(ctx context.Context) *RequestAuditValue {
	v := ctx.Value(requestAuditKey{})
	if v == nil {
		return nil
	}
	s, ok := v.(*RequestAuditValue)
	if !ok {
		return nil
	}
	return s
}

func (v *RequestAuditValue) SetUserInfo(userID string, clientID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if userID != "" {
		v.userID = userID
	}
	if clientID != "" {
		v.clientID = clientID
	}
}

func (v *RequestAuditValue) UserID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.userID
}

func (v *RequestAuditValue) ClientID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.clientID
}
