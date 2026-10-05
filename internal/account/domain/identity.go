package domain

import "context"

type identityKey struct{}
type IdentityState struct {
	AuthID   string
	Revision int64
}

func WithIdentity(ctx context.Context, authID string, revision int64) context.Context {
	return context.WithValue(ctx, identityKey{}, IdentityState{authID, revision})
}
func Identity(ctx context.Context) (IdentityState, bool) {
	v, ok := ctx.Value(identityKey{}).(IdentityState)
	return v, ok
}
