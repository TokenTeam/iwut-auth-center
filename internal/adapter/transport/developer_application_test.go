package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_application"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	d "iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/usecase"
	"testing"
	"time"
)

type applicationRepoStub struct {
	state   d.ApplicationState
	calls   int
	retries int
}

func (r *applicationRepoStub) Evaluate(_ context.Context, _ []byte, decide func(d.ApplicationState) (d.HandleClaim, error)) (d.ApplicationState, error) {
	r.calls++
	for range r.retries {
		if _, e := decide(r.state); e != nil {
			return d.ApplicationState{}, e
		}
	}
	activate, e := decide(r.state)
	if e != nil {
		return d.ApplicationState{}, e
	}
	if activate.DeveloperHandle != "" {
		r.state.DeveloperHandle = activate.DeveloperHandle
		now := time.Now()
		r.state.Status = d.DeveloperStatusApproved
		r.state.ActivatedAt = &now
	}
	return r.state, nil
}
func TestDeveloperApplicationAccountAdmissionAndRetries(t *testing.T) {
	gate, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 100, CompleteGlobal: 100, BeginSource: 100, CompleteLocator: 2, MaxBuckets: 10})
	repo := &applicationRepoStub{state: d.ApplicationState{AuthID: "u", EmailRevision: 1}, retries: 3}
	s := NewDeveloperApplicationService(usecase.NewApplication(repo, gate, true), 16384)
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-iwut-session", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	if _, e := s.GetOwnDeveloperEligibility(ctx, &pb.GetOwnDeveloperEligibilityRequest{}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); e != nil {
		t.Fatal(e)
	}
	_, e := s.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"})
	if status.Code(e) != codes.ResourceExhausted || kerrors.FromError(e).Metadata["retryAfterSeconds"] != "60" {
		t.Fatal(e)
	}
}
func TestDeveloperApplicationSourceAndBoundedCapacity(t *testing.T) {
	gate, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 100, CompleteGlobal: 100, BeginSource: 2, CompleteLocator: 100, MaxBuckets: 2})
	repo := &applicationRepoStub{state: d.ApplicationState{AuthID: "u", EmailRevision: 1}}
	a := usecase.NewApplication(repo, gate, true)
	s := NewDeveloperApplicationService(a, 16384)
	// Invalid tokens consume bounded source admission but create no account bucket.
	for range 2 {
		if _, e := s.ApplyForDeveloper(t.Context(), &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); status.Code(e) != codes.Unauthenticated {
			t.Fatal(e)
		}
	}
	if _, e := s.ApplyForDeveloper(t.Context(), &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); status.Code(e) != codes.ResourceExhausted {
		t.Fatal(e)
	}
	if repo.calls != 0 {
		t.Fatal("unauthenticated request reached storage")
	}
	if e := a.AdmitSource("other-source"); e != nil {
		t.Fatal(e)
	}
	if e := a.AdmitSource("overflow-source"); !errors.Is(e, d.ErrApplicationRate) {
		t.Fatal("bucket capacity grew", e)
	}
}
func TestDeveloperApplicationGlobalAdmission(t *testing.T) {
	gate, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1, CompleteGlobal: 1, BeginSource: 100, CompleteLocator: 100, MaxBuckets: 10})
	a := usecase.NewApplication(&applicationRepoStub{}, gate, true)
	if e := a.AdmitSource("one"); e != nil {
		t.Fatal(e)
	}
	if e := a.AdmitSource("two"); !errors.Is(e, d.ErrApplicationRate) {
		t.Fatal(e)
	}
}
