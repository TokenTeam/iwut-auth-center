package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/port"
)

type repositoryStub struct {
	principals []domain.Principal
	err        error
	calls      int
}

func (stub *repositoryStub) BatchGet(_ context.Context, _ []domain.AuthID) ([]domain.Principal, error) {
	stub.calls++
	return append([]domain.Principal{}, stub.principals...), stub.err
}

func TestBatchGetDeveloperStatusesPreservesRequestOrder(t *testing.T) {
	approved := principal(t, "auth-b", domain.PrincipalTypeUser, domain.DeveloperStatusApproved)
	suspended := principal(t, "auth-a", domain.PrincipalTypeUser, domain.DeveloperStatusSuspended)
	handler := NewBatchGetDeveloperStatusesHandler(&repositoryStub{principals: []domain.Principal{approved, suspended}})

	entries, err := handler.Handle(context.Background(), []string{"auth-a", "auth-b"})
	if err != nil || len(entries) != 2 || entries[0].AuthID.String() != "auth-a" || entries[1].AuthID.String() != "auth-b" {
		t.Fatalf("Handle() = (%v, %v)", entries, err)
	}
}

func TestBatchGetDeveloperStatusesFailsClosed(t *testing.T) {
	tests := []struct {
		name       string
		ids        []string
		principals []domain.Principal
		want       error
		calls      int
	}{
		{name: "empty", want: ErrInvalidDeveloperStatusQuery},
		{name: "duplicate", ids: []string{"auth-a", "auth-a"}, want: ErrInvalidDeveloperStatusQuery},
		{name: "too many", ids: authIDs(MaxBatchSize + 1), want: ErrInvalidDeveloperStatusQuery},
		{name: "empty auth id", ids: []string{""}, want: ErrInvalidDeveloperStatusQuery},
		{name: "oversized auth id", ids: []string{strings.Repeat("a", domain.MaxAuthIDBytes+1)}, want: ErrInvalidDeveloperStatusQuery},
		{name: "invalid UTF-8 auth id", ids: []string{string([]byte{0xff})}, want: ErrInvalidDeveloperStatusQuery},
		{name: "missing", ids: []string{"auth-a", "auth-b"}, principals: []domain.Principal{principal(t, "auth-a", domain.PrincipalTypeUser, domain.DeveloperStatusApproved)}, want: ErrDeveloperStatusNotFound, calls: 1},
		{name: "system", ids: []string{"system"}, principals: []domain.Principal{principal(t, "system", domain.PrincipalTypeSystem, "")}, want: ErrDeveloperStatusNotFound, calls: 1},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := &repositoryStub{principals: testCase.principals}
			_, err := NewBatchGetDeveloperStatusesHandler(repository).Handle(context.Background(), testCase.ids)
			if !errors.Is(err, testCase.want) || repository.calls != testCase.calls {
				t.Fatalf("Handle() = %v, calls %d", err, repository.calls)
			}
		})
	}
}

func TestBatchGetDeveloperStatusesRejectsMalformedRepositoryResult(t *testing.T) {
	tests := []struct {
		name       string
		principals []domain.Principal
	}{
		{name: "duplicate", principals: []domain.Principal{
			principal(t, "auth-a", domain.PrincipalTypeUser, domain.DeveloperStatusApproved),
			principal(t, "auth-a", domain.PrincipalTypeUser, domain.DeveloperStatusApproved),
		}},
		{name: "unrequested", principals: []domain.Principal{
			principal(t, "auth-a", domain.PrincipalTypeUser, domain.DeveloperStatusApproved),
			principal(t, "auth-b", domain.PrincipalTypeUser, domain.DeveloperStatusApproved),
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewBatchGetDeveloperStatusesHandler(&repositoryStub{principals: testCase.principals}).Handle(context.Background(), []string{"auth-a"})
			if !errors.Is(err, port.ErrDeveloperStatusUnavailable) {
				t.Fatalf("Handle() error = %v, want ErrDeveloperStatusUnavailable", err)
			}
		})
	}
}

func authIDs(count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = fmt.Sprintf("auth-%d", index)
	}
	return values
}

func principal(t *testing.T, raw string, principalType domain.PrincipalType, status domain.DeveloperStatus) domain.Principal {
	t.Helper()
	id, err := domain.NewAuthID(raw)
	if err != nil {
		t.Fatal(err)
	}
	value, err := domain.NewPrincipal(id, principalType, status)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
