package usecase

import (
	"context"
	"iwut-auth-center/internal/reviewer/domain"
	"strings"
	"testing"
)

type captureRepository struct{ command domain.Command }

func (r *captureRepository) Manage(_ context.Context, c domain.Command) (domain.State, error) {
	r.command = c
	return domain.State{}, nil
}
func (r *captureRepository) Get(context.Context, string, string) (domain.State, error) {
	return domain.State{}, nil
}
func (r *captureRepository) Bootstrap(context.Context, string) (bool, error) { return false, nil }
func TestReasonTrimBeforeLimitAndAudit(t *testing.T) {
	r := &captureRepository{}
	s := New(r)
	c := domain.Command{ActorAuthID: "a", SubjectAuthID: "b", Action: "GRANT", Reason: " \n" + strings.Repeat("x", 1024) + " \t", ExpectedRevision: 1}
	if _, err := s.Manage(t.Context(), c); err != nil || r.command.Reason != strings.Repeat("x", 1024) {
		t.Fatal(err)
	}
	c.Reason = strings.Repeat("x", 1025)
	if _, err := s.Manage(t.Context(), c); err != domain.ErrInvalid {
		t.Fatal(err)
	}
}
