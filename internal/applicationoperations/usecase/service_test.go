package usecase

import (
	"context"
	"strings"
	"testing"
	"time"

	"iwut-auth-center/internal/applicationoperations/domain"
)

type repositoryStub struct{ command domain.Command }

func (r *repositoryStub) Manage(_ context.Context, command domain.Command) (domain.State, error) {
	r.command = command
	return domain.State{}, nil
}
func (r *repositoryStub) Get(context.Context, string, string) (domain.State, error) {
	return domain.State{}, nil
}

type limiterStub struct{ allow bool }

func (l limiterStub) AllowBegin(string, time.Time) bool    { return l.allow }
func (l limiterStub) AllowComplete(string, time.Time) bool { return l.allow }

func TestServiceValidatesAndTrimsBeforeRepository(t *testing.T) {
	repository := &repositoryStub{}
	service := New(repository, limiterStub{allow: true})
	command := domain.Command{ActorAuthID: "admin", SubjectAuthID: "user", Permission: domain.Suspend, Action: "GRANT", ExpectedRevision: 1, Reason: "  " + strings.Repeat("x", 1024) + "  "}
	if _, err := service.Manage(t.Context(), command); err != nil || repository.command.Reason != strings.Repeat("x", 1024) {
		t.Fatal(repository.command, err)
	}
	for _, permission := range []string{"", "app.*", "app.profile.review", " app.application.suspend"} {
		repository.command = domain.Command{}
		command.Permission = permission
		if _, err := service.Manage(t.Context(), command); err != domain.ErrInvalid || repository.command.ActorAuthID != "" {
			t.Fatal(permission, err, repository.command)
		}
	}
	command.Permission = domain.Restore
	command.Reason = strings.Repeat("x", 1025)
	if _, err := service.Manage(t.Context(), command); err != domain.ErrInvalid {
		t.Fatal(err)
	}
}

func TestServiceRateLimitFailsClosed(t *testing.T) {
	service := New(&repositoryStub{}, limiterStub{})
	if _, err := service.Get(t.Context(), "admin", "user"); err != domain.ErrRate {
		t.Fatal(err)
	}
}
