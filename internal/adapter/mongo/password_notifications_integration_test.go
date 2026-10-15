package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	uc "iwut-auth-center/internal/password/usecase"
	"testing"
	"time"
)

type notificationCapture struct {
	fail   bool
	calls  int
	events []string
}

func (s *notificationCapture) SendPasswordNotification(_ context.Context, _, _, event string, _ time.Time) error {
	s.calls++
	s.events = append(s.events, event)
	if s.fail {
		return errors.New("SMTP failure")
	}
	return nil
}
func TestPasswordNotificationsLeaseRetryAndFinalAck(t *testing.T) {
	f := newResetFixture(t)
	o := f.beginReset(t)
	if err := f.reset.Complete(t.Context(), o.OperationID, f.mail.code, changedPassword, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	lease := uuid.NewString()
	n, found, err := f.repository.ClaimNotification(t.Context(), lease, f.clock, time.Minute)
	if err != nil || !found {
		t.Fatal(n, found, err)
	}
	if _, found, err = f.repository.ClaimNotification(t.Context(), uuid.NewString(), f.clock, time.Minute); err != nil || found {
		t.Fatal("duplicate lease", err)
	}
	f.clock = f.clock.Add(time.Minute)
	newN, found, err := f.repository.ClaimNotification(t.Context(), uuid.NewString(), f.clock, time.Minute)
	if err != nil || !found || newN.Attempts != 2 {
		t.Fatal(newN, found, err)
	}
	if err = f.repository.FinishNotification(t.Context(), n, true, f.clock); err != nil {
		t.Fatal(err)
	}
	var row bson.M
	_ = f.r.database.Collection(PasswordNotificationCollection).FindOne(t.Context(), bson.M{"eventId": o.OperationID}).Decode(&row)
	if row["state"] != "SENDING" || row["leaseId"] != newN.LeaseID {
		t.Fatal("old lease acknowledged new send", row)
	}
	if err = f.repository.FinishNotification(t.Context(), newN, false, f.clock); err != nil {
		t.Fatal(err)
	}
	sender := &notificationCapture{}
	tasks := uc.NewNotifications(f.repository, sender, f.p, time.Second)
	tasks.SetClock(func() time.Time { return f.clock })
	if err = tasks.Tick(t.Context()); err != nil || sender.calls != 0 {
		t.Fatal("retry ran before backoff", err)
	}
	f.clock = f.clock.Add(2 * time.Minute)
	if err = tasks.Tick(t.Context()); err != nil || sender.calls != 1 {
		t.Fatal(sender.calls, err)
	}
	if err = tasks.Tick(t.Context()); err != nil || sender.calls != 1 {
		t.Fatal("repeated successful notification", err)
	}
	now := f.clock
	if err = f.r.WithAuthTransaction(t.Context(), func(ctx context.Context) error {
		record, err := f.repository.readPasswordTx(ctx, f.c.AuthID)
		if err != nil {
			return err
		}
		if record.Revision != 2 {
			t.Fatal("notification repeated password change")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !f.clock.Equal(now) {
		t.Fatal("clock changed")
	}
}
func TestPasswordNotificationsBoundedFailureAndRetention(t *testing.T) {
	f := newResetFixture(t)
	o := f.beginReset(t)
	if err := f.reset.Complete(t.Context(), o.OperationID, f.mail.code, changedPassword, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	sender := &notificationCapture{fail: true}
	tasks := uc.NewNotifications(f.repository, sender, f.p, time.Second)
	tasks.SetClock(func() time.Time { return f.clock })
	for i := 0; i < 10; i++ {
		if err := tasks.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.clock = f.clock.Add(time.Hour)
	}
	if sender.calls != 8 {
		t.Fatal("unbounded retries", sender.calls)
	}
	var row bson.M
	_ = f.r.database.Collection(PasswordNotificationCollection).FindOne(t.Context(), bson.M{"eventId": o.OperationID}).Decode(&row)
	if row["state"] != "FAILED" {
		t.Fatal(row)
	}
	f.clock = o.CreatedAt.Add(24 * time.Hour)
	if err := tasks.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{PasswordResetCollection, PasswordNotificationCollection} {
		count, _ := f.r.database.Collection(col).CountDocuments(t.Context(), bson.M{})
		if count != 0 {
			t.Fatal(col, count)
		}
	}
}
