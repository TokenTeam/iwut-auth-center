package usecase

import (
	"context"
	"crypto/subtle"
	"errors"
	d "iwut-auth-center/internal/accountclosure/domain"
	p "iwut-auth-center/internal/accountclosure/port"
	owner "iwut-auth-center/internal/ownerexit/domain"
	op "iwut-auth-center/internal/ownerexit/port"
	"sync"
	"time"
)

type Service struct {
	repo                              p.Repository
	protocol                          p.Protocol
	app                               op.App
	owners                            op.Repository
	ledger                            p.TerminationLedger
	serviceID                         string
	clock                             func() time.Time
	mu                                sync.Mutex
	buckets                           map[string]bucket
	readLimit, writeLimit, maxBuckets int
}
type bucket struct {
	at time.Time
	n  int
}

func New(r p.Repository, protocol p.Protocol, app op.App, owners op.Repository, ledger p.TerminationLedger, serviceID string) (*Service, error) {
	if r == nil || protocol == nil || app == nil || owners == nil || ledger == nil || serviceID == "" {
		return nil, d.ErrUnavailable
	}
	return &Service{repo: r, protocol: protocol, app: app, owners: owners, ledger: ledger, serviceID: serviceID, clock: time.Now, buckets: map[string]bucket{}, readLimit: 30, writeLimit: 10, maxBuckets: 4096}, nil
}
func (s *Service) ConfigureLimits(read, write, buckets int) error {
	if read < 1 || write < 1 || buckets < 1 || read > 1000000 || write > 1000000 || buckets > 1000000 {
		return d.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readLimit = read
	s.writeLimit = write
	s.maxBuckets = buckets
	return nil
}
func (s *Service) SetClock(c func() time.Time) { s.clock = c }
func (s *Service) now() time.Time              { return s.clock().UTC().Truncate(time.Millisecond) }
func (s *Service) rate(id string, read bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	limit := s.writeLimit
	if read {
		limit = s.readLimit
		id = "read:" + id
	}
	b, ok := s.buckets[id]
	if !ok {
		for k, v := range s.buckets {
			if now.Sub(v.at) >= time.Minute {
				delete(s.buckets, k)
			}
		}
		if len(s.buckets) >= s.maxBuckets {
			return false
		}
	}
	if now.Sub(b.at) >= time.Minute {
		b = bucket{at: now}
	}
	if b.n >= limit {
		return false
	}
	b.n++
	s.buckets[id] = b
	return true
}
func (s *Service) Begin(ctx context.Context, in d.BeginInput) (d.Challenge, error) {
	if !owner.ValidOperationID(in.RequestID) || (in.CredentialID == "") == (len(in.PublicKeyFingerprint) == 0) {
		return d.Challenge{}, d.ErrInvalid
	}
	kind := "CREDENTIAL_ID"
	value := []byte(in.CredentialID)
	if in.CredentialID != "" {
		if !owner.ValidOperationID(in.CredentialID) {
			return d.Challenge{}, d.ErrInvalid
		}
	} else {
		kind = "PUBLIC_KEY_FINGERPRINT"
		value = in.PublicKeyFingerprint
		if len(value) != 32 {
			return d.Challenge{}, d.ErrInvalid
		}
	}
	id, e := s.protocol.NewID()
	if e != nil {
		return d.Challenge{}, d.ErrUnavailable
	}
	challenge, e := s.protocol.RandomBytes(32)
	if e != nil {
		return d.Challenge{}, d.ErrUnavailable
	}
	now := s.now()
	o, e := s.repo.Begin(ctx, d.Operation{OperationID: id, RequestID: in.RequestID, LocatorKind: kind, LocatorValue: value, Challenge: challenge, ServiceID: s.serviceID, ApplicationID: "iwut-client", PolicyVersion: d.PolicyVersion, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), RetainUntil: now.Add(24 * time.Hour), State: d.Preparing})
	if e != nil {
		return d.Challenge{}, e
	}
	payload, e := s.protocol.SigningPayload(o.Proof())
	if e != nil {
		return d.Challenge{}, d.ErrUnavailable
	}
	return d.Challenge{OperationID: o.OperationID, Challenge: o.Challenge, SigningPayload: payload, ExpiresAt: o.ExpiresAt, ServiceID: o.ServiceID, ApplicationID: o.ApplicationID, PolicyVersion: o.PolicyVersion}, nil
}
func (s *Service) Prepare(ctx context.Context, id string, signature []byte) (d.Preparation, error) {
	if !owner.ValidOperationID(id) || len(signature) < 8 || len(signature) > 72 {
		return d.Preparation{}, d.ErrInvalid
	}
	o, e := s.repo.Read(ctx, id)
	if e != nil {
		if errors.Is(e, d.ErrToken) {
			return d.Preparation{}, d.ErrProof
		}
		return d.Preparation{}, e
	}
	payload, e := s.protocol.SigningPayload(o.Proof())
	valid := e == nil && o.Acceptable && o.FailedAttempts < 5 && s.now().Before(o.ExpiresAt) && s.protocol.Verify(o.PublicKey, payload, signature)
	if !valid {
		if e = s.repo.FailProof(ctx, id, s.now()); e != nil && !errors.Is(e, d.ErrProof) {
			return d.Preparation{}, e
		}
		return d.Preparation{}, d.ErrProof
	}
	if !s.rate(o.AuthID, false) {
		return d.Preparation{}, d.ErrRate
	}
	o, owned, e := s.repo.Prepare(ctx, id, s.now())
	if e != nil {
		return d.Preparation{}, e
	}
	result := d.Preparation{OperationID: id, Outcome: "PREPARING", Blocker: o.Blocker}
	if o.Blocker != "" {
		result.Outcome = "BLOCKED"
		return result, nil
	}
	if owned.OperationID == "" {
		return result, nil
	}
	prep, e := s.app.Prepare(ctx, owned)
	if e != nil {
		return d.Preparation{}, d.ErrUnavailable
	}
	owned, e = s.owners.BindPreparation(ctx, o.AuthID, id, prep, s.now())
	if e != nil {
		return d.Preparation{}, d.ErrUnavailable
	}
	if prep.Blocker != "" {
		result.Outcome = "BLOCKED"
		result.Blocker = prep.Blocker
		return result, nil
	}
	if owned.Decision != owner.Pending {
		return d.Preparation{}, d.ErrConflict
	}
	confirmation, cd, e := s.protocol.NewToken(d.ConfirmationToken)
	if e != nil {
		return d.Preparation{}, d.ErrUnavailable
	}
	receipt, rd, e := s.protocol.NewToken(d.ReceiptToken)
	if e != nil {
		return d.Preparation{}, d.ErrUnavailable
	}
	o, e = s.repo.Ready(ctx, id, cd, rd, s.now())
	if e != nil {
		return d.Preparation{}, e
	}
	result.Outcome = "READY"
	result.ConfirmationToken = confirmation
	result.ReceiptToken = receipt
	result.Preview = &d.Preview{AuthID: o.AuthID, DeveloperHandle: o.DeveloperHandle, PolicyVersion: d.PolicyVersion, Irreversible: true, ExpiresAt: o.ExpiresAt, AuditRetentionDays: 180, BackupRetentionDays: 30, DataToDelete: []string{"profile, email, credentials and sessions", "OAuth grants, tokens and pairwise subjects", "student association membership and App personal state"}, PermanentRetention: []string{"minimal closed account and termination ledger", "device key fingerprint and developer handle occupancy", "minimal cross-service terminal decision"}}
	return result, nil
}
func (s *Service) Confirm(ctx context.Context, id, token, confirmation, policy string) (d.Status, error) {
	if !owner.ValidOperationID(id) || confirmation != "CLOSE_ACCOUNT" || policy != d.PolicyVersion {
		return d.Status{}, d.ErrInvalid
	}
	digest, e := s.protocol.TokenDigest(d.ConfirmationToken, token)
	if e != nil {
		return d.Status{}, d.ErrToken
	}
	if e = s.authorizeWrite(ctx, id, digest); e != nil {
		return d.Status{}, e
	}
	o, e := s.repo.Confirm(ctx, id, digest, s.now())
	if e != nil {
		return d.Status{}, e
	}
	if !o.LedgerConfirmed {
		if e = s.storeTermination(ctx, o.Termination()); e == nil {
			e = s.repo.MarkLedger(ctx, o.Termination())
			if e == nil {
				o.LedgerConfirmed = true
			}
		}
	}
	return s.status(ctx, o), nil
}
func (s *Service) Cancel(ctx context.Context, id, token string) (d.Status, error) {
	if !owner.ValidOperationID(id) {
		return d.Status{}, d.ErrInvalid
	}
	digest, e := s.protocol.TokenDigest(d.ConfirmationToken, token)
	if e != nil {
		return d.Status{}, d.ErrToken
	}
	if e = s.authorizeWrite(ctx, id, digest); e != nil {
		return d.Status{}, e
	}
	o, e := s.repo.Cancel(ctx, id, digest, s.now())
	if e != nil {
		return d.Status{}, e
	}
	return s.status(ctx, o), nil
}
func (s *Service) Get(ctx context.Context, id, token string) (d.Status, error) {
	if !owner.ValidOperationID(id) {
		return d.Status{}, d.ErrInvalid
	}
	digest, e := s.protocol.TokenDigest(d.ReceiptToken, token)
	if e != nil {
		return d.Status{}, d.ErrToken
	}
	o, e := s.repo.Receipt(ctx, id, digest, s.now())
	if e != nil {
		return d.Status{}, e
	}
	if !s.rate(o.AuthID, true) {
		return d.Status{}, d.ErrRate
	}
	return s.status(ctx, o), nil
}
func (s *Service) status(ctx context.Context, o d.Operation) d.Status {
	result := d.Status{State: o.State, CleanupProgress: "NOT_STARTED", TerminatedAt: o.TerminatedAt}
	if o.TerminatedAt == nil {
		return result
	}
	at := o.TerminatedAt.Add(30 * 24 * time.Hour)
	result.BackupExpiryUpperBound = &at
	result.State = d.TerminationPending
	result.CleanupProgress = "AUTH_PENDING"
	if o.LedgerConfirmed {
		result.State = d.Terminated
	}
	if o.LocalCleanupComplete {
		result.CleanupProgress = "APP_PENDING"
		owned, e := s.owners.Get(ctx, o.AuthID, o.OperationID)
		if e == nil && owned.Decision == owner.Committed && owned.AppAcknowledged && owned.AppCleanupState == "COMPLETE" {
			result.CleanupProgress = "COMPLETE"
			if o.LedgerConfirmed {
				result.State = d.CleanupComplete
			}
		}
	}
	return result
}

// Reconcile always runs before listeners, independently of public entry flags.
// Every committed local fact must be durably exported before traffic is accepted.
func (s *Service) Reconcile(ctx context.Context) error {
	return ReconcileTerminations(ctx, s.repo, s.ledger, s.now())
}
func ReconcileTerminations(ctx context.Context, repo p.Repository, ledger p.TerminationLedger, now time.Time) error {
	if repo == nil || ledger == nil {
		return d.ErrUnavailable
	}
	records, e := ledger.Records(ctx)
	if e != nil {
		return d.ErrUnavailable
	}
	if e = repo.VerifyLedger(ctx, records); e != nil {
		return e
	}
	for _, record := range records {
		names, e := ledger.Reservations(ctx, record.OperationID)
		if e != nil {
			return d.ErrUnavailable
		}
		if e = repo.ReplayReservations(ctx, names); e != nil {
			return e
		}
		if e = repo.Replay(ctx, record); e != nil {
			return e
		}
	}
	for {
		ops, e := repo.Pending(ctx, now, 500)
		if e != nil {
			return e
		}
		missing := false
		for _, o := range ops {
			if !o.LedgerConfirmed {
				missing = true
				if e = storeTermination(ctx, repo, ledger, o.Termination()); e != nil {
					return d.ErrUnavailable
				}
				if e = repo.MarkLedger(ctx, o.Termination()); e != nil {
					return e
				}
			}
		}
		if !missing {
			return nil
		}
	}
}
func (s *Service) Tick(ctx context.Context) error {
	ops, e := s.repo.Pending(ctx, s.now(), 500)
	if e != nil {
		return e
	}
	var failure error
	for _, o := range ops {
		if o.TerminatedAt == nil {
			continue
		}
		if e = s.repo.Attempt(ctx, o.OperationID, s.now()); e != nil {
			failure = e
			continue
		}
		if !o.LedgerConfirmed {
			if e = s.storeTermination(ctx, o.Termination()); e != nil {
				failure = d.ErrUnavailable
				continue
			}
			if e = s.repo.MarkLedger(ctx, o.Termination()); e != nil {
				failure = e
				continue
			}
		}
		owned, oe := s.owners.Get(ctx, o.AuthID, o.OperationID)
		if oe != nil || owned.Decision != owner.Committed {
			remote, re := s.app.Status(ctx, owner.Operation{AuthID: o.AuthID, OperationID: o.OperationID, Purpose: owner.Closure})
			if re != nil {
				failure = d.ErrUnavailable
				continue
			}
			if re = s.repo.RecoverOwner(ctx, o.Termination(), remote); re != nil {
				failure = re
				continue
			}
		}
		if s.now().Sub(*o.TerminatedAt) > 24*time.Hour {
			failure = d.ErrOverdue
		}
		if _, e = s.repo.Cleanup(ctx, o.OperationID, s.now(), 500); e != nil {
			failure = e
		}
	}
	if e = s.repo.Retain(ctx, s.now(), 500); e != nil {
		failure = e
	}
	return failure
}

func (s *Service) storeTermination(ctx context.Context, t d.Termination) error {
	return storeTermination(ctx, s.repo, s.ledger, t)
}
func storeTermination(ctx context.Context, repo p.Repository, ledger p.TerminationLedger, t d.Termination) error {
	names, e := ledger.Reservations(ctx, t.OperationID)
	if errors.Is(e, p.ErrReservationsNotFound) {
		names, e = repo.CaptureReservations(ctx, t)
		if e != nil {
			return e
		}
		if e = ledger.StoreReservations(ctx, names); e != nil {
			return d.ErrUnavailable
		}
	} else if e != nil {
		return d.ErrUnavailable
	}
	if names.AuthID != t.AuthID || names.OperationID != t.OperationID {
		return d.ErrUnavailable
	}
	return ledger.Store(ctx, t)
}

func (s *Service) authorizeWrite(ctx context.Context, id string, digest []byte) error {
	o, e := s.repo.Read(ctx, id)
	if e != nil {
		return e
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, o.ConfirmationDigest) != 1 || !s.now().Before(o.RetainUntil) {
		return d.ErrToken
	}
	if !s.rate(o.AuthID, false) {
		return d.ErrRate
	}
	return nil
}
