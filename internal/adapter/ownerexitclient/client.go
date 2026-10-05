package ownerexitclient

import (
	"context"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/account_owner_exit"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	d "iwut-auth-center/internal/ownerexit/domain"
	"strings"
	"time"
)

type Client struct {
	rpc pb.AccountOwnerExitServiceClient
	key oauthcrypto.Key
}

func New(conn grpc.ClientConnInterface, key oauthcrypto.Key) *Client {
	return &Client{pb.NewAccountOwnerExitServiceClient(conn), key}
}
func (c *Client) context(ctx context.Context) (context.Context, context.CancelFunc, error) {
	now := time.Now()
	token, e := oauthcrypto.Sign(c.key, "JWT", map[string]any{"iss": "iwut-auth-center", "sub": "iwut-auth-center", "aud": "iwut-app-center", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": uuid.NewString()})
	if e != nil {
		return nil, func() {}, d.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token)), cancel, nil
}
func purpose(s string) pb.Purpose {
	if s == d.Withdrawal {
		return pb.Purpose_PURPOSE_DEVELOPER_WITHDRAWAL
	}
	if s == d.Closure {
		return pb.Purpose_PURPOSE_ACCOUNT_CLOSURE
	}
	return pb.Purpose_PURPOSE_UNSPECIFIED
}
func decision(s string) pb.Decision {
	switch s {
	case d.Pending:
		return pb.Decision_DECISION_PENDING
	case d.Committed:
		return pb.Decision_DECISION_COMMITTED
	case d.Cancelled:
		return pb.Decision_DECISION_CANCELLED
	}
	return pb.Decision_DECISION_UNSPECIFIED
}
func (c *Client) Prepare(ctx context.Context, o d.Operation) (d.Preparation, error) {
	if !o.Valid() || o.Decision != d.Pending {
		return d.Preparation{}, d.ErrInvalid
	}
	ctx, cancel, e := c.context(ctx)
	if e != nil {
		return d.Preparation{}, e
	}
	defer cancel()
	r, e := c.rpc.PrepareAccountOwnerExit(ctx, &pb.PrepareAccountOwnerExitRequest{AuthId: o.AuthID, OperationId: o.OperationID, Purpose: purpose(o.Purpose)})
	if e != nil || r == nil {
		return d.Preparation{}, d.ErrUnavailable
	}
	switch r.Outcome {
	case pb.Outcome_OUTCOME_PREPARED:
		if !d.ValidReceiptID(r.ReceiptId) || r.Blocker != pb.Blocker_BLOCKER_NONE {
			return d.Preparation{}, d.ErrUnavailable
		}
		return d.Preparation{ReceiptID: r.ReceiptId}, nil
	case pb.Outcome_OUTCOME_BLOCKED:
		if r.ReceiptId != "" {
			return d.Preparation{}, d.ErrUnavailable
		}
		if r.Blocker == pb.Blocker_BLOCKER_OWNED_APPLICATIONS || r.Blocker == pb.Blocker_BLOCKER_PENDING_OWNERSHIP_CHANGE {
			return d.Preparation{Blocker: strings.TrimPrefix(r.Blocker.String(), "BLOCKER_")}, nil
		}
	}
	return d.Preparation{}, d.ErrUnavailable
}
func validate(o d.Operation, r *pb.AccountOwnerExitStatus) (d.Status, error) {
	if r == nil || r.AuthId != o.AuthID || r.OperationId != o.OperationID || r.Purpose != purpose(o.Purpose) || r.Decision != decision(o.Decision) || o.Decision == d.Pending || o.ReceiptID != "" && r.ReceiptId != o.ReceiptID || r.ReceiptId != "" && !d.ValidReceiptID(r.ReceiptId) {
		return d.Status{}, d.ErrUnavailable
	}
	cleanup := strings.TrimPrefix(r.CleanupState.String(), "CLEANUP_STATE_")
	if o.Decision == d.Cancelled || o.Purpose == d.Withdrawal {
		if cleanup != "NOT_REQUIRED" {
			return d.Status{}, d.ErrUnavailable
		}
	} else if cleanup != "PENDING" && cleanup != "COMPLETE" {
		return d.Status{}, d.ErrUnavailable
	}
	return d.Status{AuthID: r.AuthId, OperationID: r.OperationId, Purpose: o.Purpose, Decision: o.Decision, ReceiptID: r.ReceiptId, CleanupState: cleanup}, nil
}
func (c *Client) Finish(ctx context.Context, o d.Operation) (d.Status, error) {
	if !o.Valid() || o.Decision == d.Pending {
		return d.Status{}, d.ErrInvalid
	}
	ctx, cancel, e := c.context(ctx)
	if e != nil {
		return d.Status{}, e
	}
	defer cancel()
	r, e := c.rpc.FinishAccountOwnerExit(ctx, &pb.FinishAccountOwnerExitRequest{AuthId: o.AuthID, OperationId: o.OperationID, Purpose: purpose(o.Purpose), Decision: decision(o.Decision), ReceiptId: o.ReceiptID})
	if e != nil {
		return d.Status{}, d.ErrUnavailable
	}
	return validate(o, r)
}

// validateObserved is reserved for restoration: the caller knows the immutable
// tuple but has no local decision to compare. App reports facts; the consumer
// must still reconcile them with its independently durable Auth termination.
func validateObserved(o d.Operation, r *pb.AccountOwnerExitStatus) (d.Status, error) {
	if !d.ValidAuthID(o.AuthID) || !d.ValidOperationID(o.OperationID) || purpose(o.Purpose) == pb.Purpose_PURPOSE_UNSPECIFIED || o.Decision != "" || r == nil || r.AuthId != o.AuthID || r.OperationId != o.OperationID || r.Purpose != purpose(o.Purpose) || o.ReceiptID != "" && o.ReceiptID != r.ReceiptId {
		return d.Status{}, d.ErrUnavailable
	}
	switch r.Decision {
	case pb.Decision_DECISION_PENDING:
		if !d.ValidReceiptID(r.ReceiptId) || r.CleanupState != pb.CleanupState_CLEANUP_STATE_NOT_REQUIRED {
			return d.Status{}, d.ErrUnavailable
		}
		return d.Status{AuthID: o.AuthID, OperationID: o.OperationID, Purpose: o.Purpose, Decision: d.Pending, ReceiptID: r.ReceiptId, CleanupState: "NOT_REQUIRED"}, nil
	case pb.Decision_DECISION_COMMITTED:
		if !d.ValidReceiptID(r.ReceiptId) {
			return d.Status{}, d.ErrUnavailable
		}
		o.Decision = d.Committed
	case pb.Decision_DECISION_CANCELLED:
		o.Decision = d.Cancelled
	default:
		return d.Status{}, d.ErrUnavailable
	}
	return validate(o, r)
}
func (c *Client) Status(ctx context.Context, o d.Operation) (d.Status, error) {
	if !d.ValidAuthID(o.AuthID) || !d.ValidOperationID(o.OperationID) || purpose(o.Purpose) == pb.Purpose_PURPOSE_UNSPECIFIED || o.Decision != "" && (o.Decision != d.Committed && o.Decision != d.Cancelled) {
		return d.Status{}, d.ErrInvalid
	}
	ctx, cancel, e := c.context(ctx)
	if e != nil {
		return d.Status{}, e
	}
	defer cancel()
	r, e := c.rpc.GetAccountOwnerExitStatus(ctx, &pb.GetAccountOwnerExitStatusRequest{AuthId: o.AuthID, OperationId: o.OperationID})
	if e != nil {
		return d.Status{}, d.ErrUnavailable
	}
	if o.Decision == "" {
		return validateObserved(o, r)
	}
	return validate(o, r)
}
