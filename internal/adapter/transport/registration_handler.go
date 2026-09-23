package transport

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	api "iwut-auth-center/api/gen/go/auth_center/v1/authentication"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/registration/port"
)

type RegistrationUseCase interface {
	Begin(context.Context, string, []byte, string, []byte, string) (auth.Challenge, error)
	Complete(context.Context, string, []byte) (auth.Established, error)
}
type RegistrationHandler struct {
	registration    RegistrationUseCase
	maxMessageBytes int
}

func NewRegistrationHandler(registration RegistrationUseCase, maximumBytes ...int) *RegistrationHandler {
	limit := 16 * 1024
	if len(maximumBytes) > 0 && maximumBytes[0] > 0 {
		limit = maximumBytes[0]
	}
	return &RegistrationHandler{registration: registration, maxMessageBytes: limit}
}

func (h *RegistrationHandler) BeginUserRegistration(ctx context.Context, in *api.BeginUserRegistrationRequest) (*api.AuthenticationChallenge, error) {
	if in == nil || in.CredentialProposal == nil || in.Association == nil {
		return nil, registrationTransportError(port.ErrInvalidInput)
	}
	if h == nil || h.registration == nil {
		return nil, registrationTransportError(port.ErrUnavailable)
	}
	if proto.Size(in) > h.maxMessageBytes {
		return nil, registrationTransportError(port.ErrInputTooLarge)
	}
	result, err := h.registration.Begin(ctx, in.CredentialProposal.ProtocolVersion, in.CredentialProposal.PublicKey, in.Association.SchemeVersion, in.Association.AssociationToken, authenticationPeer(ctx))
	if err != nil {
		return nil, registrationTransportError(err)
	}
	return &api.AuthenticationChallenge{OperationId: result.OperationID, Challenge: result.Challenge, ProtocolVersion: result.ProtocolVersion, ExpiresAtUnixMs: result.ExpiresAt.UnixMilli(), SigningPayload: result.SigningPayload}, nil
}
func (h *RegistrationHandler) CompleteUserRegistration(ctx context.Context, in *api.CompleteUserRegistrationRequest) (*api.UserRegistrationResult, error) {
	if in == nil || in.Proof == nil {
		return nil, registrationTransportError(port.ErrProofInvalid)
	}
	if h == nil || h.registration == nil {
		return nil, registrationTransportError(port.ErrUnavailable)
	}
	if proto.Size(in) > h.maxMessageBytes || len(in.Proof.Signature) > 72 {
		return nil, registrationTransportError(port.ErrInputTooLarge)
	}
	result, err := h.registration.Complete(ctx, in.OperationId, in.Proof.Signature)
	if err != nil {
		return nil, registrationTransportError(err)
	}
	return &api.UserRegistrationResult{AuthId: result.AuthID, CredentialId: result.CredentialID, Session: &api.SessionEstablished{AuthId: result.AuthID, CredentialId: result.CredentialID, SessionId: result.SessionID, SessionToken: result.SessionToken, ExpiresAtUnixMs: result.ExpiresAt.UnixMilli()}}, nil
}

func registrationTransportError(err error) error {
	code, reason := codes.Unavailable, "REGISTRATION_UNAVAILABLE"
	switch {
	case errors.Is(err, port.ErrInvalidInput):
		code, reason = codes.InvalidArgument, "INVALID_REGISTRATION_INPUT"
	case errors.Is(err, port.ErrUnsupported):
		code, reason = codes.InvalidArgument, "REGISTRATION_SCHEME_UNSUPPORTED"
	case errors.Is(err, port.ErrProofInvalid):
		code, reason = codes.Unauthenticated, "REGISTRATION_PROOF_INVALID"
	case errors.Is(err, port.ErrAlreadyCompleted):
		code, reason = codes.AlreadyExists, "REGISTRATION_ALREADY_COMPLETED"
	case errors.Is(err, port.ErrCredentialRegistered):
		code, reason = codes.AlreadyExists, "CREDENTIAL_ALREADY_REGISTERED"
	case errors.Is(err, port.ErrRateLimited):
		code, reason = codes.ResourceExhausted, "REGISTRATION_RATE_LIMITED"
	case errors.Is(err, port.ErrInputTooLarge):
		code, reason = codes.ResourceExhausted, "REGISTRATION_INPUT_TOO_LARGE"
	}
	return transportStatus(code, reason, reason)
}
