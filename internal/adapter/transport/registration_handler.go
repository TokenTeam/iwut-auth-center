package transport

import api "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"

// RegistrationHandler retains the old RPC names only to report UNIMPLEMENTED.
// USER creation is exclusively owned by the verified email registration flow.
type RegistrationHandler struct {
	api.UnimplementedAuthenticationServiceServer
}

func NewRegistrationHandler() *RegistrationHandler { return &RegistrationHandler{} }
