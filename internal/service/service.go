package service

import (
	"iwut-auth-center/internal/service/auth"

	"github.com/google/wire"
)

// ProviderSet is service providers.
var ProviderSet = wire.NewSet(auth.NewAuthService)
