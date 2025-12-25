package service

import (
	"iwut-auth-center/internal/service/auth"
	"iwut-auth-center/internal/service/user"

	"github.com/google/wire"
)

// ProviderSet is service providers.
var ProviderSet = wire.NewSet(auth.NewAuthService, user.NewUserService)
