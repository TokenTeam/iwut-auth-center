package biz

import (
	"iwut-auth-center/internal/biz/mail"

	"github.com/google/wire"
)

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(NewAuthUsecase, NewUserUsecase, NewOauth2Usecase, mail.NewMailUsecase)
