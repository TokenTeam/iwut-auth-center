package biz

import (
	"iwut-auth-center/internal/biz/mail"

	"github.com/google/wire"
)

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(NewAuthUsecase, mail.NewMailUsecase)
