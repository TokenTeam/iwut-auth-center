package mongo

import (
	"github.com/goforj/wire"

	"iwut-auth-center/internal/developer/port"
)

var ProviderSet = wire.NewSet(
	NewPrincipalRepository,
	wire.Bind(new(port.PrincipalRepository), new(*PrincipalRepository)),
)
