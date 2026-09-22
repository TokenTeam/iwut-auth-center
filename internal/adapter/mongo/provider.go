package mongo

import (
	"github.com/goforj/wire"

	"iwut-auth-center/internal/developer/port"
	systemprincipalport "iwut-auth-center/internal/systemprincipal/port"
)

var ProviderSet = wire.NewSet(
	NewPrincipalRepository,
	wire.Bind(new(port.PrincipalRepository), new(*PrincipalRepository)),
	NewSystemPrincipalRepository,
	wire.Bind(new(systemprincipalport.Repository), new(*SystemPrincipalRepository)),
)
