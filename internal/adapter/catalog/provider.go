package catalog

import (
	"github.com/goforj/wire"

	"iwut-auth-center/internal/scope/port"
)

var ProviderSet = wire.NewSet(
	NewHardcodedCatalog,
	wire.Bind(new(port.Catalog), new(*HardcodedCatalog)),
)
