package util

import "github.com/google/wire"

// ProviderSet for wire DI (keep minimal wiring)
var ProviderSet = wire.NewSet(NewJwtUtil)
