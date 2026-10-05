package domain

import "time"

// NamespaceReservations preserves only permanent namespace occupancy. It is
// separate from the four-field terminal fact and from the principal tombstone.
type NamespaceReservations struct {
	AuthID       string
	OperationID  string
	Fingerprints [][]byte
	Handle       *HandleReservation
}

type HandleReservation struct {
	DeveloperHandle string
	ClaimedAt       time.Time
}
