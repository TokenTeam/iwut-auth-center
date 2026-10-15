package mongo

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/academicyear/domain"
)

func TestAcademicYearDocumentRoundTripsNanoseconds(t *testing.T) {
	anchor := time.Date(2027, time.February, 20, 1, 2, 3, 456789123, time.FixedZone("Shanghai", 8*60*60))
	updated := time.Date(2026, time.October, 10, 0, 0, 0, 321000000, time.UTC)
	state := d.State{AnchorAt: anchor, AnchorAcademicYear: 2027, Revision: 2, UpdatedAt: updated, UpdatedByAuthID: "admin"}
	encoded, err := bson.Marshal(academicYearDocument(state))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAcademicYearState(bson.Raw(encoded))
	if err != nil || !decoded.AnchorAt.Equal(anchor) || decoded.AnchorAt.Nanosecond() != anchor.Nanosecond() {
		t.Fatalf("round trip = %#v, %v", decoded, err)
	}
}

func TestDecodeAcademicYearStateRejectsMissingManualAttribution(t *testing.T) {
	state := d.State{AnchorAt: time.Date(2027, time.September, 1, 0, 0, 0, 0, time.UTC), AnchorAcademicYear: 2027, Revision: 2, UpdatedAt: time.Now().UTC()}
	encoded, err := bson.Marshal(academicYearDocument(state))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAcademicYearState(bson.Raw(encoded)); err == nil {
		t.Fatal("manual state without actor attribution was accepted")
	}
}
