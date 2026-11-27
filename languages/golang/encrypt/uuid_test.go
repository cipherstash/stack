package encrypt_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// A UUID field of generated code is stored as a UUID, queried by equality,
// and read back as the field's own type: a type declared as [16]byte (as
// github.com/google/uuid.UUID is), or [16]byte itself. A pointer to one is
// nil when the value is absent, whether nil is sealed or stored as SQL NULL.
func TestGeneratedCodeStoresQueriesAndReadsAUUID(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	owner := testusers.DeviceID{0x0b, 0x0b}
	parent := testusers.DeviceID{0x0c, 0x0c}
	devices := []testusers.Device{
		{Name: "laptop", ID: testusers.DeviceID{0x01, 0x02, 15: 0xff}, Serial: [16]byte{0xaa, 15: 0x01}, Owner: &owner, Parent: &parent},
		{Name: "phone", ID: testusers.DeviceID{0x03, 0x04, 15: 0xfe}, Serial: [16]byte{0xbb, 15: 0x02}},
		{Name: "tablet", ID: testusers.DeviceID{0x01, 0x02, 15: 0xff}, Serial: [16]byte{0xaa, 15: 0x01}, Owner: &owner},
	}

	encrypted, err := testusers.EncryptDevice(ctx, cipher, devices)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		if len(e.ID.Ciphertext) == 0 || len(e.ID.Equality) == 0 || len(e.Serial.Ciphertext) == 0 || len(e.Serial.Equality) == 0 {
			t.Fatalf("row %d: outputs missing: %+v", i, e)
		}
		// A nil owner is sealed like a value; a nil parent stores nothing.
		if len(e.Owner.Ciphertext) == 0 || len(e.Owner.Equality) == 0 {
			t.Errorf("row %d: the owner is not sealed", i)
		}
		if (e.Parent == nil) != (devices[i].Parent == nil) {
			t.Errorf("row %d: parent stored %v for %v", i, e.Parent, devices[i].Parent)
		}
	}

	// Equal UUIDs give equal terms, and different ones do not.
	if !encrypted[0].ID.Equality.Equal(encrypted[2].ID.Equality) || encrypted[0].ID.Equality.Equal(encrypted[1].ID.Equality) {
		t.Error("the id's equality terms do not follow the UUID")
	}
	if !encrypted[0].Serial.Equality.Equal(encrypted[2].Serial.Equality) || encrypted[0].Serial.Equality.Equal(encrypted[1].Serial.Equality) {
		t.Error("the serial's equality terms do not follow the UUID")
	}

	// A query by equality finds the rows that hold the UUID, and no other.
	fields := testusers.DeviceFields
	probe, err := fields.ID.Eq(ctx, cipher, devices[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Equal(encrypted[0].ID.Equality) || !probe.Equal(encrypted[2].ID.Equality) || probe.Equal(encrypted[1].ID.Equality) {
		t.Error("the id query does not single out its rows")
	}
	serial, err := fields.Serial.Eq(ctx, cipher, devices[1].Serial)
	if err != nil {
		t.Fatal(err)
	}
	if !serial.Equal(encrypted[1].Serial.Equality) || serial.Equal(encrypted[0].Serial.Equality) {
		t.Error("the serial query does not single out its row")
	}
	byOwner, err := fields.Owner.Eq(ctx, cipher, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !byOwner.Equal(encrypted[0].Owner.Equality) || !byOwner.Equal(encrypted[2].Owner.Equality) || byOwner.Equal(encrypted[1].Owner.Equality) {
		t.Error("the owner query does not single out its rows")
	}
	noOwner, err := fields.Owner.EqNull(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !noOwner.Equal(encrypted[1].Owner.Equality) || noOwner.Equal(encrypted[0].Owner.Equality) {
		t.Error("the query for a nil owner does not single out its row")
	}

	// A field's own Encrypt derives the term the record stored.
	one, err := fields.ID.Encrypt(ctx, cipher, devices[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !one.Equality.Equal(encrypted[1].ID.Equality) {
		t.Error("a field's own Encrypt derives another term than the record's")
	}

	// Each UUID reads back as the field's own type.
	back, err := testusers.DecryptDevice(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, devices) {
		t.Fatalf("DecryptDevice = %+v, want %+v", back, devices)
	}

	// A column update: one field's ciphertext opens in a row.
	encrypted[0].ID = testusers.EncryptedDeviceID(one)
	again, err := testusers.DecryptDevice(ctx, cipher, encrypted[:1])
	if err != nil || again[0].ID != devices[1].ID {
		t.Fatalf("after a column update: %v %+v", err, again)
	}
}
