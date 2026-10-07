package encrypt_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testmember"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testpolicy"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The generator writes a file three ways: from a struct's own tags, from
// tags declared for a type in another package (-for), and from a policy
// (stashgen.Generate). The golden tests only compile the second and third;
// this runs them against the deterministic guest, beside the tag path, for
// one declaration (testusers.User's) over one set of values, and holds the
// three to the same bytes.

var members = []testmember.Member{
	{ID: 1, Age: 34, Email: "alice@example.com", Notes: "likes cats"},
	{ID: 2, Age: 29, Email: "bob@example.com", Notes: "likes dogs"},
}

func asUsers(ms []testmember.Member) []testusers.User {
	out := make([]testusers.User, len(ms))
	for i, m := range ms {
		out[i] = testusers.User{ID: m.ID, Age: m.Age, Email: m.Email, Notes: m.Notes}
	}
	return out
}

func TestGeneratedCodeFromForAndFromAPolicyRunsAgainstTheGuest(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	tagged, err := testusers.Encrypt(ctx, cipher, asUsers(members))
	if err != nil {
		t.Fatal(err)
	}
	forPath, err := testusers.EncryptMember(ctx, cipher, members)
	if err != nil {
		t.Fatalf("the -for path: %v", err)
	}
	policyPath, err := testpolicy.Encrypt(ctx, cipher, members)
	if err != nil {
		t.Fatalf("the policy path: %v", err)
	}

	// One declaration, three authors, the same terms.
	for i := range members {
		for name, got := range map[string]struct{ ageEq, ageOre, emailEq, emailMatch []byte }{
			"the -for path":   {forPath[i].Age.Equality, forPath[i].Age.Ore, forPath[i].Email.Equality, forPath[i].Email.Match},
			"the policy path": {policyPath[i].Age.Equality, policyPath[i].Age.Ore, policyPath[i].Email.Equality, policyPath[i].Email.Match},
		} {
			want := tagged[i]
			if !bytes.Equal(got.ageEq, want.Age.Equality) || !bytes.Equal(got.ageOre, want.Age.Ore) || !bytes.Equal(got.emailEq, want.Email.Equality) || !bytes.Equal(got.emailMatch, want.Email.Match) {
				t.Errorf("row %d: %s derives other terms than the tag path", i, name)
			}
		}
		if len(forPath[i].Notes.Ciphertext) == 0 || len(policyPath[i].Notes.Ciphertext) == 0 || forPath[i].ID != members[i].ID || policyPath[i].ID != members[i].ID {
			t.Errorf("row %d: outputs missing: %+v %+v", i, forPath[i], policyPath[i])
		}
	}

	// Each path opens its own rows, through the cipher and the client.
	for _, d := range []struct {
		name string
		by   encrypt.Decrypter
	}{{"cipher", cipher}, {"client", c}} {
		back, err := testusers.DecryptMember(ctx, d.by, forPath)
		if err != nil {
			t.Fatalf("DecryptMember through the %s: %v", d.name, err)
		}
		for i := range members {
			if back[i] != members[i] {
				t.Fatalf("the -for path through the %s: row %d = %+v, want %+v", d.name, i, back[i], members[i])
			}
		}
		back, err = testpolicy.Decrypt(ctx, d.by, policyPath)
		if err != nil {
			t.Fatalf("testpolicy.Decrypt through the %s: %v", d.name, err)
		}
		for i := range members {
			if back[i] != members[i] {
				t.Fatalf("the policy path through the %s: row %d = %+v, want %+v", d.name, i, back[i], members[i])
			}
		}
	}

	// And each opens the tag path's rows: the stored shape is one shape.
	crossed := make([]testusers.EncryptedMember, len(tagged))
	for i, e := range tagged {
		crossed[i] = testusers.EncryptedMember{
			ID:    e.ID,
			Age:   testusers.EncryptedMemberAge(e.Age),
			Email: testusers.EncryptedMemberEmail(e.Email),
			Notes: testusers.EncryptedMemberNotes(e.Notes),
		}
	}
	if back, err := testusers.DecryptMember(ctx, cipher, crossed); err != nil || back[0] != members[0] {
		t.Fatalf("the -for path opening the tag path's rows: %v %+v", err, back)
	}
	viaPolicy := make([]testpolicy.EncryptedMember, len(tagged))
	for i, e := range tagged {
		viaPolicy[i] = testpolicy.EncryptedMember{
			ID:    e.ID,
			Age:   testpolicy.EncryptedMemberAge(e.Age),
			Email: testpolicy.EncryptedMemberEmail(e.Email),
			Notes: testpolicy.EncryptedMemberNotes(e.Notes),
		}
	}
	if back, err := testpolicy.Decrypt(ctx, cipher, viaPolicy); err != nil || back[1] != members[1] {
		t.Fatalf("the policy path opening the tag path's rows: %v %+v", err, back)
	}

	// A term derived through each path's Fields is the tag path's.
	probe, err := testusers.Fields.Email.Equality(ctx, cipher, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	forProbe, err := testusers.MemberFields.Email.Equality(ctx, cipher, "bob@example.com")
	if err != nil || !forProbe.Equal(probe) {
		t.Fatalf("the -for path's probe: %v, equal=%v", err, forProbe.Equal(probe))
	}
	policyProbe, err := testpolicy.Fields.Email.Equality(ctx, cipher, "bob@example.com")
	if err != nil || !policyProbe.Equal(probe) {
		t.Fatalf("the policy path's probe: %v, equal=%v", err, policyProbe.Equal(probe))
	}
	ore, err := testpolicy.Fields.Age.Ore(ctx, cipher, 29)
	if err != nil || !bytes.Equal(ore, tagged[1].Age.Ore) {
		t.Fatalf("the policy path's ORE probe: %v", err)
	}
	if !probe.Equal(tagged[1].Email.Equality) || probe.Equal(tagged[0].Email.Equality) {
		t.Error("the probe does not single out bob's row")
	}
}
