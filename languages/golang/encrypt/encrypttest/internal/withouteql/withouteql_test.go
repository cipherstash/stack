package withouteql_test

import (
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/eqlguest"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testmember"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testpolicy"
)

func TestRoundTripWithoutTheEQLTypes(t *testing.T) {
	if eqlguest.Linked() {
		t.Fatal("package eql is linked: this test must not import anything that names an EQL type")
	}
	client := encrypttest.NewClient(t)
	members := []testmember.Member{{ID: 1, Age: 34, Email: "ada@example.com", Notes: "first"}}
	rows, err := testpolicy.Encrypt(t.Context(), client.DefaultKeyset(), members)
	if err != nil {
		t.Fatal(err)
	}
	back, err := testpolicy.Decrypt(t.Context(), client, rows)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, members) {
		t.Fatalf("%+v, want %+v", back, members)
	}
}
