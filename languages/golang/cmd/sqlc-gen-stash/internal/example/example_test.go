package example

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/internal/example/db"
	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/internal/example/db/dbstash"
	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlaintextRedaction checks that printing or logging a plaintext companion
// never shows its plaintext.
func TestPlaintextRedaction(t *testing.T) {
	nickname := "secret-nickname"
	p := dbstash.PlainUser{GivenNameEql4Search: "secret-given-name", NicknameEql4: &nickname}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("user", "user", p)
	for _, out := range []string{fmt.Sprint(p), fmt.Sprintf("%+v", &p), fmt.Sprintf("%#v", p), logged.String()} {
		if strings.Contains(out, "secret") {
			t.Errorf("plaintext printed: %s", out)
		}
	}
}

// column is what every per-column value has, plaintext or encrypted.
type column interface {
	Table() string
	Column() string
	QualifiedName() string
}

// zeroOf infers a plaintext column's Go type from its Zero method, as code
// in another module that can't name dbstash.Column does.
func zeroOf[T any](c interface {
	column
	Zero() T
}) T {
	return c.Zero()
}

// The method sets that tell the kinds of encrypted column apart.
type (
	encrypted interface {
		column
		EQLType() string
		NullMode() gensupport.NullMode
	}
	textEq interface {
		Eq(ctx context.Context, c *encrypt.Cipher, v string) (eql.TextEqQuery, error)
	}
	textSearch interface {
		Lt(ctx context.Context, c *encrypt.Cipher, v string) (eql.TextSearchQuery, error)
		Gte(ctx context.Context, c *encrypt.Cipher, v string) (eql.TextSearchQuery, error)
		Matches(ctx context.Context, c *encrypt.Cipher, v string) (encrypt.EQLMatchQuery[eql.TextSearchQuery, string], error)
	}
	document interface {
		Contains(ctx context.Context, c *encrypt.Cipher, needle any) (eql.JSONSearchQuery, error)
	}
)

// Compile-time: a plaintext column's T is sqlc-gen-go's Go type for it, a
// pointer where it can be NULL.
var (
	_ pgtype.Timestamptz = zeroOf(dbstash.UserFields.CreatedAt)
	_ *uuid.UUID         = zeroOf(dbstash.UserFields.ParentID)
	_ db.UserStatus      = zeroOf(dbstash.UserFields.Status)
)

// Compile-time: a parameter cast to a query domain holds the query value a
// field entry's query method derives, a pointer for sqlc.narg.
var (
	_ eql.TextSearchQuery = db.SearchUsersParams{}.NameMatch
	_ *eql.TextEqQuery    = db.SearchUsersParams{}.Email
)

// TestFields checks the per-column values: every column of every table has
// one, including contacts, which no query returns, so that sqlc.yaml's
// omit_unused_structs leaves it without a model, a view has none, and an
// encrypted column's methods are the queries its EQL type answers, so a
// storage-only column has none.
func TestFields(t *testing.T) {
	var c column = dbstash.ContactFields.UserID
	if c.Table() != "contacts" || c.Column() != "user_id" || c.QualifiedName() != "contacts.user_id" {
		t.Errorf("ContactFields.UserID = %s, %s, %s", c.Table(), c.Column(), c.QualifiedName())
	}
	src, err := os.ReadFile("db/dbstash/stash.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "UserSummaryFields") {
		t.Error("the view user_summaries has per-column values")
	}

	f := dbstash.UserFields
	tests := []struct {
		name                           string
		col                            encrypted
		eqlType                        string
		null                           gensupport.NullMode
		textEq, textSearch, isDocument bool
	}{
		{"GivenNameEql4Search", f.GivenNameEql4Search, "TextSearch", "", false, true, false},
		{"EmailEql4Eq", f.EmailEql4Eq, "TextEq", gensupport.NullSQL, true, false, false},
		{"NicknameEql4", f.NicknameEql4, "Text", gensupport.NullSQL, false, false, false},
		{"DobEql4", f.DobEql4, "Date", gensupport.NullSQL, false, false, false},
		{"AnnotationsEql4Search", f.AnnotationsEql4Search, "JsonSearch", gensupport.NullSQL, false, false, true},
	}
	for _, tt := range tests {
		_, isTextEq := tt.col.(textEq)
		_, isTextSearch := tt.col.(textSearch)
		_, isDocument := tt.col.(document)
		if tt.col.EQLType() != tt.eqlType || tt.col.NullMode() != tt.null || isTextEq != tt.textEq || isTextSearch != tt.textSearch || isDocument != tt.isDocument {
			t.Errorf("UserFields.%s: EQLType %q, NullMode %q, TextEq %t, TextSearch %t, document %t; want %q, %q, %t, %t, %t",
				tt.name, tt.col.EQLType(), tt.col.NullMode(), isTextEq, isTextSearch, isDocument, tt.eqlType, tt.null, tt.textEq, tt.textSearch, tt.isDocument)
		}
	}
	if q := f.GivenNameEql4Search.QualifiedName(); q != "users.given_name_eql4_search" {
		t.Errorf("UserFields.GivenNameEql4Search.QualifiedName() = %q", q)
	}
}

// storedUsers is a small ciphertext store behind pgx's database interface.
// The tests run the real generated queries and conversions without a database.
type storedUsers struct {
	pgx.Tx

	rows        []*db.User
	returnedRow *db.User
}

func (s *storedUsers) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.HasPrefix(sql, "-- name: InsertUser "):
		row := &db.User{
			ID: args[0].(uuid.UUID), ParentID: args[1].(*uuid.UUID),
			CreatedAt: args[2].(pgtype.Timestamptz), Status: args[3].(db.UserStatus),
			GivenNameEql4Search: args[4].(eql.TextSearch), NicknameEql4: args[5].(*eql.Text),
			EmailEql4Eq: args[6].(*eql.TextEq), DobEql4: args[7].(*eql.Date),
			AnnotationsEql4Search: args[8].(*eql.JSONSearch),
		}
		s.rows = append(s.rows, row)
		if s.returnedRow != nil {
			row = s.returnedRow
		}

		return userValues(row)
	case strings.HasPrefix(sql, "-- name: GetUser "):
		for _, row := range s.rows {
			if row.ID == args[0].(uuid.UUID) {
				return userValues(row)
			}
		}

		return storedRow(nil)
	case strings.HasPrefix(sql, "-- name: FindUserEmail "):
		// Echo the scalar ciphertext independently of EQL's equality operators.
		return storedRow(args)
	default:
		panic("unexpected query: " + sql)
	}
}

func userValues(row *db.User) storedRow {
	return storedRow{row.ID, row.ParentID, row.CreatedAt, row.Status, row.GivenNameEql4Search,
		row.NicknameEql4, row.EmailEql4Eq, row.DobEql4, row.AnnotationsEql4Search}
}

func (s *storedUsers) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.HasPrefix(sql, "-- name: ListUserNames ") {
		panic("unexpected query: " + sql)
	}
	rows := &storedRows{}
	for _, row := range s.rows {
		rows.remaining = append(rows.remaining, storedRow{row.ID, row.GivenNameEql4Search})
	}

	return rows, nil
}

func (s *storedUsers) SendBatch(_ context.Context, batch *pgx.Batch) pgx.BatchResults {
	for _, query := range batch.QueuedQueries {
		if !strings.HasPrefix(query.SQL, "-- name: SetUserNicknames ") {
			panic("unexpected batch query: " + query.SQL)
		}
		for _, row := range s.rows {
			if row.ID == query.Arguments[1].(uuid.UUID) {
				row.NicknameEql4 = query.Arguments[0].(*eql.Text)
			}
		}
	}

	return &storedBatch{}
}

type storedRow []any

func (r storedRow) Scan(dest ...any) error {
	if r == nil {
		return pgx.ErrNoRows
	}
	for i, value := range r {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}

	return nil
}

type storedRows struct {
	pgx.Rows

	remaining []storedRow
	current   storedRow
}

func (r *storedRows) Next() bool {
	if len(r.remaining) == 0 {
		return false
	}
	r.current, r.remaining = r.remaining[0], r.remaining[1:]

	return true
}

func (r *storedRows) Scan(dest ...any) error { return r.current.Scan(dest...) }
func (*storedRows) Close()                   {}
func (*storedRows) Err() error               { return nil }

type storedBatch struct{ pgx.BatchResults }

func (*storedBatch) Exec() (pgconn.CommandTag, error) { return pgconn.NewCommandTag("UPDATE 1"), nil }
func (*storedBatch) Close() error                     { return nil }

func TestQueryMethods(t *testing.T) {
	client := encrypttest.NewClient(t)
	a := client.Keyset(encrypt.KeysetName("tenant-a"))
	b := client.Keyset(encrypt.KeysetName("tenant-b"))
	type cipherKey struct{}
	ctxA := context.WithValue(t.Context(), cipherKey{}, a)
	ctxB := context.WithValue(t.Context(), cipherKey{}, b)
	store := &storedUsers{}
	errNoCipher := errors.New("no cipher")
	q := dbstash.New(store, func(ctx context.Context) (*encrypt.Cipher, error) {
		c, ok := ctx.Value(cipherKey{}).(*encrypt.Cipher)
		if !ok {
			return nil, errNoCipher
		}

		return c, nil
	})
	nickname, email := "Málaga", "alice@example.test"
	p := &dbstash.PlainInsertUserParams{
		ID: uuid.New(), Status: db.UserStatusActive, GivenNameEql4Search: "Alice",
		NicknameEql4: &nickname, EmailEql4Eq: &email,
	}

	// A missing cipher must fail with the lookup's error before the store changes.
	_, err := q.InsertUser(t.Context(), p)
	require.ErrorIs(t, err, errNoCipher)
	require.Empty(t, store.rows)

	_, err = q.InsertUser(ctxA, nil)
	require.Error(t, err)
	_, err = q.SetUserNicknames(ctxA, []*dbstash.PlainSetUserNicknamesParams{nil})
	require.Error(t, err)
	require.Empty(t, store.rows)

	row, err := q.InsertUser(ctxA, p)
	require.NoError(t, err)
	assert.Equal(t, &dbstash.PlainUser{
		ID: p.ID, Status: db.UserStatusActive, GivenNameEql4Search: "Alice",
		NicknameEql4: &nickname, EmailEql4Eq: &email,
	}, row)
	require.Len(t, store.rows, 1)
	require.NotNil(t, store.rows[0].NicknameEql4)
	assert.Nil(t, store.rows[0].DobEql4)
	assert.Nil(t, store.rows[0].AnnotationsEql4Search)
	stored, err := q.GetUser(ctxA, p.ID)
	require.NoError(t, err)
	assert.Equal(t, row, stored)

	// The manual API remains available alongside automatic query methods.
	sealed, err := dbstash.EncryptInsertUserParams(ctxA, a, p)
	require.NoError(t, err)
	manualRow := db.User(*sealed)
	opened, err := dbstash.DecryptUser(ctxA, a, []*db.User{&manualRow})
	require.NoError(t, err)
	require.Equal(t, []*dbstash.PlainUser{row}, opened)
	sealedRows, err := dbstash.EncryptUser(ctxA, a, opened)
	require.NoError(t, err)
	opened, err = dbstash.DecryptUser(ctxA, a, sealedRows)
	require.NoError(t, err)
	assert.Equal(t, []*dbstash.PlainUser{row}, opened)
	_, err = dbstash.DecryptUser(ctxB, b, sealedRows)
	require.ErrorIs(t, err, encrypt.ErrForeignKeyset)

	// SQL errors retain their identity, and are not result-decryption errors.
	_, err = q.GetUser(ctxA, uuid.New())
	require.ErrorIs(t, err, pgx.ErrNoRows)
	var resultErr *dbstash.ResultDecryptionError
	assert.NotErrorAs(t, err, &resultErr)
	rows, err := q.ListUserNames(ctxA)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, p.ID, rows[0].ID)
	assert.Equal(t, "Alice", rows[0].Name)
	openedEmail, err := q.FindUserEmail(ctxA, &email)
	require.NoError(t, err)
	assert.Equal(t, &email, openedEmail)
	openedEmail, err = q.FindUserEmail(ctxA, nil)
	require.NoError(t, err)
	assert.Nil(t, openedEmail)

	// The same wrapper must obtain B's cipher from this call's context, not
	// reuse A's. B can read its own row, but cannot read A's row.
	bParams := &dbstash.PlainInsertUserParams{ID: uuid.New(), GivenNameEql4Search: "Bob"}
	bRow, err := q.InsertUser(ctxB, bParams)
	require.NoError(t, err)
	assert.Equal(t, "Bob", bRow.GivenNameEql4Search)
	assert.Nil(t, bRow.NicknameEql4)
	_, err = q.GetUser(ctxA, bParams.ID)
	require.ErrorIs(t, err, encrypt.ErrForeignKeyset)
	_, err = q.GetUser(ctxB, p.ID)
	require.ErrorIs(t, err, encrypt.ErrForeignKeyset)
	require.ErrorAs(t, err, &resultErr)
	assert.Equal(t, "GetUser", resultErr.Query)

	// A result error is explicitly after execution: the new row persists
	// even though the returned ciphertext belongs to another keyset.
	store.returnedRow = store.rows[1]
	third := &dbstash.PlainInsertUserParams{ID: uuid.New(), GivenNameEql4Search: "Carol"}
	_, err = q.InsertUser(ctxA, third)
	require.ErrorAs(t, err, &resultErr)
	require.ErrorIs(t, err, encrypt.ErrForeignKeyset)
	assert.Equal(t, "InsertUser", resultErr.Query)
	require.Len(t, store.rows, 3)
	assert.Equal(t, third.ID, store.rows[2].ID)

	// A nil error and a non-nil cipher are both required before SQL execution.
	for _, tt := range []struct {
		name   string
		cipher *encrypt.Cipher
		err    error
	}{
		{name: "nil cipher without an error"},
		{name: "cipher with an error", cipher: a, err: errNoCipher},
	} {
		t.Run(tt.name, func(t *testing.T) {
			failing := dbstash.New(store, func(context.Context) (*encrypt.Cipher, error) { return tt.cipher, tt.err })
			_, err := failing.InsertUser(ctxA, p)
			require.Error(t, err)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			}
			require.Len(t, store.rows, 3)
		})
	}

	// Batch parameter conversion can clear one value and populate another.
	_, err = q.SetUserNicknames(ctxA, []*dbstash.PlainSetUserNicknamesParams{
		{ID: p.ID},
		{ID: third.ID, NicknameEql4: &nickname},
	})
	require.NoError(t, err)
	row, err = q.GetUser(ctxA, p.ID)
	require.NoError(t, err)
	assert.Nil(t, row.NicknameEql4)
	row, err = q.GetUser(ctxA, third.ID)
	require.NoError(t, err)
	assert.Equal(t, &nickname, row.NicknameEql4)

	// WithTx must keep the conversion methods and cipher lookup while routing
	// SQL to the transaction, not the original connection.
	tx := &storedUsers{}
	transactionQueries := q.WithTx(tx)
	row, err = transactionQueries.InsertUser(ctxA, p)
	require.NoError(t, err)
	assert.Equal(t, "Alice", row.GivenNameEql4Search)
	require.Len(t, tx.rows, 1)
	assert.Len(t, store.rows, 3)
	_, err = transactionQueries.GetUser(ctxB, p.ID)
	require.ErrorIs(t, err, encrypt.ErrForeignKeyset)
	_, err = q.GetUser(ctxA, bParams.ID)
	require.ErrorIs(t, err, encrypt.ErrForeignKeyset)
}
