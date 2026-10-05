package users

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
	"gorm.io/gorm"
)

// UserRow is the GORM model: one field for each column. GORM's default naming
// maps EmailEq to email_eq. stashgen reads its stash tags and writes UserRows,
// which stops compiling when this struct changes.
type UserRow struct {
	ID         int64                     `stash:"id"`
	Email      stackencrypt.Ciphertext   `stash:"email"`
	EmailEq    stackencrypt.EqualityTerm `stash:"email,equality"`
	EmailMatch stackencrypt.MatchTerm    `stash:"email,match"`
	Age        stackencrypt.Ciphertext   `stash:"age"`
	AgeEq      stackencrypt.EqualityTerm `stash:"age,equality"`
	AgeOre     stackencrypt.OreTerm      `stash:"age,ore"`
	Attrs      stackencrypt.JSONDocument `stash:"attrs,json"`
	Notes      stackencrypt.Ciphertext   `stash:"notes"`
}

func (UserRow) TableName() string { return "users" }

// GormStore encrypts before GORM sees a value. driver.Valuer gets no
// context.Context and runs one field at a time, so it cannot batch a ZeroKMS
// request or stop when the request is cancelled. An AfterFind hook works too,
// but it decrypts one row per ZeroKMS request.
type GormStore struct {
	db     *gorm.DB
	client *stackencrypt.Client
}

func NewGormStore(db *gorm.DB, client *stackencrypt.Client) *GormStore {
	return &GormStore{db: db, client: client}
}

func (s *GormStore) Create(ctx context.Context, tenant string, people ...User) error {
	cipher := s.client.Keyset(stackencrypt.KeysetName(tenant))
	rows, err := UserRows.EncryptAll(ctx, cipher, people)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).CreateInBatches(rows, 500).Error
}

func (s *GormStore) FindByEmail(ctx context.Context, tenant, email string) ([]User, error) {
	cipher := s.client.Keyset(stackencrypt.KeysetName(tenant))
	term, err := UserFields.Email.Equality(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	var rows []UserRow
	if err := s.db.WithContext(ctx).Where("email_eq = ?", term).Find(&rows).Error; err != nil {
		return nil, err
	}
	return UserRows.DecryptAll(ctx, cipher, rows)
}
