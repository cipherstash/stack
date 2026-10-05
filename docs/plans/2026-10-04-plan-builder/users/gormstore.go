package users

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
	"gorm.io/gorm"
)

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
	rows, err := userRowPlan.EncryptAll(ctx, cipher, people)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).CreateInBatches(rows, 500).Error
}

func (s *GormStore) FindByEmail(ctx context.Context, tenant, email string) ([]User, error) {
	cipher := s.client.Keyset(stackencrypt.KeysetName(tenant))
	term, err := emailPlan.Equality(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	var rows []UserRow
	if err := s.db.WithContext(ctx).Where("email_eq = ?", term).Find(&rows).Error; err != nil {
		return nil, err
	}
	return userRowPlan.DecryptAll(ctx, cipher, rows)
}
