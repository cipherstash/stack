package users

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
	"gorm.io/gorm"
)

// TableName lets GORM use the generated type as the model. Without it GORM
// would look for a table named encrypted_users.
func (EncryptedUser) TableName() string { return "users" }

// GormStore encrypts before GORM sees a value. driver.Valuer gets no
// context.Context and runs one field at a time, so it cannot batch a ZeroKMS
// request or stop when the request is cancelled.
type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) Create(ctx context.Context, cipher *stackencrypt.Cipher, people ...User) error {
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).CreateInBatches(encrypted, 500).Error
}

func (s *GormStore) FindByEmail(ctx context.Context, cipher *stackencrypt.Cipher, email string) ([]User, error) {
	query, err := Fields.Email.Query(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	var encrypted []EncryptedUser
	err = s.db.WithContext(ctx).Where("email = ?::eql_v3.query_text_search", query).Find(&encrypted).Error
	if err != nil {
		return nil, err
	}
	return Decrypt(ctx, cipher, encrypted)
}
