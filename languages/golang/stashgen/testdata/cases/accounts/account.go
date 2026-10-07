// Package accounts shows an embedded struct, another library's tags, an
// unexported field, and generated print methods.
package accounts

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"gorm.io/gorm"
)

//go:generate go tool stashgen -type Account -redact

type Account struct {
	_ struct{} `stash:"context=accounts"`

	// One tag decides for every field of gorm.Model, which cannot carry tags.
	gorm.Model `stash:",passthrough"`

	// stashgen copies the gorm and json tags onto EncryptedAccount.
	Email string `stash:"email,encrypt_into=TextEq" gorm:"uniqueIndex" json:"email"`

	// An unexported field with no stash tag is ignored, and stashgen and the
	// running program both warn about it.
	cache string

	// The tag acknowledges the skip, so nothing warns.
	token string `stash:"-"`
}

func (EncryptedAccount) TableName() string { return "accounts" }

func Create(ctx context.Context, db *gorm.DB, cipher *encrypt.Cipher, accounts []Account) error {
	encrypted, err := Encrypt(ctx, cipher, accounts)
	if err != nil {
		return err
	}
	return db.WithContext(ctx).Create(&encrypted).Error
}
