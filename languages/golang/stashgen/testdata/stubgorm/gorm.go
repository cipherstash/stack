// Package gorm is a TEST STUB of gorm.io/gorm with the types and methods the
// example inputs name. The generator reads gorm.Model's fields through it.
package gorm

import (
	"context"
	"database/sql"
	"time"
)

type DeletedAt sql.NullTime

type Model struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt DeletedAt `gorm:"index"`
}

type DB struct{ Error error }

func (db *DB) WithContext(context.Context) *DB { return db }
func (db *DB) Create(any) *DB                  { return db }
