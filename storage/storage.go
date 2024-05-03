package storage

import (
	"context"
	"fmt"
)

var (
	ErrNotFound  = fmt.Errorf("Not found")
	ErrNoEffect  = fmt.Errorf("Operation made no effect")
	ErrInvalidId = fmt.Errorf("Invalid id")
)

type RefreshToken struct {
	Id string `bson:"_id,omitempty"`
	// hexadecimal encoding
	Hash string `bson:"hash,omitempty"`
}

type TokenStorage interface {
	Get(ctx context.Context, id string) (RefreshToken, error)
	Save(ctx context.Context, hash []byte) (id string, err error)
	Delete(ctx context.Context, id string) error
}
