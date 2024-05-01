package storage

import (
	"fmt"
	"marat/medodsauth/models"
	"time"
)

var (
	ErrNotFound = fmt.Errorf("Not found")
	ErrExpired  = fmt.Errorf("Expired")
	IMS         = new(InMemoryStorage)
)

type TokenStorage interface {
	Save(hash string, token models.RefreshToken) error
	Get(hash string) (models.RefreshToken, error)
	Delete(hash string)
}

type InMemoryStorage struct {
	Tokens map[string]models.RefreshToken
}

func (ims *InMemoryStorage) Save(hash string, token models.RefreshToken) error {
	if ims.Tokens == nil {
		ims.Tokens = make(map[string]models.RefreshToken)
	}
	ims.Tokens[hash] = token

	return nil
}

func (ims *InMemoryStorage) Delete(hash string) {
	if ims.Tokens == nil {
		ims.Tokens = make(map[string]models.RefreshToken)
	}
	delete(ims.Tokens, hash)
}

func (ims *InMemoryStorage) Get(hash string) (models.RefreshToken, error) {
	if ims.Tokens == nil {
		ims.Tokens = make(map[string]models.RefreshToken)
	}
	found, ok := ims.Tokens[hash]

	if !ok {
		return models.RefreshToken{}, ErrNotFound
	}

	if time.Now().After(found.ExpiresAt) {
		delete(ims.Tokens, hash)
		return models.RefreshToken{}, ErrExpired
	}

	return found, nil
}
