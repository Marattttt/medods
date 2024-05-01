package models

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TokenPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

// Refresh token used for granting access to creation of access tokens without relogin
type RefreshToken struct {
	Id        uuid.UUID
	UserId    uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
	Salt      []byte
}

func (rt RefreshToken) Write(p []byte) (n int, err error) {
	const maxLen = 8 + 8 + 16
	if len(p) < maxLen {
		return 0, fmt.Errorf("buffer too short")
	}

	written := 0

	timeBuf := make([]byte, 16)
	binary.BigEndian.PutUint64(timeBuf[:8], uint64(rt.IssuedAt.Unix()))
	binary.BigEndian.PutUint64(timeBuf[8:16], uint64(rt.ExpiresAt.Unix()))

	written += copy(p, timeBuf)

	// Copy into the remaining part
	written += copy(p[written:], rt.UserId[:])

	return written, nil
}
