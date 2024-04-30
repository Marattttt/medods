package auth

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"marat/medodsauth/config"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type ApiAuthenticator interface {
	Generate(id uuid.UUID) TokenPair
	Verify(accessTok []byte) bool
	Refresh(refresh []byte) (access []byte)
}

const (
	UserIdClaim      = "sub"
	ExprirationClaim = "exp"
	IssuedAtClaim    = "iat"
)

type DefaultAuthenticator struct {
	Tokens map[uuid.UUID]string
	logger *slog.Logger
	conf   *config.Config
}

func NewDefaultAuthenticator(conf *config.Config, logger *slog.Logger) DefaultAuthenticator {
	return DefaultAuthenticator{
		Tokens: make(map[uuid.UUID]string),
		logger: logger,
		conf:   conf,
	}
}

func (d DefaultAuthenticator) GeneratePair(id uuid.UUID) *TokenPair {
	var pair TokenPair

	accessRaw := GenerateAccessTok(id)
	slog.Debug("Generated access token", slog.Any("claims", accessRaw.Claims))

	accessHash, err := HashAccessTok(accessRaw)
	if err != nil {
		d.logger.Error("generating access jwt", err, slog.String("id", id.String()))
		return nil
	}
	pair.Access = accessHash

	refreshRaw := GenerateRefreshTok(id)
	slog.Debug("Generated refresh token",
		slog.String("id", refreshRaw.id.String()),
		slog.String("issuedAt", refreshRaw.issuedAt.String()),
		slog.String("expiresAt", refreshRaw.expiresAt.String()))

	refreshHash, err := HashRefreshTok(refreshRaw)
	if err != nil {
		d.logger.Error("Hashing refresh token", slog.String("err", err.Error()), slog.Any("token", refreshRaw))
	}

	pair.Refresh = refreshHash

	return &pair
}

func GenerateAccessTok(id uuid.UUID) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS512)

	claims := token.Claims.(jwt.MapClaims)
	claims[UserIdClaim] = id
	claims[ExprirationClaim] = time.Now().Add(time.Hour).Unix()
	claims[IssuedAtClaim] = time.Now().Unix()

	return token
}

func HashAccessTok(tok *jwt.Token) (string, error) {
	signed, err := tok.SignedString([]byte(config.Conf.Server.JWTSignature))
	if err != nil {
		return "", fmt.Errorf("singing with jwt from config.Conf: %w", err)
	}

	return signed, nil
}

// Refresh token used for granting access to creation of access tokens without relogin
type RefreshToken struct {
	id        uuid.UUID
	issuedAt  time.Time
	expiresAt time.Time
}

func (rt RefreshToken) Write(p []byte) (n int, err error) {
	const maxLen = 8 + 8 + 16
	if len(p) < maxLen {
		return 0, fmt.Errorf("buffer too short")
	}

	written := 0

	timeBuf := make([]byte, 16)
	binary.BigEndian.PutUint64(timeBuf[:8], uint64(rt.issuedAt.Unix()))
	binary.BigEndian.PutUint64(timeBuf[8:16], uint64(rt.expiresAt.Unix()))

	written += copy(p, timeBuf)

	// Copy into the remaining part
	written += copy(p[written:], rt.id[:])

	return written, nil
}

func GenerateRefreshTok(id uuid.UUID) RefreshToken {
	return RefreshToken{
		id:        id,
		issuedAt:  time.Now(),
		expiresAt: time.Now(),
	}
}

func HashRefreshTok(rt RefreshToken) (string, error) {
	raw := make([]byte, 72)
	n, err := rt.Write(raw)
	if err != nil {
		return "", fmt.Errorf("writing to buf of len %d: %w", len(raw), err)
	}

	_, err = rand.Read(raw[n:])
	if err != nil {
		return "", fmt.Errorf("generating random data into buffer: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword(raw, bcrypt.DefaultCost)

	// Should never happen
	if err != nil {
		panic(err)

	}

	return string(hashed), nil
}
