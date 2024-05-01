package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"marat/medodsauth/config"
	"marat/medodsauth/models"
	"marat/medodsauth/storage"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrTokenExprired = fmt.Errorf("Token expired")
	ErrTokenNotFound = fmt.Errorf("Token not found")
)

type ApiAuthenticator interface {
	Generate(id uuid.UUID) models.TokenPair
	Verify(accessTok []byte) bool
	Refresh(refresh []byte) (access []byte)
}

const (
	UserIdClaim      = "sub"
	ExprirationClaim = "exp"
	IssuedAtClaim    = "iat"
)

type Default struct {
	logger     *slog.Logger
	conf       *config.Config
	tokenStore storage.TokenStorage
}

func NewDefault(conf *config.Config, store storage.TokenStorage, logger *slog.Logger) Default {
	return Default{
		logger:     logger,
		conf:       conf,
		tokenStore: store,
	}
}

func (d Default) Refresh(hash string) (*models.TokenPair, error) {
	found, err := d.tokenStore.Get(hash)
	if err != nil {
		if errors.Is(err, storage.ErrExpired) {
			return nil, ErrTokenExprired
		}
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("getting token from storage: %w", err)
	}

	newPair := d.GeneratePair(found.UserId)

	// Remove old token
	d.tokenStore.Delete(hash)

	return newPair, nil
}

func (d Default) GeneratePair(id uuid.UUID) *models.TokenPair {
	var pair models.TokenPair

	accessRaw := GenerateAccessTok(id)
	d.logger.Debug("Generated access token", slog.Any("claims", accessRaw.Claims))

	accessHash, err := HashAccessTok(accessRaw)
	if err != nil {
		d.logger.Error("generating access jwt", err, slog.String("id", id.String()))
		return nil
	}
	pair.Access = accessHash

	refreshRaw := GenerateRefreshTok()
	d.logger.Debug("Generated refresh token",
		slog.String("id", refreshRaw.UserId.String()),
		slog.String("issuedAt", refreshRaw.IssuedAt.String()),
		slog.String("expiresAt", refreshRaw.ExpiresAt.String()))

	refreshHash, err := HashRefreshTok(&refreshRaw)
	if err != nil {
		d.logger.Error("Hashing refresh token", slog.String("err", err.Error()), slog.Any("token", refreshRaw))
	}

	pair.Refresh = refreshHash

	if err := d.tokenStore.Save(refreshHash, refreshRaw); err != nil {
		d.logger.Error("Could not save refresh token", slog.String("err", err.Error()))
		return nil
	}

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

func GenerateRefreshTok() models.RefreshToken {
	return models.RefreshToken{
		UserId:    uuid.New(),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now(),
	}
}

func HashRefreshTok(rt *models.RefreshToken) (string, error) {
	raw := make([]byte, 72)
	n, err := rt.Write(raw)
	if err != nil {
		return "", fmt.Errorf("writing to buf of len %d: %w", len(raw), err)
	}

	salt := make([]byte, len(raw)-n)
	_, err = rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("generating random data into buffer: %w", err)
	}

	copy(raw[n:], salt)

	hashed, err := bcrypt.GenerateFromPassword(raw, bcrypt.DefaultCost)

	// Should never happen
	if err != nil {
		panic(err)

	}

	// Save slat to rt after checking hashing error
	rt.Salt = salt

	return string(hashed), nil
}

func (d Default) Validate(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Conf.Server.JWTSignature), nil
	})

	if err != nil || !token.Valid {
		return uuid.Nil, fmt.Errorf("token is not valid")
	}

	claims := token.Claims.(jwt.MapClaims)
	d.logger.Debug("Parsed claims", slog.Any("claims", claims))

	expirationUnix, ok := claims[ExprirationClaim].(float64)
	if !ok {
		return uuid.Nil, fmt.Errorf("expiration claim is missing or invalid")
	}

	expiration := time.Unix(int64(expirationUnix), 0)
	if time.Now().After(expiration) {
		return uuid.Nil, ErrTokenExprired
	}

	// Extract user ID claim
	userID, ok := claims[UserIdClaim].(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID claim is missing or invalid")
	}

	// Convert user ID to UUID
	parsedUUID, err := uuid.Parse(userID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parsing user ID: %w", err)
	}

	return parsedUUID, nil
}
