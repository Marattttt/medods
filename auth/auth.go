package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"marat/medodsauth/config"
	"marat/medodsauth/storage"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrTokenExprired = fmt.Errorf("Token expired")
	ErrTokenNotFound = fmt.Errorf("Token not found")
	ErrTokenInvalid  = fmt.Errorf("Token invalid")
)

type TokenPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type ApiAuthenticator interface {
	GeneratePair(ctx context.Context, id uuid.UUID) *TokenPair
	ValidateAccessTok(tokenString string) (*jwt.Token, error)
	Refresh(ctx context.Context, oldPair TokenPair) (TokenPair, error)
}

const (
	ExprirationClaim = "exp"
	IssuedAtClaim    = "iat"
	RefreshIdClaim   = "refresh_id"
	UserIdClaim      = "uid"

	refreshTokenSize = 50
)

var (
	refreshTokenEncodiing = base64.RawURLEncoding
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

func (d Default) Refresh(ctx context.Context, oldPair TokenPair) (TokenPair, error) {
	access, err := d.ValidateAccessTok(oldPair.Access)
	if err != nil {
		return TokenPair{}, err
	}

	refresh := DecodeRefreshTok(oldPair.Refresh)

	claims := access.Claims.(jwt.MapClaims)
	refreshId := claims[RefreshIdClaim].(string)

	hashedRefresh, err := d.tokenStore.Get(ctx, string(refreshId))
	if errors.Is(err, storage.ErrNotFound) {
		d.logger.Info("Refresh token not found")
		return TokenPair{}, ErrTokenInvalid
	}

	if hashedRefresh.Id != refreshId {
		d.logger.Info("Refresh token id does not match the one in db", slog.String("db", hashedRefresh.Id), slog.String("fromJwt", refreshId))
		return TokenPair{}, ErrTokenInvalid
	}

	if hashedRefresh.Hash != string(refresh) {
		slog.Info("Refresh token hash does not match encrypted hash in db", slog.String("dbHash", hashedRefresh.Hash), slog.String("provided", string(refresh)))
		return TokenPair{}, ErrTokenInvalid
	}

	userId := claims[UserIdClaim].(string)
	parsedUserId, err := uuid.Parse(userId)
	if err != nil {
		return TokenPair{}, fmt.Errorf("Userid claim is empty or invalid")
	}

	newPair := d.GeneratePair(ctx, parsedUserId)
	if newPair == nil {
		return TokenPair{}, fmt.Errorf("Could not generate pair")
	}

	if err := d.tokenStore.Delete(ctx, refreshId); err != nil {
		d.logger.Warn("Error while deleting after refresh", slog.String("err", err.Error()))
	}

	return *newPair, nil
}

func DecodeRefreshTok(encoded string) []byte {
	reader := bytes.NewReader([]byte(encoded))
	decoder := base64.NewDecoder(refreshTokenEncodiing, reader)

	// The length is unknown before decoding, but it will not exceed the reader.Len()
	buf := make([]byte, reader.Len())

	n, err := decoder.Read(buf)
	slog.Debug("Decoded refresh token", slog.Int("bytesRead", n), slog.Int("encodedLen", reader.Len()))

	// Should never happen
	if err != nil {
		panic(err)
	}

	// This leaks the extra memory
	return buf[:n]
}

func ValidateRefreshTok(hash, raw []byte) error {
	return bcrypt.CompareHashAndPassword(hash, raw)
}

func (d Default) GeneratePair(ctx context.Context, id uuid.UUID) *TokenPair {
	accessRaw := GenerateAccessTok(id)
	refreshRaw := GenerateRefreshTok()
	d.logger.Debug("Generated access and refresh tokens", slog.Any("accessClaims", accessRaw.Claims))

	refreshHashed := HashRefreshTok(refreshRaw)

	refreshId, err := d.tokenStore.Save(ctx, refreshHashed)
	if err != nil {
		d.logger.Warn("Did not save refresh token", slog.String("err", err.Error()))
		return nil
	}

	d.logger.Info("Saved refresh token", slog.Any("id", refreshId), slog.Any("hash", refreshHashed))

	// Add refresh id
	claims := accessRaw.Claims.(jwt.MapClaims)
	claims[RefreshIdClaim] = refreshId

	accessHashed, err := HashAccessTok(accessRaw)
	if err != nil {
		d.logger.Error("Could not hash generated tokens", err)
		return nil
	}

	return &TokenPair{
		Access:  accessHashed,
		Refresh: EncodeRefreshTok(refreshHashed),
	}
}

func GenerateAccessTok(id uuid.UUID) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS512)

	claims := token.Claims.(jwt.MapClaims)
	claims[ExprirationClaim] = time.Now().Add(time.Hour).Unix()
	claims[IssuedAtClaim] = time.Now().Unix()
	claims[UserIdClaim] = id.String()

	return token
}

// Generated token is suitable f
func GenerateRefreshTok() []byte {
	// Such size fits in a bcrypt hash with a lot of space

	randomTok := make([]byte, refreshTokenSize)
	rand.Read(randomTok)

	return randomTok
}

// With more details, this function could be more useful,
// but as it was only specified to use bcrypt to hash refresh tokens, i did it nonetheless
func HashRefreshTok(raw []byte) []byte {
	hash, err := bcrypt.GenerateFromPassword(raw, bcrypt.DefaultCost)

	// Should never happen
	if err != nil {
		panic(err)
	}

	return hash
}

// Base64 encoding for a token
func EncodeRefreshTok(raw []byte) string {
	encoded := bytes.Buffer{}
	encoder := base64.NewEncoder(refreshTokenEncodiing, &encoded)

	encoder.Write(raw)
	encoder.Close()

	return string(encoded.Bytes())
}

// Id is added to claims
func HashAccessTok(access *jwt.Token) (string, error) {
	signed, err := access.SignedString([]byte(config.Conf.Server.JWTSignature))
	if err != nil {
		return "", fmt.Errorf("singing with jwt from config.Conf: %w", err)
	}

	return signed, nil
}

func (d Default) ValidateAccessTok(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Conf.Server.JWTSignature), nil
	})

	if err != nil || !token.Valid {
		slog.Debug("token failed validation")
		return nil, ErrTokenInvalid
	}

	claims := token.Claims.(jwt.MapClaims)
	d.logger.Debug("Parsed claims", slog.Any("claims", claims))

	expirationUnix, ok := claims[ExprirationClaim].(float64)
	if !ok {
		d.logger.Debug("expiration claim is missing or invalid")
		return nil, ErrTokenInvalid
	}
	expiration := time.Unix(int64(expirationUnix), 0)
	if time.Now().After(expiration) {
		d.logger.Debug("token expired", slog.String("date", expiration.String()))
		return nil, ErrTokenExprired
	}

	_, ok = claims[RefreshIdClaim].(string)
	if !ok {
		d.logger.Debug("refresh id claim is missing or invalid")
		return nil, ErrTokenInvalid
	}

	// Extract user ID claim
	userID, ok := claims[UserIdClaim].(string)
	if !ok {
		return nil, fmt.Errorf("user ID claim is missing or invalid")
	}

	// Convert user ID to UUID
	_, err = uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("parsing user ID: %w", err)
	}
	return token, nil
}
