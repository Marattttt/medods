package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"marat/medodsauth/config"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Mongo *mongo.Client

func SetupMongoClient(ctx context.Context, conf *config.StorageConfig) error {
	opts := options.Client().ApplyURI(conf.Url)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("pinging: %w", err)

	}

	Mongo = client

	return nil
}

type MongoStorage struct {
	tokens *mongo.Collection
	conf   *config.Config
	logger *slog.Logger
}

// Structure for storing tokens in db
type mongoToken struct {
	Id   primitive.ObjectID `bson:"_id,omitempty"`
	Hash []byte             `bson:"hash,omitempty"`
}

func NewMongo(client *mongo.Client, conf *config.Config, logger *slog.Logger) MongoStorage {
	return MongoStorage{
		tokens: client.Database(conf.Storage.Database).Collection(conf.Storage.TokensCollection),
		conf:   conf,
		logger: logger,
	}
}

func (m MongoStorage) Get(ctx context.Context, id string) (RefreshToken, error) {
	objid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return RefreshToken{}, ErrInvalidId
	}
	m.logger.Debug("Parsed object id", slog.String("objId", objid.Hex()), slog.String("from", id))

	filter := mongoToken{Id: objid}

	m.logger.Info("Executing query for tokens", slog.Any("filter", filter))
	res := m.tokens.FindOne(ctx, interface{}(filter))

	if errors.Is(res.Err(), mongo.ErrNoDocuments) {
		return RefreshToken{}, ErrNotFound
	}
	if res.Err() != nil {
		return RefreshToken{}, fmt.Errorf("querying: %w", res.Err())
	}

	var token RefreshToken

	// Print all elemetns
	if m.conf.Mode.IsDebug() {
		raw, _ := res.Raw()
		elements, _ := raw.Elements()
		pretty := make([]string, 0, len(elements))
		for _, el := range elements {
			pretty = append(pretty, el.DebugString())
		}

		slog.Debug("Received elements", slog.Any("raw", pretty))
	}

	if err := res.Decode(&token); err != nil {
		return RefreshToken{}, fmt.Errorf("unmarshalling refresh token: %w", err)
	}
	return token, nil
}

func (m MongoStorage) Save(ctx context.Context, hash []byte) (string, error) {
	mToken := mongoToken{Hash: hash}

	m.logger.Info("Executing insertOne on tokens", slog.Any("newToken", mToken))
	res, err := m.tokens.InsertOne(ctx, mToken)
	if err != nil {
		return "", fmt.Errorf("inserting: %w", err)
	}

	m.logger.Info("Saved refresh token", slog.String("hash", string(hash)))

	id := res.InsertedID.(primitive.ObjectID)

	return id.Hex(), nil
}

func (m MongoStorage) Delete(ctx context.Context, idHex string) error {
	id, err := primitive.ObjectIDFromHex(idHex)
	if err != nil {
		return ErrInvalidId
	}

	mToken := mongoToken{Id: id}

	m.logger.Info("Executing delete one on tokens", slog.Any("filter", mToken))
	res, err := m.tokens.DeleteOne(ctx, interface{}(mToken))
	if err != nil {
		return fmt.Errorf("executing delete: %w", err)
	}
	if res.DeletedCount == 0 {
		return ErrNoEffect
	}

	return nil
}
