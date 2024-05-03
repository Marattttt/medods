package config

import (
	"context"
	"strings"
	"time"

	"github.com/sethvargo/go-envconfig"
)

var Conf *Config

func ReadConfig(ctx context.Context) error {
	var tempConf Config
	if err := envconfig.Process(ctx, &tempConf); err != nil {
		return err
	}
	Conf = &tempConf
	return nil
}

type Config struct {
	Mode    Mode `env:"MODE, default=DEBUG"`
	Server  ServerConfig
	Storage StorageConfig
}

type Mode string

func (m Mode) IsDebug() bool {
	return strings.ToUpper(string(m)) == "DEBUG"
}

type ServerConfig struct {
	Host                  string        `env:"HOST, default=0.0.0.0"`
	Port                  int           `env:"PORT, default=3030"`
	JWTSignature          string        `env:"JWT_SIGNATURE, default=secret"`
	AccessTokenValidTime  time.Duration `env:"TOKEN_ACCESS_VALID_FOR, default=1h"`
	RefreshTokenValidTime time.Duration `env:"TOKEN_REFRESH_VALID_FOR, default=24h"`
}

type StorageConfig struct {
	Url              string `env:"DB_URL, default=mongodb://mongodb:27017"`
	Database         string `env:"DB_DBNAME, default=medods_test_assignment"`
	TokensCollection string `env:"DB_TOKENS_COLNAME, default=tokens"`
}
