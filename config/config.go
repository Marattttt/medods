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
	Host                  string        `env:"HOST, default=127.0.0.1"`
	Port                  int           `env:"PORT, default=3030"`
	JWTSignature          string        `env:"JWT_SIGNATURE, default=secret"`
	AccessTokenValidTime  time.Duration `env:"TOKEN_ACCESS_VALID_FOR, default=1h"`
	RefreshTokenValidTime time.Duration `env:"TOKEN_REFRESH_VALID_FOR, default=24h"`
}

type StorageConfig struct {
	DBAddr string `env:"DBADDR, default=27017"`
}
