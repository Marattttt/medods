package config

import (
	"context"

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
	return m == "DEBUG"
}

type ServerConfig struct {
	Host string `env:"HOST, default=127.0.0.1"`
	Port int    `env:"PORT, default=3030"`
}

type StorageConfig struct {
	DBAddr string `env:"DBADDR, default=27017"`
}
