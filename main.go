package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"marat/medodsauth/api"
	"marat/medodsauth/config"
	"marat/medodsauth/storage"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

//go:generate swagger generate spec -o swagger.json
func main() {
	cancelsignals := []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM}
	appCtx, appcancel := signal.NotifyContext(context.Background(), cancelsignals...)
	defer appcancel()

	if err := config.ReadConfig(appCtx); err != nil {
		panic(err)

	}

	if err := storage.SetupMongoClient(appCtx, &config.Conf.Storage); err != nil {
		panic(err)
	}

	if config.Conf.Mode.IsDebug() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	printConfig(*config.Conf)

	go func() {
		server := api.Server(config.Conf)
		slog.Info("Serving http", slog.String("adress", server.Addr))
		if err := server.ListenAndServe(); err != nil {
			slog.Error("Unxpected stop to serving http", err)
		}
		slog.Info("Stopped serving http")
	}()

	<-appCtx.Done()
}

func printConfig(conf config.Config) {
	if !conf.Mode.IsDebug() {
		slog.Info("Using config", slog.Any("config", conf))
		return
	}

	// Print a pretrier version of config
	marshalledConf, err := json.MarshalIndent(conf, "", strings.Repeat(" ", 4))
	if err != nil {
		slog.Error("Marshalling created config", err)
		os.Exit(1)
	}
	slog.Info("Using config: \n" + string(marshalledConf))
}
