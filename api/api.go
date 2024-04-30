package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"marat/medodsauth/auth"
	"marat/medodsauth/config"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

var served atomic.Uint64

type requestData struct {
	logger *slog.Logger
	reqId  uint64
}

func Server(conf *config.Config) *http.Server {
	mux := chi.NewMux()

	mux.Use(addRequestData, logRequestStatus)

	// Might be better to set an http mnethod, but it was not specified, so did not set any
	mux.Handle("/login", http.HandlerFunc(HandleLogin))

	listenOn := fmt.Sprintf("%s:%s", conf.Server.Host, strconv.Itoa(conf.Server.Port))
	return &http.Server{
		Handler: mux,
		Addr:    listenOn,
	}
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	var (
		ctx     = r.Context()
		reqData = ctx.Value(requestData{}).(requestData)
	)
	idParam := r.URL.Query().Get("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		fmt.Fprintf(w, "Invalid uuid")
		return
	}

	authenticator := auth.NewDefaultAuthenticator(config.Conf, reqData.logger)

	tokenPair := authenticator.GeneratePair(id)

	if tokenPair == nil {
		slog.Info("Did not generate auth token pair", slog.Any("id", id))
		http.Error(w, "Could not generate token pair", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(tokenPair)
}
