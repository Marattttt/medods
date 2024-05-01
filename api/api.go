package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"marat/medodsauth/auth"
	"marat/medodsauth/config"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

var served atomic.Uint64

type requestData struct {
	conf   *config.Config
	logger *slog.Logger
	reqId  uint64
}

func Server(conf *config.Config) *http.Server {
	mux := chi.NewMux()

	mux.Use(addRequestData, logRequestStatus)

	// Might be better to set an http mnethod, but it was not specified, so did not set any
	mux.Handle("/login", http.HandlerFunc(HandleLogin))

	mux.Handle("/validate", http.HandlerFunc(HandleTokenStatus))

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

func HandleTokenStatus(w http.ResponseWriter, r *http.Request) {
	var (
		ctx     = r.Context()
		reqData = ctx.Value(requestData{}).(requestData)
	)

	// Get the Authorization header value
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "no Authorization header found", http.StatusUnauthorized)
		return
	}

	// Split the Authorization header value into parts
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	authorizer := auth.NewDefaultAuthenticator(reqData.conf, reqData.logger)
	id, err := authorizer.Validate(parts[1])
	if err != nil {
		if errors.Is(err, auth.ErrTokenExprired) {
			http.Error(w, "Token exprired", http.StatusUnauthorized)
			return
		}

		reqData.logger.Info("Did not authorize request", slog.String("err", err.Error()))
	}

	json.NewEncoder(w).Encode(id)
}
