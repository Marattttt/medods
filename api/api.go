package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"marat/medodsauth/auth"
	"marat/medodsauth/config"
	"marat/medodsauth/storage"
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
	mux.Handle("/refresh", http.HandlerFunc(HandleRefresh))
	mux.Handle("/validate", http.HandlerFunc(HandleTokenValidate))

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
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{"Invalid uuid"})
		return
	}

	authenticator := auth.NewDefault(config.Conf, storage.IMS, reqData.logger)

	tokenPair := authenticator.GeneratePair(id)

	if tokenPair == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{"Could not generate token pair"})
		return
	}

	json.NewEncoder(w).Encode(tokenPair)
}

func HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var (
		ctx     = r.Context()
		reqData = ctx.Value(requestData{}).(requestData)
	)

	hash := r.URL.Query().Get("token")
	if hash == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{"refresh query param not found"})
		return
	}

	authorizer := auth.NewDefault(config.Conf, storage.IMS, reqData.logger)
	pair, err := authorizer.Refresh(hash)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{err.Error()})
		return
	}

	json.NewEncoder(w).Encode(pair)
}

func HandleTokenValidate(w http.ResponseWriter, r *http.Request) {
	var (
		ctx     = r.Context()
		reqData = ctx.Value(requestData{}).(requestData)
	)

	// Get the Authorization header value
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{"No Authorization header found"})
		return
	}

	// Split the Authorization header value into parts
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{"Invalid Authorization header format"})
		return
	}

	authorizer := auth.NewDefault(reqData.conf, storage.IMS, reqData.logger)
	id, err := authorizer.Validate(parts[1])
	if err != nil {
		if errors.Is(err, auth.ErrTokenExprired) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{"Token exprired"})
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{err.Error()})
		return
	}

	json.NewEncoder(w).Encode(TokenStatusResponse{"Valid", id.String()})
}
