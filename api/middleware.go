package api

import (
	"context"
	"log/slog"
	"marat/medodsauth/config"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
)

func addRequestData(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestId := served.Add(1)
		requestLogger := slog.With(slog.Uint64("requestId", requestId))
		ctx := context.WithValue(r.Context(), requestData{}, requestData{
			reqId:  requestId,
			conf:   config.Conf,
			logger: requestLogger,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Produces an http handler that logs when request starts and ends
func logRequestStatus(next http.Handler) http.Handler {
	// Return a HandleFunc wrapper or chi middleware
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		data := ctx.Value(requestData{}).(requestData)

		data.logger.Info("Received request", slog.String("path", r.URL.Path))

		start := time.Now()

		// Required to get data about a finished request
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(wrapped, r)

		took := time.Since(start)
		data.logger.Info(
			"Finished request",
			slog.Duration("timeTook", took),
			slog.Int("responseCode", wrapped.Status()),
			slog.Int("length", wrapped.BytesWritten()),
		)
	})
}
