package api

import (
	"encoding/json"
	"net/http"
)

func jsonError(w http.ResponseWriter, msg string, code int) {
	mp := map[string]string{"error": msg}
	json.NewEncoder(w).Encode(mp)
	w.WriteHeader(code)
}

func jsonMessage(w http.ResponseWriter, msg string) {
	mp := map[string]string{"message": msg}
	json.NewEncoder(w).Encode(mp)
}
