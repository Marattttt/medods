package api

import (
	"fmt"
	"marat/medodsauth/config"
	"net/http"
	"strconv"
)

func Server(conf *config.Config) *http.Server {
	mux := http.NewServeMux()

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Heeeey!"))
	}))

	listenOn := fmt.Sprintf("%s:%s", conf.Server.Host, strconv.Itoa(conf.Server.Port))
	return &http.Server{
		Handler: mux,
		Addr:    listenOn,
	}
}
