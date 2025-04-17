package main

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"

	"github.com/audunhov/gokkreg/internal"
	"github.com/jackc/pgx/v5"
)

type API struct {
	*internal.Queries
}

func main() {

	ctx := context.Background()
	db, err := pgx.Connect(ctx, "postgresql://postgres:postgres@db/postgres")
	if err != nil {
		log.Fatal("Could not connect to db:", err)
	}
	defer db.Close(ctx)

	api := API{internal.New(db)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		users, err := api.ListUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(users)
	})

	port := ":8080"
	slog.Info("Server running at " + port)
	if err := http.ListenAndServe(port, mux); err != nil {
		slog.Error("Fatal error", "err", err)
	}
}
