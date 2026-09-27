// Command pan-vault runs the PAN vault HTTP service (Echo v4).
//
// main is the composition root: it constructs the real implementations and
// injects them via httpapi.Deps. The work happens in internal/httpapi; see
// ../README.md for the implementation order.
package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"example.com/pan-vault/internal/httpapi"
	"example.com/pan-vault/internal/redact"
	"example.com/pan-vault/internal/vault"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	addr := os.Getenv("PAN_VAULT_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	// Application logs go through the redacting writer as well: the process
	// must never write a raw PAN to stdout/stderr. (Echo's own logger is
	// wrapped inside httpapi.New.)
	logOut := redact.NewWriter(os.Stdout)

	defer logOut.Close()
	slog.SetDefault(slog.New(slog.NewTextHandler(logOut, nil)))

	e, err := httpapi.New(httpapi.Deps{
		Vault:     vault.NewRedis(redisAddr),
		LogOutput: logOut,
	})
	if err != nil {
		slog.Error("Error creating http client", err)
	}

	slog.Info("pan-vault listening", "addr", addr)

	if err := e.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Error creating http client", "error", err)
		os.Exit(1)

	}
}
