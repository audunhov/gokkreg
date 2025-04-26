package internal

import (
	"context"
	"log/slog"
	"os"
)

func GetAuthUser(ctx context.Context) User {
	user, ok := ctx.Value("user").(User)
	if !ok {
		slog.Error("Invalid use, must have user in context")
		os.Exit(1)
	}
	return user
}
