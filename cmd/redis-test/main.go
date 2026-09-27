package main

import (
	"context"
	"fmt"
	"log"

	"example.com/pan-vault/internal/vault"
)

func main() {
	ctx := context.Background()

	rdb := vault.NewRedis("localhost:6379")
	defer rdb.Close()

	if err := rdb.Ping(ctx); err != nil {
		log.Fatal("Redis connection error:", err)
	}

	fmt.Println("Redis connected successfully")

	if err := rdb.Store(ctx, "test-token", "4111111111111111"); err != nil {
		log.Fatal("Redis store error:", err)
	}

	pan, ok := rdb.Lookup(ctx, "test-token")

	if !ok {
		log.Fatal("Token not found")
	}

	fmt.Println("Token:", "test-token")
	fmt.Println("PAN:", pan)

}
