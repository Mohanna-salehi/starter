package vault

import (
	"context"
	"errors"
	"os"

	"example.com/pan-vault/internal/cryptoKey"
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	client *redis.Client
	key    []byte
}

func NewRedis(address string) *Redis {
	client := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: "",
		DB:       0,
	})

	key, err := cryptoKey.DecodeKey(os.Getenv("PAN_ENCODEING"))
	if err != nil {
		return nil
	}

	return &Redis{client: client, key: key}
}

func (r *Redis) Store(ctx context.Context, token, pan string) error {
	encrypt, err := cryptoKey.Encrypt(pan, r.key)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, token, encrypt, 0).Err()
}

func (r *Redis) Lookup(ctx context.Context, token string) (string, bool) {
	pan, err := r.client.Get(ctx, token).Result()

	if errors.Is(err, redis.Nil) {
		return "", false
	}

	if err != nil {
		return "", false
	}

	decryptPan, err := cryptoKey.Decrypt(pan, r.key)
	if err != nil {
		return "", false
	}

	return decryptPan, true
}

func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}
func (r *Redis) Close() error {
	return r.client.Close()
}
