// Package vault stores the mapping between opaque tokens and PANs.
//
// The contract is in ../PROJECT.md §3.2.
package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Vault is consumed by the HTTP layer, so it is defined here where it is used.
// Tests provide their own implementation; production uses Memory.
type Vault interface {
	Store(ctx context.Context, token, pan string) error
	Lookup(ctx context.Context, token string) (string, bool)
}

// Memory is an in-memory Vault.
//
// TODO: make it safe for concurrent use — the HTTP server calls it from many
// goroutines, and `go test -race` will hold you to it.
type Memory struct {
	m     map[string]string
	mutex sync.RWMutex
}

// NewMemory returns an empty vault.
func NewMemory() *Memory {
	return &Memory{m: make(map[string]string)}
}

// Store associates token with pan. Storing the same token twice overwrites.
//
// TODO: implement.

func (v *Memory) Store(ctx context.Context, token, pan string) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.m[token] = pan
	return nil

}

// Lookup returns the PAN stored under token.
//
// TODO: implement.
func (v *Memory) Lookup(ctx context.Context, token string) (string, bool) {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	pan, ok := v.m[token]
	if !ok {
		return "", false
	}
	//return pan, ok
	return pan, true
}

// NewToken returns a fresh token: 16 bytes from cryptoKey/rand, hex-encoded
// (32 characters). It must never derive from a counter, a clock, or the PAN.
//
// TODO: implement. math/rand is not acceptable here.
func NewToken() (string, error) {
	b := make([]byte, 16)
	random, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	//point
	return hex.EncodeToString(b[:random]), nil
}
