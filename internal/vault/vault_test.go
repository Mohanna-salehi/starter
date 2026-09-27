package vault

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
)

func TestMemoryStoreLookupRoundTrip(t *testing.T) {
	v := NewMemory()
	ctx := context.Background()
	const token, pan = "0123456789abcdef0123456789abcdef", "4111111111111111"

	if err := v.Store(ctx, token, pan); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, ok := v.Lookup(ctx, token)
	if !ok {
		t.Fatalf("Lookup(%q) = not found, want found", token)
	}
	if got != pan {
		t.Fatalf("Lookup(%q) = %q, want %q", token, got, pan)
	}
}

func TestMemoryLookupUnknown(t *testing.T) {
	v := NewMemory()
	if _, ok := v.Lookup(context.Background(), "does-not-exist"); ok {
		t.Fatal("Lookup of unknown token returned ok=true")
	}
}

func TestTokensAreOpaqueAndUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		tok, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if len(tok) != 32 {
			t.Fatalf("NewToken length = %d (%q), want 32 hex chars", len(tok), tok)
		}
		if _, err := hex.DecodeString(tok); err != nil {
			t.Fatalf("NewToken(%q) is not hex: %v", tok, err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("NewToken returned duplicate %q after %d draws", tok, i)
		}
		seen[tok] = struct{}{}
	}
}

func TestMemoryConcurrentAccess(t *testing.T) {
	v := NewMemory()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := "token-" + string(rune('a'+i%26))
			if err := v.Store(ctx, tok, "4111111111111111"); err != nil {
				t.Errorf("Store: %v", err)
				return
			}
			if _, ok := v.Lookup(ctx, tok); !ok {
				t.Errorf("Lookup(%q) not found after Store", tok)
			}
		}(i)
	}
	wg.Wait()
}
