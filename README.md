# `pan-vault` starter scaffold

A compiling skeleton with **deliberately failing tests**. The tests are the
contract: they encode what `PROJECT.md` and `LUHN.md` specify. Your job is to
make them green in the order below, then keep them green while the server
shape grows around them.

```bash
cd starter
go test ./...        # everything fails, on purpose
go test ./... -run TestMaskGoldenFromTestdata -v
```

## Packages and the order to implement them

| Order | Package | TODO | Tests that must pass |
|---|---|---|---|
| 1 | `internal/pan` | `IsLuhnValid`, `Mask` (see `LUHN.md`) | `pan_test.go` |
| 2 | `internal/vault` | concurrency-safe map, `NewToken` via `crypto/rand` | `vault_test.go` |
| 3 | `internal/redact` | buffering writer, split-run handling, `Close` flush | `redact_test.go` |
| 4 | `internal/httpapi` | Echo v4 handlers, JSON bodies, error codes, `New(Deps)` | `httpapi_test.go` |

`cmd/pan-vault/main.go` already starts the Echo app returned by
`httpapi.New()`.

## Rules of the scaffold

- Do not weaken a test to make it pass; if a test looks wrong, ask why it was
  written that way first.
- Run `go test -race ./...` after every step — the vault requires it.
- Keep the coverage of each package ≥ 80 % once implemented.
- The golden file `internal/pan/testdata/cards.jsonl` is the same data as
  `../samples/cards.jsonl`; treat it as read-only test input.
- Dependencies are injected: `httpapi.New(Deps{Vault: ..., LogOutput: ...})`
  takes them from the caller. `main` is the only place that constructs real
  implementations; tests pass `vault.NewMemory()` and an `io.Discard` output.
  If you add an audit store, add it to `Deps` and construct it in `main` too.
  `New` must return a fresh, isolated app per call — the tests rely on it.
- Echo's logger output is wrapped in `internal/redact` inside `New`, so
  framework logs cannot leak a PAN. Keep that wiring and keep `main`'s slog
  output wrapped the same way.
- `github.com/labstack/echo/v4` is the only allowed direct dependency. When in
  doubt prefer the standard library.

When all tests are green, continue with the remaining acceptance criteria in
`../PROJECT.md` §5 and fill in `../SUBMISSION.md`.
