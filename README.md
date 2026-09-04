# hansestack-go

[![CI](https://github.com/hansestack/hansestack-go/actions/workflows/ci.yml/badge.svg)](https://github.com/hansestack/hansestack-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hansestack/hansestack-go.svg)](https://pkg.go.dev/github.com/hansestack/hansestack-go)

Official Go client library for the [Hansestack](https://hansestack.de) API.
No third-party dependencies — standard library only.

> **Using an AI coding agent?** Point it at [`llms.txt`](./llms.txt) for
> machine-readable integration rules.

## Installation

```sh
go get github.com/hansestack/hansestack-go
```

## Packages

| Package | Description |
| --- | --- |
| [`leakcheck`](./leakcheck) | Check passwords against a known data-breach corpus using k-anonymity. |

## leakcheck

Checks whether a password appears in a known data-breach corpus, without ever
transmitting the password or its full hash.

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hansestack/hansestack-go/leakcheck"
)

func main() {
	client := leakcheck.NewClient(os.Getenv("HANSESTACK_API_KEY"))

	leaked, count, err := client.CheckPassword(context.Background(), "hunter2")
	if err != nil {
		// Unreachable with the default fail-open policy.
		panic(err)
	}

	if leaked {
		fmt.Printf("password found in %d known breaches\n", count)
	} else {
		fmt.Println("password not found in any known breach")
	}
}
```

### k-Anonymity

The plaintext password never leaves your process, and neither does its full
hash. The client hashes the password with SHA-1 locally and sends only the
first five characters of the uppercase hex digest. The server returns every
known suffix sharing that prefix, and the final comparison happens locally.

The server therefore learns only that *some* password beginning with a given
five-character hash prefix was checked — a set spanning a very large number of
candidates. It cannot tell which one, nor whether there was a match.

> SHA-1 is used because the protocol and the upstream breach corpus are defined
> in terms of it. It is a wire format here, not a security control.

### Fail-open by default

A leak check is a supplementary security signal, never a single point of
failure. By default the client **fails open**: network errors, timeouts, rate
limiting (429) and upstream faults (5xx) are logged and reported as
"not leaked" with a `nil` error, so sign-up, login and password-change flows
continue as if the check had not run.

Every request is bounded by an explicit **500 ms** timeout and attempted
**exactly once** — no retries, no caching, no sleeping on 429.

### Configuration

```go
client := leakcheck.NewClient(apiKey,
	leakcheck.WithTimeout(300*time.Millisecond), // default: 500ms
	leakcheck.WithLogger(slog.Default()),        // default: discard
	leakcheck.WithFailClose(),                   // default: fail open
)
```

| Option | Default | Description |
| --- | --- | --- |
| `WithTimeout(d)` | `500ms` | Per-request timeout. Non-positive values are ignored. |
| `WithLogger(l)` | discard | `*slog.Logger` for internal diagnostics. `nil` is ignored. |
| `WithFailClose()` | fail open | Return errors to the caller instead of swallowing them. |

With `WithFailClose`, failures are returned as errors wrapping package
sentinels — match them with `errors.Is`:

```go
leaked, count, err := client.CheckPassword(ctx, password)
switch {
case errors.Is(err, leakcheck.ErrUnauthorized):
	// Broken integration: bad or missing API key.
case errors.Is(err, leakcheck.ErrRateLimited):
	// Quota exceeded; pace background workloads.
case errors.Is(err, leakcheck.ErrRequestFailed):
	// Timeout or connectivity problem.
}
```

Available sentinels: `ErrUnauthorized`, `ErrBadRequest`, `ErrRateLimited`,
`ErrServerError`, `ErrUnexpectedStatus`, `ErrInvalidResponse`,
`ErrRequestFailed`.

### Logging

Log levels encode who has to act:

| Level | Conditions |
| --- | --- |
| `ERROR` | 401/403 and other 4xx — broken integration, needs a human. |
| `WARN` | Timeouts, connection failures, 429, 5xx, malformed responses. |

A successful check logs nothing. Clients are safe for concurrent use; create
one and reuse it so connections are pooled.

## For AI coding agents

[`llms.txt`](./llms.txt) is a machine-readable integration guide for AI agents
(Copilot, Cursor, Claude) wiring this library into a Go backend. It documents
the exact API surface, the fail-open prime directive, a canonical HTTP handler
pattern, and the anti-patterns to avoid — most importantly, never returning a
5xx to a user because a leak check failed.

It is written for agents *integrating* the library, not for agents modifying
this repository.

## Development

```sh
make help    # list targets
make test    # go test -v -race ./...
make lint    # golangci-lint
make verify  # tidy + lint + test
```

## License

[MIT](./LICENSE)
