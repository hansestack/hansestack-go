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

	res, err := client.CheckPassword(context.Background(), "hunter2")
	if err != nil {
		// Unreachable with the default fail-open policy.
		panic(err)
	}

	if res.Leaked {
		fmt.Printf("password found in %d known breaches\n", res.Count)
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
| `WithHTTPClient(hc)` | internal client | Carry requests through your own `*http.Client`, e.g. to add a circuit breaker, metrics or tracing in a `RoundTripper`. `nil` is ignored. The context deadline still bounds every call. |
| `WithCircuitBreaker(n, d)` | off | Stop sending after `n` consecutive failures and skip the check for `d`, then let one probe through. |

### Bringing your own HTTP client

`WithHTTPClient` swaps the transport, not the contract. Put anything that
satisfies `http.RoundTripper` in front of the call — metrics, tracing, or a
circuit breaker from a library you already run:

```go
hc := &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}

client := leakcheck.NewClient(apiKey, leakcheck.WithHTTPClient(hc))
```

The supplied client needs no `Timeout` of its own: the client timeout is
applied as a context deadline on every call, so the fail-open guarantee holds
either way, and the earlier of the two deadlines wins.

### Telling a skipped check from a clean miss

Under fail-open, a password that is not in the corpus and a check that never
ran are both reported as "not leaked". `Result.Outcome` keeps them apart, so a
skip can be counted, alerted on, or fed into a risk decision without changing
the fail-open policy:

```go
res, _ := client.CheckPassword(ctx, password)

leakChecks.WithLabelValues(res.Outcome.String()).Inc()

switch {
case res.Leaked:
    requirePasswordChange()
case !res.Outcome.Checked() && suspiciousLogin(r):
    // The control did not run and the login already looks unusual.
    requireStepUp()
}
```

| Outcome | `Checked()` | Meaning |
| --- | --- | --- |
| `OutcomeChecked` | `true` | The API answered; `Leaked` is authoritative. |
| `OutcomeSkippedTimeout` | `false` | The deadline expired before an answer arrived. |
| `OutcomeSkippedRateLimited` | `false` | The API answered `429`. |
| `OutcomeSkippedError` | `false` | Connection error, upstream `5xx`, unreadable body, or misconfiguration. |
| `OutcomeSkippedCanceled` | `false` | The caller's context was cancelled — a user who navigated away. Kept apart from a timeout so a rise in `skipped_timeout` still means the API got slow. |
| `OutcomeSkippedCircuitOpen` | `false` | The breaker was open; no request was sent. See below. |

### Surviving an outage

Without a breaker, an unreachable API costs every single login the full request
timeout, because each call waits for its own deadline. `WithCircuitBreaker`
turns that wait into an immediate fail-open skip after a few consecutive
failures, and probes for recovery once per cooldown:

```go
client := leakcheck.NewClient(apiKey,
    leakcheck.WithCircuitBreaker(5, 30*time.Second),
)
```

Both values are plain arguments so they can come from your own configuration:

```go
threshold, _ := strconv.Atoi(os.Getenv("LEAKCHECK_BREAKER_THRESHOLD"))
cooldown, _ := time.ParseDuration(os.Getenv("LEAKCHECK_BREAKER_COOLDOWN"))

client := leakcheck.NewClient(os.Getenv("LEAKCHECK_API_KEY"),
    leakcheck.WithCircuitBreaker(threshold, cooldown),
)
```

An unset `LEAKCHECK_BREAKER_THRESHOLD` parses to `0`, which leaves the breaker
off — a missing configuration degrades to the previous behaviour rather than to
a surprise. An unset cooldown falls back to `DefaultBreakerCooldown`.

Only unavailability counts towards the threshold:

| Failure | Counted | Why |
| --- | --- | --- |
| Timeout, connection error | yes | The outage the breaker exists for. |
| `5xx` | yes | Same. |
| `429` | yes | Fast, but backing off is the correct response to it. |
| `401`/`403`, other `4xx`, off-contract status | no | Answers instantly, so there is no latency to win back, and tripping would hide `ErrUnauthorized` behind `ErrCircuitOpen`. |
| Malformed response body | no | Same. |
| Caller cancelled the request | no | A user who abandons a login says nothing about the API's health. |

The breaker is off by default and counts *consecutive* failures, so
intermittent errors never trip a healthy service. Under fail-open a
short-circuited call is skipped silently; under `WithFailClose` it returns
`ErrCircuitOpen`, which distinguishes it from a request that was actually
attempted.

Either way the call reports `OutcomeSkippedCircuitOpen` rather than
`OutcomeSkippedError`. During an outage that separation is the whole picture:
`skipped_error` counts the calls that paid a full timeout, `skipped_circuit_open`
counts the ones the breaker made free. Merged into one label, a working breaker
and a broken one look identical.

With `WithFailClose`, failures are returned as errors wrapping package
sentinels — match them with `errors.Is`:

```go
res, err := client.CheckPassword(ctx, password)
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
