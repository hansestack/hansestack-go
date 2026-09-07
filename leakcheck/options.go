package leakcheck

import (
	"log/slog"
	"net/http"
	"time"
)

// Option configures a [Client]. Options are applied by [NewClient] in the
// order they are supplied, after all defaults have been established.
//
// Option is implemented as a function type rather than an interface because
// the configuration surface of this client is deliberately small and closed:
// the base URL is fixed by the API contract and is therefore not exposed.
type Option func(*Client)

// WithTimeout overrides the per-request timeout. The default is
// [DefaultTimeout] (500ms), which is mandated by the Hansestack fail-open
// contract: a leak check must never become a latency bottleneck in a sign-up,
// login or password-change flow.
//
// The timeout bounds the entire request, including connection setup, TLS
// handshake, and response body read. It is applied both to the underlying
// [http.Client] and as a context deadline, so it holds even when the caller
// passes a context without one.
//
// Non-positive durations are ignored and the default is retained; a zero
// timeout on an [http.Client] means "no timeout at all", which would silently
// defeat the fail-open guarantee.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d <= 0 {
			return
		}
		c.timeout = d
	}
}

// WithFailClose switches the client from fail-open to fail-close.
//
// By default the client fails open: network errors, timeouts, 429s and 5xx
// responses are logged and reported as "not leaked" with a nil error, so the
// caller's authentication flow proceeds exactly as if no check had run. This
// is the correct behaviour for production auth paths, where an outage of a
// supplementary security check must not lock users out.
//
// With WithFailClose, those same conditions are returned to the caller as
// errors instead. Use it in tests, batch jobs, and CI pipelines where a
// silently skipped check would be worse than a hard failure, or in
// high-assurance flows that must not proceed on unverified credentials.
//
// In both modes the boolean and integer results are identical for a
// successful check; only error handling differs.
func WithFailClose() Option {
	return func(c *Client) {
		c.failClose = true
	}
}

// WithLogger sets the [slog.Logger] used for internal diagnostics: timeouts,
// rate limiting, upstream outages and integration errors such as an invalid
// API key.
//
// The default is a logger backed by [slog.DiscardHandler], so an unconfigured
// client never writes to standard output. Passing nil is a no-op and keeps
// that default rather than panicking at the first log call.
//
// Logging is performed on the request path but is non-blocking: the client
// only ever hands a record to the supplied handler and never waits on I/O of
// its own.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		if logger == nil {
			return
		}
		c.logger = logger
	}
}

// WithHTTPClient makes the client issue its requests through hc instead of the
// [http.Client] constructed by [NewClient].
//
// Use it to attach transport-level behaviour this package deliberately leaves
// out — a circuit breaker, pool tuning, metrics, tracing — in a
// [http.RoundTripper] the caller owns.
//
// The fail-open contract holds either way: [Client.CheckPassword] applies the
// client timeout as a context deadline, so an hc without its own Timeout is
// still bounded and the earlier of the two deadlines wins. A nil client is a
// no-op, so an unset dependency cannot silently disable timeouts.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc == nil {
			return
		}
		c.httpClient = hc
	}
}

// WithCircuitBreaker stops sending requests after threshold consecutive
// failures and skips the check outright until cooldown has elapsed.
//
// Without it an outage costs every login the full request timeout, because
// each call waits out its own deadline. The breaker turns that wait into an
// immediate fail-open skip, then lets a single probe through once the cooldown
// is over: success closes the circuit, failure restarts the cooldown.
//
// Only unavailability counts towards the threshold: timeouts, connection
// failures, 5xx and 429. A cancelled request, a rejected API key or a
// malformed one answer instantly and are left uncounted, so the breaker never
// masks [ErrUnauthorized] behind [ErrCircuitOpen].
//
// Off by default. A non-positive threshold disables it, so a value read from
// unset configuration degrades to the previous behaviour instead of to a
// surprise; a non-positive cooldown falls back to [DefaultBreakerCooldown].
// Under [WithFailClose] a short-circuited call returns [ErrCircuitOpen].
func WithCircuitBreaker(threshold int, cooldown time.Duration) Option {
	return func(c *Client) {
		if threshold <= 0 {
			return
		}
		if cooldown <= 0 {
			cooldown = DefaultBreakerCooldown
		}
		c.breaker = &breaker{threshold: threshold, cooldown: cooldown}
	}
}

// withBaseURL overrides the API base URL.
//
// This option is deliberately unexported. The Hansestack Leak-Check API base
// URL is fixed by the API contract and must not be configurable by users of
// this library; the option exists solely so that the package's own tests can
// point the client at an httptest server.
func withBaseURL(rawURL string) Option {
	return func(c *Client) {
		if rawURL == "" {
			return
		}
		c.baseURL = rawURL
	}
}
