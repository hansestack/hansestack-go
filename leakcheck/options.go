package leakcheck

import (
	"log/slog"
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
