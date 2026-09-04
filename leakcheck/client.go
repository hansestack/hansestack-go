// Package leakcheck provides a client for the Hansestack Leak-Check API,
// which reports whether a password appears in a known data-breach corpus.
//
// # k-Anonymity
//
// The plaintext password never leaves the process, and neither does its full
// hash. The client computes SHA-1 over the password locally, uppercases the
// 40-character hex digest, and sends only the first five characters — the
// prefix — to the API. The server answers with every known suffix sharing
// that prefix, together with a breach count, and the final comparison happens
// locally against the 35-character suffix.
//
// The server therefore learns only that some password beginning with a given
// five-character hash prefix was checked, a set that spans a very large number
// of candidate passwords. It cannot determine which one, nor whether the
// lookup produced a hit.
//
// SHA-1 is used because the protocol and the upstream breach corpus are
// defined in terms of it. It is a wire format here, not a security control:
// no security property of this package depends on SHA-1 being
// collision-resistant.
//
// # Fail-open by default
//
// A leak check is a supplementary security signal, never a single point of
// failure. By default the client fails open: network errors, timeouts, rate
// limiting and upstream outages are logged and reported as "not leaked" with a
// nil error, so sign-up, login and password-change flows continue exactly as
// if the check had not run. Use [WithFailClose] to have those conditions
// returned as errors instead.
//
// Every request is bounded by an explicit timeout ([DefaultTimeout], 500ms)
// and is attempted exactly once. The client performs no retries and no
// caching; a single bounded attempt is sufficient for fail-open behaviour, and
// retries on an auth hot path would multiply latency during an outage.
//
// # Usage
//
//	client := leakcheck.NewClient(os.Getenv("HANSESTACK_API_KEY"))
//
//	leaked, count, err := client.CheckPassword(ctx, password)
//	if err != nil {
//		// Only reachable with WithFailClose; the default never errors here.
//		return err
//	}
//	if leaked {
//		return fmt.Errorf("password appeared in %d known breaches", count)
//	}
//
// A Client is safe for concurrent use by multiple goroutines.
package leakcheck

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: required by the k-anonymity wire protocol, not used as a security control.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultBaseURL is the fixed production endpoint of the Hansestack
	// Leak-Check API. It is intentionally not configurable through an
	// exported option; see withBaseURL.
	defaultBaseURL = "https://api.hansestack.de/leakcheck"

	// DefaultTimeout bounds every request to the API. It is deliberately
	// aggressive: the check runs inline in authentication flows, where a slow
	// answer is worse than no answer, and the fail-open contract makes an
	// expired deadline harmless.
	DefaultTimeout = 500 * time.Millisecond

	// prefixLength is the number of leading hex characters of the digest sent
	// to the server. The remaining characters form the locally compared
	// suffix.
	prefixLength = 5

	// maxResponseBytes caps how much of a response body is read. A well-formed
	// bucket is a few tens of kilobytes; the cap bounds memory use if an
	// upstream error page or a misrouted response is served instead.
	maxResponseBytes = 8 << 20 // 8 MiB
)

// Errors reported by [Client.CheckPassword] when the client is configured with
// [WithFailClose]. In the default fail-open mode these are logged and
// swallowed, and CheckPassword returns a nil error instead.
//
// Match them with [errors.Is]; the returned values wrap these sentinels with
// additional context such as the observed status code.
var (
	// ErrUnauthorized indicates the API key was missing, malformed or
	// rejected (HTTP 401 or 403). This is a broken integration, not a
	// transient fault, and will not resolve on its own.
	ErrUnauthorized = errors.New("leakcheck: unauthorized, check API key")

	// ErrBadRequest indicates the server rejected the request as malformed
	// (HTTP 4xx other than 401, 403 and 429). It signals a client bug or a
	// protocol mismatch rather than a leak or an outage.
	ErrBadRequest = errors.New("leakcheck: malformed request")

	// ErrRateLimited indicates the API key exceeded its quota (HTTP 429).
	// The client never retries or sleeps in response; inspect
	// X-RateLimit-Reset in logs to pace background workloads.
	ErrRateLimited = errors.New("leakcheck: rate limited")

	// ErrServerError indicates an upstream fault (HTTP 5xx).
	ErrServerError = errors.New("leakcheck: server error")

	// ErrUnexpectedStatus indicates a status code outside every range the API
	// contract defines.
	ErrUnexpectedStatus = errors.New("leakcheck: unexpected status")

	// ErrInvalidResponse indicates the response could not be read or was not
	// the flat JSON object of suffix to breach count that the API promises.
	ErrInvalidResponse = errors.New("leakcheck: invalid response body")

	// ErrRequestFailed indicates the request never produced a response:
	// DNS failure, connection refused, a TLS error, or an expired deadline.
	ErrRequestFailed = errors.New("leakcheck: request failed")
)

// Client is a Hansestack Leak-Check API client.
//
// Create one with [NewClient] and reuse it: the embedded [http.Client] pools
// connections, which matters on an authentication hot path. The zero value is
// not usable.
//
// A Client is safe for concurrent use by multiple goroutines. All fields are
// set during construction and are never mutated afterwards.
type Client struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	failClose  bool
	logger     *slog.Logger
	httpClient *http.Client
}

// NewClient returns a [Client] authenticating with the given API key.
//
// Defaults: a [DefaultTimeout] request timeout, fail-open error handling, and
// a logger backed by [slog.DiscardHandler] so an unconfigured client stays
// silent. Override them with [WithTimeout], [WithFailClose] and [WithLogger].
//
// An empty API key is not rejected here. The client is designed never to panic
// or fail construction on an auth path; a missing key surfaces as an HTTP 401,
// which is logged at error level and, under the default fail-open policy,
// reported as "not leaked".
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:  apiKey,
		baseURL: defaultBaseURL,
		timeout: DefaultTimeout,
		logger:  slog.New(slog.DiscardHandler),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Constructed after options are applied so the timeout reflects
	// WithTimeout. Set explicitly rather than relying on any library default,
	// which for http.Client is no timeout at all.
	c.httpClient = &http.Client{Timeout: c.timeout}

	return c
}

// hashPassword computes the k-anonymity prefix and suffix for a password.
//
// It returns the uppercase hex SHA-1 digest split after [prefixLength]
// characters: a 5-character prefix, which is the only part transmitted, and a
// 35-character suffix, which is compared locally and never leaves the process.
func hashPassword(password string) (prefix, suffix string) {
	// SHA-1 is mandated by the k-anonymity protocol and the upstream breach
	// corpus. It is a wire format, not a security control.
	sum := sha1.Sum([]byte(password)) //nolint:gosec // G401: see above.
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))

	return digest[:prefixLength], digest[prefixLength:]
}

// CheckPassword reports whether password appears in the breach corpus and, if
// so, how many times it was seen.
//
// Only the first five characters of the password's uppercase SHA-1 digest are
// sent to the API. The password itself, the full digest and the digest suffix
// never leave the process; see the package documentation for details.
//
// The request is bounded by the client timeout ([DefaultTimeout] by default).
// If ctx carries an earlier deadline, that deadline wins. Exactly one attempt
// is made: this client never retries, including on 429 and 5xx.
//
// In the default fail-open mode the error result is always nil. Network
// failures, timeouts, rate limiting, upstream faults and misconfiguration are
// logged and reported as (false, 0, nil), so the caller's flow proceeds as if
// no check had run. With [WithFailClose] those conditions are returned as
// errors wrapping the sentinels declared in this package; match them with
// [errors.Is].
//
// A non-nil error always accompanies a (false, 0) result, so callers that
// treat errors as "not leaked" remain correct in either mode.
func (c *Client) CheckPassword(ctx context.Context, password string) (bool, int, error) {
	prefix, suffix := hashPassword(password)

	// Applied even when ctx already has a deadline: WithTimeout only ever
	// shortens, so the effective bound is the earlier of the two.
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	suffixes, err := c.fetchPrefix(ctx, prefix)
	if err != nil {
		return c.fail(err)
	}

	// Case-sensitive lookup against the uppercase hex suffix, matching the
	// key format the API guarantees.
	if count, ok := suffixes[suffix]; ok {
		return true, count, nil
	}

	return false, 0, nil
}

// fail applies the configured failure policy.
//
// Under fail-close the error is returned to the caller. Under the default
// fail-open policy it is discarded and a neutral "not leaked" result is
// reported, so a failing check never blocks an authentication flow. The
// failure has already been logged at the point where it was detected, with the
// level and attributes appropriate to its cause.
func (c *Client) fail(err error) (bool, int, error) {
	if c.failClose {
		return false, 0, err
	}

	return false, 0, nil
}

// fetchPrefix performs the single GET against /v1/prefixes/{prefix} and
// decodes the suffix bucket.
//
// It is the only place that touches the network. Every failure is logged here,
// where the cause is still known, and returned as an error wrapping one of the
// package sentinels; the caller applies the fail-open or fail-close policy.
func (c *Client) fetchPrefix(ctx context.Context, prefix string) (map[string]int, error) {
	endpoint := c.baseURL + "/v1/prefixes/" + url.PathEscape(prefix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		// Only reachable if baseURL is unparseable, which cannot happen with
		// the fixed production endpoint.
		c.logger.ErrorContext(ctx, "leakcheck: could not build request",
			"error", err, "prefix", prefix)

		return nil, fmt.Errorf("%w: %w", ErrRequestFailed, err)
	}

	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logTransportError(ctx, prefix, err)

		return nil, fmt.Errorf("%w: %w", ErrRequestFailed, err)
	}
	defer func() {
		// Drain before closing so the connection can return to the pool.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.statusError(ctx, prefix, resp)
	}

	// The body is the map itself: a flat JSON object of suffix to breach
	// count, with no envelope or wrapper key.
	var suffixes map[string]int
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&suffixes); err != nil {
		c.logger.WarnContext(ctx, "leakcheck: could not decode response",
			"error", err, "prefix", prefix)

		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	return suffixes, nil
}

// logTransportError records a failure that produced no HTTP response.
//
// Timeouts and cancellations are distinguished from connection-level faults
// because they call for different operational responses: a deadline that is
// too tight for the network path, versus DNS, TLS or connectivity problems.
// All are warnings — expected, transient, and absorbed by the fail-open path.
func (c *Client) logTransportError(ctx context.Context, prefix string, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		c.logger.WarnContext(ctx, "leakcheck: request timed out, skipping check",
			"error", err, "prefix", prefix, "timeout", c.timeout)
	case errors.Is(err, context.Canceled):
		c.logger.WarnContext(ctx, "leakcheck: request canceled, skipping check",
			"error", err, "prefix", prefix)
	default:
		c.logger.WarnContext(ctx, "leakcheck: request failed, skipping check",
			"error", err, "prefix", prefix)
	}
}

// statusError logs a non-200 response and maps it to a sentinel error.
//
// Log levels encode who has to act. Misconfiguration (401, 403, and other 4xx)
// is logged at error level: the integration is broken, every request will keep
// failing, and a human must intervene. Rate limiting and upstream faults are
// logged at warning level: they are transient and expected, and the fail-open
// path already contains the impact.
//
// No status causes a retry or a delay, including 429. X-RateLimit-Reset is
// recorded for telemetry only, so that background workloads can be paced out
// of band; blocking here would push rate-limit latency onto an end user.
func (c *Client) statusError(ctx context.Context, prefix string, resp *http.Response) error {
	status := resp.StatusCode

	switch {
	case status == http.StatusTooManyRequests:
		c.logger.WarnContext(ctx, "leakcheck: rate limited, skipping check",
			"status", status,
			"prefix", prefix,
			"ratelimit_limit", resp.Header.Get("X-RateLimit-Limit"),
			"ratelimit_remaining", resp.Header.Get("X-RateLimit-Remaining"),
			"ratelimit_reset", resp.Header.Get("X-RateLimit-Reset"),
		)

		return fmt.Errorf("%w (status %d)", ErrRateLimited, status)

	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		c.logger.ErrorContext(ctx, "leakcheck: API key rejected, check integration",
			"status", status, "prefix", prefix)

		return fmt.Errorf("%w (status %d)", ErrUnauthorized, status)

	case status >= 400 && status < 500:
		c.logger.ErrorContext(ctx, "leakcheck: request rejected, check integration",
			"status", status, "prefix", prefix)

		return fmt.Errorf("%w (status %d)", ErrBadRequest, status)

	case status >= 500:
		c.logger.WarnContext(ctx, "leakcheck: upstream error, skipping check",
			"status", status, "prefix", prefix)

		return fmt.Errorf("%w (status %d)", ErrServerError, status)

	default:
		c.logger.WarnContext(ctx, "leakcheck: unexpected status, skipping check",
			"status", status, "prefix", prefix)

		return fmt.Errorf("%w (status %d)", ErrUnexpectedStatus, status)
	}
}
