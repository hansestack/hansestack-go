package leakcheck

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// minResetIn floors the wait taken from a 429. The reset headers have
	// one-second resolution and legitimately round a sub-second bucket down
	// to zero; honouring that literally would leave the open state with no
	// cooldown at all.
	minResetIn = time.Second

	// maxResetIn caps it. The value arrives over the network and decides how
	// long a security control stays switched off, so it is never taken at
	// face value: unclamped, an X-RateLimit-Reset carrying a Unix timestamp
	// instead of a delta would hold the circuit open for decades.
	maxResetIn = time.Minute

	// epochCutoff separates the two encodings of X-RateLimit-Reset, in
	// seconds. Values below it are read as a delta, values at or above it as
	// a Unix timestamp. It sits at 2001-09-09, which is unreachable as a wait
	// and long past as a timestamp, so neither encoding can be taken for the
	// other.
	epochCutoff = 1_000_000_000
)

// RateLimitError is returned when the API rate-limits a request, and carries
// the reset delta the response advertised.
//
// It exists so the circuit breaker can wait exactly as long as the server
// asked instead of falling back to a configured guess. Callers who want the
// same information can reach it with [errors.As]:
//
//	var rle *leakcheck.RateLimitError
//	if errors.As(err, &rle) && rle.ResetIn > 0 {
//		// The API said the quota returns in rle.ResetIn.
//	}
//
// It unwraps to [ErrRateLimited], so errors.Is(err, ErrRateLimited) keeps
// matching and [Result.Outcome] is still [OutcomeSkippedRateLimited].
//
// The verdict and the status that produced it are separate fields on purpose.
// "Rate limited" is a closed set — one sentinel, one outcome, the thing
// callers branch on. The statuses that mean it are not: 429 is the canonical
// one and the only one this client recognises today, but secondary and abuse
// limits are signalled with 403 at some APIs and 503 carries the same meaning
// under overload. Folding the status into the verdict would make recognising
// any of those a silent behaviour change for every existing caller; kept
// beside it, it is additive.
type RateLimitError struct {
	// ResetIn is how long the response asked the client to wait, clamped to
	// between one second and one minute. It is zero when the response carried
	// no usable reset header, which is the signal to fall back to the
	// statically configured cooldown.
	ResetIn time.Duration

	// StatusCode is the status this rate-limit verdict was derived from.
	//
	// It is 429 for every error this package currently produces, and is not
	// promised to stay the only value: see the open-set note above. Branch on
	// [ErrRateLimited] for the verdict and read this only when the particular
	// status matters to you.
	StatusCode int
}

// Error implements error, matching the format of every other status error in
// this package.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s (status %d)", ErrRateLimited, e.StatusCode)
}

// Unwrap returns [ErrRateLimited] so existing errors.Is checks keep working.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// newRateLimitError builds the rate-limit error for a response, reading the
// reset delta out of its headers and the verdict's status off the response
// itself rather than assuming 429. now is passed in rather than read from the
// clock so the absolute header forms stay testable.
func newRateLimitError(resp *http.Response, now time.Time) *RateLimitError {
	return &RateLimitError{
		ResetIn:    resetFrom(resp.Header, now),
		StatusCode: resp.StatusCode,
	}
}

// resetFrom extracts the wait a 429 advertises, clamped to
// [minResetIn, maxResetIn]. It returns zero when the response carries no
// usable answer, which the breaker reads as "keep the static cooldown".
//
// Retry-After is preferred over X-RateLimit-Reset, and deliberately so. It is
// the only one of the two that is specified (RFC 9110) and the only one whose
// value is self-describing; X-RateLimit-Reset is a de-facto convention that
// carries seconds-remaining at some vendors and a Unix timestamp at others,
// with nothing in the value itself to say which. Where both are present the
// specified header wins, which is also the precedence the IETF RateLimit
// draft settled on.
func resetFrom(header http.Header, now time.Time) time.Duration {
	if d, ok := parseRetryAfter(header.Get("Retry-After"), now); ok {
		return clampReset(d)
	}

	if d, ok := parseRateLimitReset(header.Get("X-RateLimit-Reset"), now); ok {
		return clampReset(d)
	}

	return 0
}

// parseRetryAfter reads both RFC 9110 forms of Retry-After: delta-seconds and
// an absolute HTTP-date.
//
// The date form is compared against now, which imports whatever skew exists
// between this host's clock and the server's. That is tolerable only because
// the result is clamped: skew can move the wait within the bounds, never
// outside them.
func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}

	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		// A negative delta-seconds is not valid per the grammar; treat it as
		// unusable rather than as "immediately", so the static cooldown wins.
		if seconds < 0 {
			return 0, false
		}

		return secondsToDuration(seconds), true
	}

	if deadline, err := http.ParseTime(raw); err == nil {
		return deadline.Sub(now), true
	}

	return 0, false
}

// parseRateLimitReset reads X-RateLimit-Reset in either of the two encodings
// found in the wild, discriminating on magnitude against [epochCutoff].
//
// The heuristic is what makes this header safe to read at all. Without it a
// timestamp taken for a delta would be a wait of roughly fifty years, which
// for a security control means switched off permanently; the cutoff plus the
// clamp reduce a wrong guess to at most [maxResetIn].
func parseRateLimitReset(raw string, now time.Time) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, false
	}

	if value >= epochCutoff {
		return time.Unix(value, 0).Sub(now), true
	}

	return secondsToDuration(value), true
}

// secondsToDuration converts whole seconds, saturating instead of overflowing
// time.Duration on the way.
func secondsToDuration(seconds int64) time.Duration {
	if seconds > int64(maxResetIn/time.Second) {
		return maxResetIn
	}

	return time.Duration(seconds) * time.Second
}

// clampReset holds a parsed delta inside the bounds documented on
// [minResetIn] and [maxResetIn].
func clampReset(d time.Duration) time.Duration {
	if d < minResetIn {
		return minResetIn
	}

	if d > maxResetIn {
		return maxResetIn
	}

	return d
}

// resetInFor reports the reset delta an error advertised, and whether the
// error was a rate limit at all. The breaker uses both: only a run made up
// entirely of rate limits may take its cooldown from the server.
func resetInFor(err error) (resetIn time.Duration, rateLimited bool) {
	var rle *RateLimitError
	if errors.As(err, &rle) {
		return rle.ResetIn, true
	}

	return 0, false
}
