package leakcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rateLimitHandler serves a 429 carrying the given headers.
func rateLimitHandler(headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}
}

func retryAfter(value string) map[string]string {
	return map[string]string{"Retry-After": value}
}

// TestResetFrom pins the parser against the values a gateway can put on the
// wire. Anything it cannot use must come back as zero, which the breaker reads
// as "keep the static cooldown" — the header is an optimisation, never a
// correctness condition.
func TestResetFrom(t *testing.T) {
	// Fixed so the absolute forms are deterministic.
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		headers map[string]string
		want    time.Duration
	}{
		{"no headers at all", nil, 0},

		// Retry-After, delta-seconds: the common case and the one the
		// gateway's rate limiter emits.
		{"the one-second bucket", retryAfter("1"), time.Second},
		{"a longer quota window", retryAfter("30"), 30 * time.Second},
		{"surrounding whitespace", retryAfter("  2  "), 2 * time.Second},

		// The headers have one-second resolution and round a sub-second
		// bucket down to zero. Taken literally that would leave no cooldown
		// at all, so the floor applies.
		{"zero is floored, not ignored", retryAfter("0"), minResetIn},
		{"anything past the cap is capped", retryAfter("600"), maxResetIn},

		// Retry-After, HTTP-date: the other RFC 9110 form.
		{"an absolute deadline", retryAfter("Tue, 22 Sep 2026 12:00:05 GMT"), 5 * time.Second},
		{"a deadline already past", retryAfter("Tue, 22 Sep 2026 11:59:00 GMT"), minResetIn},

		{"negative delta is malformed", retryAfter("-5"), 0},
		{"garbage", retryAfter("soon"), 0},
		{"not an integer", retryAfter("1.5"), 0},

		// X-RateLimit-Reset, both encodings found in the wild.
		{
			"reset as seconds remaining",
			map[string]string{"X-RateLimit-Reset": "3"},
			3 * time.Second,
		},
		{
			"reset as a unix timestamp",
			map[string]string{"X-RateLimit-Reset": strconv.FormatInt(now.Add(4*time.Second).Unix(), 10)},
			4 * time.Second,
		},
		{
			"a stale timestamp cannot exceed the cap",
			map[string]string{"X-RateLimit-Reset": strconv.FormatInt(now.Add(time.Hour).Unix(), 10)},
			maxResetIn,
		},
		{
			"garbage in reset",
			map[string]string{"X-RateLimit-Reset": "later"},
			0,
		},

		// The cutoff itself, from both sides. This is where the whole
		// heuristic lives, and the pair is what stops someone later
		// "simplifying" it into a plain seconds parse.
		{
			"one below the cutoff is still a delta",
			map[string]string{"X-RateLimit-Reset": strconv.FormatInt(epochCutoff-1, 10)},
			maxResetIn, // a delta that large is capped, not read as a date
		},
		{
			"the cutoff itself is a timestamp",
			map[string]string{"X-RateLimit-Reset": strconv.FormatInt(epochCutoff, 10)},
			minResetIn, // 2001-09-09 is long past, so the wait floors
		},

		// Retry-After is specified and self-describing; X-RateLimit-Reset is
		// neither. Where both are present the specified header wins.
		{
			"Retry-After wins over reset",
			map[string]string{"Retry-After": "2", "X-RateLimit-Reset": "45"},
			2 * time.Second,
		},
		{
			"an unusable Retry-After falls through to reset",
			map[string]string{"Retry-After": "soon", "X-RateLimit-Reset": "5"},
			5 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			for name, value := range tc.headers {
				header.Set(name, value)
			}

			if got := resetFrom(header, now); got != tc.want {
				t.Errorf("resetFrom() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRateLimitErrorStaysMatchable guards the compatibility promise of adding
// a typed error: existing callers match [ErrRateLimited] and [outcomeFor]
// reads the same sentinel. Neither may notice that a duration now rides along.
func TestRateLimitErrorStaysMatchable(t *testing.T) {
	client := newTestClient(t, rateLimitHandler(retryAfter("2")), WithFailClose())

	res, err := client.CheckPassword(context.Background(), pwPassword)

	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false, want true")
	}
	if res.Outcome != OutcomeSkippedRateLimited {
		t.Errorf("outcome = %v, want skipped_rate_limited", res.Outcome)
	}
	if got := err.Error(); got != "leakcheck: rate limited (status 429)" {
		t.Errorf("message = %q, want the unchanged status context", got)
	}

	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatal("errors.As did not reach *RateLimitError")
	}
	if rle.ResetIn != 2*time.Second {
		t.Errorf("ResetIn = %v, want 2s", rle.ResetIn)
	}
	if rle.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", rle.StatusCode)
	}
}

// TestRateLimitErrorTracksItsStatus pins the separation the type is built on:
// [ErrRateLimited] is the verdict callers branch on, StatusCode is the status
// it was derived from, and the two are not the same set. 429 is the only
// status this package produces today, so this drives the constructor directly
// to prove the field is read off the response rather than assumed — which is
// what lets a 403 or 503 rate limit be recognised later without changing what
// existing callers see.
func TestRateLimitErrorTracksItsStatus(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusForbidden} {
		resp := &http.Response{StatusCode: status, Header: http.Header{}}
		err := newRateLimitError(resp, time.Now())

		if err.StatusCode != status {
			t.Errorf("StatusCode = %d, want %d — the status must come from the response", err.StatusCode, status)
		}
		if !errors.Is(err, ErrRateLimited) {
			t.Errorf("status %d: verdict changed with the status, want ErrRateLimited either way", status)
		}
	}
}

// TestDynamicCooldownFromHeader is acceptance criterion 2, and the point of
// the whole change: the gateway's bucket refills in a second, so serving the
// configured cooldown would keep the check off for a minute and leave every
// login in that window unscreened.
func TestDynamicCooldownFromHeader(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		rateLimitHandler(retryAfter("1"))(w, r)
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	// Two 429s trip the circuit, and it short-circuits from there.
	for range 5 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — the circuit should have opened at the threshold", got)
	}

	// Well past the second the API asked for, nowhere near the configured
	// cooldown. The probe must be allowed through.
	now = now.Add(time.Second)

	mustCheck(t, client)
	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — the cooldown should track Retry-After, not the configured minute", got)
	}
}

// TestDynamicCooldownFromResetHeader drives the X-RateLimit-Reset path end to
// end, through a real response rather than the parser alone.
//
// It is the encoding most likely to be wrong in production — a bare timestamp,
// no Retry-After to fall back on — and the one where the parser being right in
// isolation proves least, because the value has to survive the response, the
// error and the breaker to change anything an operator can see.
func TestDynamicCooldownFromResetHeader(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		reset := strconv.FormatInt(time.Now().Add(2*time.Second).Unix(), 10)
		rateLimitHandler(map[string]string{"X-RateLimit-Reset": reset})(w, r)
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range 4 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — the circuit should have opened at the threshold", got)
	}

	// The timestamp is two seconds out; the configured cooldown is a minute.
	now = now.Add(3 * time.Second)

	mustCheck(t, client)
	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — a timestamp reset must shorten the cooldown like a delta does", got)
	}
}

// TestStaticCooldownForOutages is acceptance criterion 1. A 5xx carries no
// reset delta, so the configured cooldown must apply untouched.
func TestStaticCooldownForOutages(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}, WithCircuitBreaker(2, 30*time.Second))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range 4 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}

	now = now.Add(29 * time.Second)
	mustCheck(t, client)
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — an outage must serve the full configured cooldown", got)
	}

	now = now.Add(2 * time.Second)
	mustCheck(t, client)
	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — the configured cooldown should have elapsed", got)
	}
}

// TestMixedRunKeepsStaticCooldown is the other half of criterion 1, and the
// case a naive "last error wins" override gets wrong. A 429 among timeouts and
// 5xx says nothing about the outage that joined it; handing its one-second
// delta to that circuit would send the breaker back to probing a dead API
// every second, which is the latency the breaker exists to stop paying.
func TestMixedRunKeepsStaticCooldown(t *testing.T) {
	tests := []struct {
		name string

		// rateLimitOn is the 1-based request in the run answered with a 429.
		// The rest are 5xx.
		rateLimitOn int64
	}{
		// The 429 is not the failure that trips the circuit.
		{"rate limit opens the run", 1},

		// The 429 *is* the failure that trips it. This is the order that
		// catches a "last error wins" override: the delta is sitting right
		// there in the result that closed the run, and it still must not be
		// used, because the two 5xx before it are what the circuit is for.
		{"rate limit closes the run", 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) == tc.rateLimitOn {
					rateLimitHandler(retryAfter("1"))(w, r)

					return
				}
				w.WriteHeader(http.StatusInternalServerError)
			}, WithCircuitBreaker(3, 30*time.Second))

			now := time.Now()
			client.breaker.now = func() time.Time { return now }

			for range 5 {
				mustCheck(t, client)
			}
			if got := hits.Load(); got != 3 {
				t.Fatalf("requests = %d, want 3", got)
			}

			// Past the second the 429 advertised, far short of the configured
			// wait.
			now = now.Add(5 * time.Second)
			mustCheck(t, client)
			if got := hits.Load(); got != 3 {
				t.Fatalf("requests = %d, want 3 — a 429 leaked its delta into a mixed run", got)
			}

			now = now.Add(30 * time.Second)
			mustCheck(t, client)
			if got := hits.Load(); got != 4 {
				t.Errorf("requests = %d, want 4 — the configured cooldown should have elapsed", got)
			}
		})
	}
}

// TestMissingHeaderFallsBackToStaticCooldown is acceptance criterion 3: a 429
// still trips the circuit, it just has nothing better than the configured wait
// to serve.
func TestMissingHeaderFallsBackToStaticCooldown(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"no header", nil},
		{"unparseable", retryAfter("whenever")},
		{"negative delta", retryAfter("-1")},
		{"unusable in both", map[string]string{"Retry-After": "soon", "X-RateLimit-Reset": "nope"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				rateLimitHandler(tc.headers)(w, r)
			}, WithCircuitBreaker(2, 30*time.Second))

			now := time.Now()
			client.breaker.now = func() time.Time { return now }

			for range 4 {
				mustCheck(t, client)
			}

			now = now.Add(29 * time.Second)
			mustCheck(t, client)
			if got := hits.Load(); got != 2 {
				t.Fatalf("requests = %d, want 2 — the fallback must hold for the full cooldown", got)
			}

			now = now.Add(2 * time.Second)
			mustCheck(t, client)
			if got := hits.Load(); got != 3 {
				t.Errorf("requests = %d, want 3 — the configured cooldown should have elapsed", got)
			}
		})
	}
}

// TestOverrideDoesNotOutliveItsOpenState is the bug a stored override invites.
// The shortened cooldown belongs to the trip that earned it; left in place it
// would quietly shorten every later outage for the life of the process, and
// the breaker would look like it was working while probing a dead API once a
// second.
func TestOverrideDoesNotOutliveItsOpenState(t *testing.T) {
	now := time.Now()
	b := &breaker{threshold: 1, cooldown: 30 * time.Second, now: func() time.Time { return now }}

	// A rate limit opens the circuit with the advertised one-second wait.
	cooldown, tripped := b.failure(&RateLimitError{ResetIn: time.Second, StatusCode: http.StatusTooManyRequests})
	if !tripped {
		t.Fatal("the circuit did not open")
	}
	if cooldown != time.Second {
		t.Fatalf("cooldown = %v, want 1s from the header", cooldown)
	}

	// It recovers, and later goes down for real.
	now = now.Add(2 * time.Second)
	if allowed, _ := b.allow(); !allowed {
		t.Fatal("the one-second cooldown did not elapse")
	}
	b.success()

	cooldown, tripped = b.failure(ErrServerError)
	if !tripped {
		t.Fatal("the outage did not reopen the circuit")
	}
	if cooldown != 30*time.Second {
		t.Errorf("cooldown = %v, want the configured 30s — the override outlived its open state", cooldown)
	}
}

// TestFailedProbeTakesItsOwnCooldown covers recovery through a rate limiter: a
// probe answered with a 429 must re-open on that response's delta, not on the
// cooldown of whatever opened the circuit the first time.
func TestFailedProbeTakesItsOwnCooldown(t *testing.T) {
	now := time.Now()
	b := &breaker{threshold: 1, cooldown: 30 * time.Second, now: func() time.Time { return now }}

	_, _ = b.failure(ErrServerError) // an outage opens it on the configured wait
	now = now.Add(31 * time.Second)

	if allowed, _ := b.allow(); !allowed {
		t.Fatal("the configured cooldown did not elapse")
	}

	// The probe runs into the rate limiter instead.
	cooldown, tripped := b.failure(&RateLimitError{ResetIn: time.Second, StatusCode: http.StatusTooManyRequests})
	if !tripped {
		t.Fatal("the failed probe did not reopen the circuit")
	}
	if cooldown != time.Second {
		t.Fatalf("cooldown = %v, want 1s — a failed probe should serve its own verdict", cooldown)
	}

	now = now.Add(2 * time.Second)
	if allowed, _ := b.allow(); !allowed {
		t.Error("the probe's own cooldown did not elapse")
	}
}

// TestCircuitOpenedLogNamesTheCause is the observability half of the change.
//
// A short-circuited call reports OutcomeSkippedCircuitOpen whether rate limits
// or an outage opened the circuit, and merging the two on a dashboard hides
// the one distinction this PR exists to draw: a quota the caller is exceeding
// and an API that is down want different people to do different things. The
// trip is a state transition rather than a per-request event, so the cause
// goes in one log line there rather than into the Outcome enum every caller
// would have to learn.
func TestCircuitOpenedLogNamesTheCause(t *testing.T) {
	tests := []struct {
		name         string
		handler      http.HandlerFunc
		wantCause    string
		wantCooldown string
	}{
		{
			name:         "rate limits name themselves and shorten the wait",
			handler:      rateLimitHandler(retryAfter("1")),
			wantCause:    OutcomeSkippedRateLimited.String(),
			wantCooldown: "1s",
		},
		{
			name:         "an outage keeps the configured wait",
			handler:      statusHandlerBreaker(http.StatusInternalServerError),
			wantCause:    OutcomeSkippedError.String(),
			wantCooldown: "30s",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			client := newTestClient(t, tc.handler,
				WithCircuitBreaker(1, 30*time.Second), WithLogger(logger))

			mustCheck(t, client)

			var opened map[string]any
			for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("log record is not valid JSON: %v (%q)", err, line)
				}
				if rec["msg"] == "leakcheck: circuit opened, skipping checks" {
					opened = rec
				}
			}

			if opened == nil {
				t.Fatalf("no circuit-opened record was logged; got %q", buf.String())
			}
			if opened["cause"] != tc.wantCause {
				t.Errorf("cause = %v, want %v", opened["cause"], tc.wantCause)
			}
			if opened["cooldown"] != tc.wantCooldown {
				t.Errorf("cooldown = %v, want %v", opened["cooldown"], tc.wantCooldown)
			}
		})
	}
}

// TestRateLimitConcurrentUse exercises the override under the concurrency a
// login path actually sees. Run with -race for it to be meaningful.
func TestRateLimitConcurrentUse(t *testing.T) {
	client := newTestClient(t, rateLimitHandler(retryAfter("1")), WithCircuitBreaker(5, time.Minute))

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.CheckPassword(context.Background(), pwPassword)
		}()
	}
	wg.Wait()
}
