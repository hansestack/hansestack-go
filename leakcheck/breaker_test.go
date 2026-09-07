package leakcheck

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBreakerDisabledByDefault guards the compatibility promise: a client
// built without the option must keep hitting the API however often it fails.
func TestBreakerDisabledByDefault(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	for range 5 {
		if _, err := client.CheckPassword(context.Background(), pwPassword); err != nil {
			t.Fatalf("fail-open must swallow the failure, got %v", err)
		}
	}

	if got := hits.Load(); got != 5 {
		t.Errorf("requests = %d, want 5 — the default must not short-circuit", got)
	}
}

// TestBreakerOpensAfterThreshold is the reason the breaker exists: once the
// API is down, further logins must not pay the request timeout.
func TestBreakerOpensAfterThreshold(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}, WithCircuitBreaker(3, time.Minute))

	for range 10 {
		if _, err := client.CheckPassword(context.Background(), pwPassword); err != nil {
			t.Fatalf("fail-open must swallow the failure, got %v", err)
		}
	}

	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — the circuit should have opened after the threshold", got)
	}
}

// TestBreakerResetsOnSuccess proves the counter tracks *consecutive* failures,
// so intermittent errors never trip a healthy service.
func TestBreakerResetsOnSuccess(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		// Fail on every odd request, succeed on every even one.
		if hits.Add(1)%2 == 1 {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}, WithCircuitBreaker(2, time.Minute))

	for range 10 {
		if _, err := client.CheckPassword(context.Background(), pwPassword); err != nil {
			t.Fatalf("fail-open must swallow the failure, got %v", err)
		}
	}

	if got := hits.Load(); got != 10 {
		t.Errorf("requests = %d, want 10 — alternating failures must not trip the breaker", got)
	}
}

// TestBreakerHalfOpenProbe covers recovery: after the cooldown exactly one
// request is let through, and a success closes the circuit again.
func TestBreakerHalfOpenProbe(t *testing.T) {
	var (
		hits    atomic.Int64
		healthy atomic.Bool
	)
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	// Trip it, then confirm it is short-circuiting.
	for range 4 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 before the cooldown", got)
	}

	// Cooldown elapses and the service recovers.
	now = now.Add(2 * time.Minute)
	healthy.Store(true)

	mustCheck(t, client) // the probe
	if got := hits.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 — exactly one probe should pass", got)
	}

	// Circuit closed again: everything flows.
	for range 3 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 6 {
		t.Errorf("requests = %d, want 6 — the circuit should be closed after a successful probe", got)
	}
}

// TestBreakerFailedProbeReopens makes sure a still-broken service does not get
// hammered again after one cooldown.
func TestBreakerFailedProbeReopens(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range 4 {
		mustCheck(t, client)
	}
	now = now.Add(2 * time.Minute)

	mustCheck(t, client) // the probe, which fails
	for range 5 {
		mustCheck(t, client)
	}

	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — a failed probe must re-open the circuit", got)
	}
}

// TestBreakerIgnoresCallerCancellation guards a failure mode invisible in
// production: if abandoned logins counted as failures, impatient users alone
// could declare a healthy API dead.
func TestBreakerIgnoresCallerCancellation(t *testing.T) {
	var hits atomic.Int64
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done() // hold until the caller gives up
	}, WithCircuitBreaker(2, time.Minute))

	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		if _, err := client.CheckPassword(ctx, pwPassword); err != nil {
			t.Fatalf("fail-open must swallow the cancellation, got %v", err)
		}
		cancel()
	}

	if got := hits.Load(); got != 5 {
		t.Errorf("requests = %d, want 5 - cancellations must not trip the breaker", got)
	}
	if client.breaker.state != breakerClosed {
		t.Errorf("breaker state = %v, want closed", client.breaker.state)
	}
}

// TestBreakerCancelledProbeDoesNotWedge covers the nastiest state the machine
// can reach: only a completed probe leaves half-open, so a probe whose caller
// cancels would strand the circuit there and short-circuit every later request
// for the life of the process — a permanently disabled check on a healthy API.
func TestBreakerCancelledProbeDoesNotWedge(t *testing.T) {
	var (
		hits    atomic.Int64
		hang    atomic.Bool
		healthy atomic.Bool
	)
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case hang.Load():
			<-r.Context().Done()
		case healthy.Load():
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range 4 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 before the cooldown", got)
	}

	// Cooldown elapses, and the caller of the probe walks away.
	now = now.Add(2 * time.Minute)
	hang.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if _, err := client.CheckPassword(ctx, pwPassword); err != nil {
		t.Fatalf("fail-open must swallow the cancellation, got %v", err)
	}
	cancel()

	if got := hits.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 — the probe should have been let through", got)
	}

	// The service is fine; the next caller must be able to find that out.
	hang.Store(false)
	healthy.Store(true)

	mustCheck(t, client)
	if got := hits.Load(); got != 4 {
		t.Fatalf("requests = %d, want 4 — a cancelled probe must not strand the circuit", got)
	}
	if client.breaker.state != breakerClosed {
		t.Errorf("breaker state = %v, want closed after a successful probe", client.breaker.state)
	}
}

// TestBreakerStragglerSuccessKeepsCircuitOpen covers a request that started
// before the trip and lands after it. Closing on that stale evidence would
// undo a decision made from newer data and flap the circuit.
func TestBreakerStragglerSuccessKeepsCircuitOpen(t *testing.T) {
	b := &breaker{threshold: 2, cooldown: time.Minute}

	b.failure()
	b.failure()
	if b.allow() {
		t.Fatal("circuit did not open at the threshold")
	}

	b.success()

	if b.allow() {
		t.Error("a late success from before the trip reopened the circuit")
	}
}

// TestBreakerStragglerFailureDoesNotExtendCooldown covers the same race in the
// other direction: late failures must not re-stamp openedAt, or a burst of
// them would keep pushing recovery further out.
func TestBreakerStragglerFailureDoesNotExtendCooldown(t *testing.T) {
	now := time.Now()
	b := &breaker{threshold: 2, cooldown: time.Minute, now: func() time.Time { return now }}

	b.failure()
	b.failure()
	openedAt := b.openedAt

	now = now.Add(30 * time.Second)
	b.failure() // the straggler

	if !b.openedAt.Equal(openedAt) {
		t.Errorf("openedAt moved from %v to %v", openedAt, b.openedAt)
	}

	now = now.Add(31 * time.Second) // 61s after the trip, cooldown is 60s
	if !b.allow() {
		t.Error("cooldown did not elapse — a late failure pushed it forward")
	}
}

// TestBreakerCountsOnlyUnavailability pins what is worth tripping on. The
// breaker exists to stop paying the request timeout during an outage; a
// rejected key answers instantly, so counting it would buy no latency back and
// would hide the real error. Rate limiting is the exception: backing off is
// the correct response to it.
func TestBreakerCountsOnlyUnavailability(t *testing.T) {
	const (
		threshold = 2
		attempts  = 5
	)

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		wantHits int64
	}{
		{"5xx is an outage", statusHandlerBreaker(http.StatusInternalServerError), threshold},
		{"429 is worth backing off from", statusHandlerBreaker(http.StatusTooManyRequests), threshold},
		{"401 is a broken integration", statusHandlerBreaker(http.StatusUnauthorized), attempts},
		{"400 is a client bug", statusHandlerBreaker(http.StatusBadRequest), attempts},
		{"an off-contract status is not an outage", statusHandlerBreaker(http.StatusMultipleChoices), attempts},
		{"a malformed body is not an outage", jsonHandler(`{"truncated":`), attempts},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				tc.handler(w, r)
			}, WithCircuitBreaker(threshold, time.Minute))

			for range attempts {
				mustCheck(t, client)
			}

			if got := hits.Load(); got != tc.wantHits {
				t.Errorf("requests = %d, want %d", got, tc.wantHits)
			}
		})
	}
}

// TestBreakerDoesNotMaskIntegrationErrors is the operator-facing half of the
// same rule: a bad API key must keep reporting itself as one, not turn into an
// outage symptom after a few attempts.
func TestBreakerDoesNotMaskIntegrationErrors(t *testing.T) {
	client := newTestClient(t, statusHandlerBreaker(http.StatusUnauthorized),
		WithCircuitBreaker(1, time.Minute), WithFailClose())

	for range 3 {
		_, err := client.CheckPassword(context.Background(), pwPassword)
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("error = %v, want ErrUnauthorized on every attempt", err)
		}
	}
}

// TestBreakerFailClose surfaces the sentinel so an operator can tell a
// short-circuited check from a real request failure.
func TestBreakerFailClose(t *testing.T) {
	client := newTestClient(t, statusHandlerBreaker(http.StatusInternalServerError),
		WithCircuitBreaker(1, time.Minute), WithFailClose())

	if _, err := client.CheckPassword(context.Background(), pwPassword); !errors.Is(err, ErrServerError) {
		t.Fatalf("first error = %v, want ErrServerError", err)
	}

	res, err := client.CheckPassword(context.Background(), pwPassword)
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("second error = %v, want ErrCircuitOpen", err)
	}
	if res.Outcome != OutcomeSkippedCircuitOpen {
		t.Errorf("outcome = %v, want skipped_circuit_open", res.Outcome)
	}
}

// TestBreakerOutcomeIsCountableApartFromErrors is the observability contract:
// during an outage the first call pays a full timeout and every later one is
// free. Both are skips, but merged onto one metric label a working breaker and
// a breaker that never tripped look identical.
func TestBreakerOutcomeIsCountableApartFromErrors(t *testing.T) {
	client := newTestClient(t, statusHandlerBreaker(http.StatusInternalServerError),
		WithCircuitBreaker(1, time.Minute))

	attempted, err := client.CheckPassword(context.Background(), pwPassword)
	if err != nil {
		t.Fatalf("fail-open must swallow the failure, got %v", err)
	}
	if attempted.Outcome != OutcomeSkippedError {
		t.Fatalf("attempted call outcome = %v, want skipped_error", attempted.Outcome)
	}

	shortCircuited, err := client.CheckPassword(context.Background(), pwPassword)
	if err != nil {
		t.Fatalf("fail-open must swallow the short circuit, got %v", err)
	}
	if shortCircuited.Outcome != OutcomeSkippedCircuitOpen {
		t.Errorf("short-circuited outcome = %v, want skipped_circuit_open", shortCircuited.Outcome)
	}
	if shortCircuited.Leaked || shortCircuited.Count != 0 {
		t.Errorf("result = %+v, want the neutral fail-open values", shortCircuited)
	}
}

// TestBreakerOptionValidation pins the two guard rails that keep a missing or
// malformed configuration from changing behaviour unexpectedly.
func TestBreakerOptionValidation(t *testing.T) {
	t.Run("non-positive threshold leaves the breaker off", func(t *testing.T) {
		for _, threshold := range []int{0, -1} {
			c := NewClient("k", WithCircuitBreaker(threshold, time.Minute))
			if c.breaker.enabled() {
				t.Errorf("threshold %d enabled the breaker", threshold)
			}
		}
	})

	t.Run("non-positive cooldown falls back to the default", func(t *testing.T) {
		c := NewClient("k", WithCircuitBreaker(3, 0))
		if c.breaker.cooldown != DefaultBreakerCooldown {
			t.Errorf("cooldown = %v, want %v", c.breaker.cooldown, DefaultBreakerCooldown)
		}
	})
}

// TestBreakerConcurrentUse exercises the breaker under the concurrency a login
// path actually sees; run with -race for it to be meaningful.
func TestBreakerConcurrentUse(t *testing.T) {
	client := newTestClient(t, statusHandlerBreaker(http.StatusInternalServerError),
		WithCircuitBreaker(5, time.Minute))

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

func mustCheck(t *testing.T, c *Client) {
	t.Helper()

	if _, err := c.CheckPassword(context.Background(), pwPassword); err != nil {
		t.Fatalf("fail-open must swallow the failure, got %v", err)
	}
}

func statusHandlerBreaker(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}
}
