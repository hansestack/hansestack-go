package leakcheck

import (
	"sync"
	"time"
)

// DefaultBreakerCooldown is the time a tripped circuit stays open before a
// single probe is allowed through.
const DefaultBreakerCooldown = 30 * time.Second

// breakerState is the phase of the circuit.
type breakerState uint8

const (
	// breakerClosed lets every request through; this is the zero value, so a
	// client without a configured breaker behaves exactly as before.
	breakerClosed breakerState = iota

	// breakerOpen rejects every request without touching the network.
	breakerOpen

	// breakerHalfOpen lets exactly one probe through to find out whether the
	// API has recovered.
	breakerHalfOpen
)

// breaker is a consecutive-failure circuit breaker.
//
// During an outage every login waits out its own deadline, which makes a
// supplementary check the slowest step of the auth path at the worst possible
// moment. The breaker turns that wait into an immediate fail-open skip and
// probes for recovery. Deliberately minimal — consecutive failures, a
// cooldown, one probe — so it needs no dependency and no background goroutine.
//
// The cooldown is static except in one case. A 429 is an unavailability signal
// like any other, but unlike the others it arrives with the server's own
// answer to "how long": against an RPS bucket that refills in a second, the
// configured 30s would keep the check switched off thirty times longer than
// asked, and every login in that window goes unscreened. So a circuit opened
// by rate limiting alone serves the advertised delta instead. Mixed runs and
// every other failure keep the configured wait — a 429 in the middle of an
// outage says nothing about the outage.
//
// The zero value is disabled: allow reports true, the rest are no-ops. Counts
// are guarded by mu because one Client serves every request goroutine.
type breaker struct {
	threshold int
	cooldown  time.Duration

	// now is swappable in tests; nil means time.Now.
	now func() time.Time

	mu       sync.Mutex
	state    breakerState
	failures int
	openedAt time.Time

	// openCooldown is the wait in force for the current open state, set at
	// the moment the circuit trips and cleared on every trip that is not a
	// rate limit. Zero means the configured cooldown applies.
	//
	// Stamped per open state rather than kept on the breaker because it is a
	// property of why this trip happened, not of how the client is
	// configured. Leaving a previous value in place would let one 429 shorten
	// every later outage cooldown for the life of the process.
	openCooldown time.Duration

	// rateLimitRun records whether every failure in the current consecutive
	// run was a rate limit. Only such a run may take its cooldown from the
	// server: in a mixed run the 429s say nothing about the 5xx that joined
	// them, and a one-second bucket delta applied to an outage would send the
	// breaker back to probing a dead API every second.
	rateLimitRun bool
}

// enabled reports whether a breaker was configured.
func (b *breaker) enabled() bool { return b != nil && b.threshold > 0 }

func (b *breaker) clock() time.Time {
	if b.now != nil {
		return b.now()
	}

	return time.Now()
}

// allow reports whether a request may proceed, moving an expired open circuit
// into the half-open probe state.
//
// It also returns the cooldown the decision was made against, so a caller that
// logs the skip does not have to take the lock a second time to find out — on
// a short-circuited call that second acquisition would be the only cost left,
// and the point of the breaker is that those calls are free. Returning it from
// here also means the value logged is the one that was compared, rather than
// whatever the state happens to be a moment later.
func (b *breaker) allow() (ok bool, cooldown time.Duration) {
	if !b.enabled() {
		return true, 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	cooldown = b.effectiveCooldown()

	switch b.state {
	case breakerOpen:
		if b.clock().Sub(b.openedAt) < cooldown {
			return false, cooldown
		}
		// Cooldown elapsed: let exactly one probe through.
		b.state = breakerHalfOpen

		return true, cooldown
	case breakerHalfOpen:
		// A probe is already in flight; keep short-circuiting the rest.
		return false, cooldown
	default: // breakerClosed
		return true, cooldown
	}
}

// success closes the circuit and clears the failure count.
func (b *breaker) success() {
	if !b.enabled() {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// A success while open belongs to a request that started before the trip.
	// Closing on it would undo a decision made from newer evidence and flap
	// the circuit; only a half-open probe may close it.
	if b.state == breakerOpen {
		return
	}

	b.state = breakerClosed
	b.failures = 0
	b.rateLimitRun = false
}

// effectiveCooldown is the wait in force for the current open state: the delta
// the server advertised when a rate limit opened the circuit, the configured
// cooldown in every other case. The caller holds mu.
func (b *breaker) effectiveCooldown() time.Duration {
	if b.openCooldown > 0 {
		return b.openCooldown
	}

	return b.cooldown
}

// failure records a failed request, tripping the circuit at the threshold. A
// failed probe re-opens it immediately and restarts the cooldown.
//
// It takes the error rather than a bare signal because the cooldown to serve
// depends on what failed: a rate limit advertises its own reset delta, and a
// run of nothing but rate limits should wait that long instead of the
// configured cooldown. Anything else keeps the static wait.
//
// It reports whether this failure opened the circuit, and the cooldown the new
// open state will serve. Opening is a state transition rather than a
// per-request event, so it is the one moment worth a log line naming what
// happened and for how long — without it, an operator can see that the circuit
// is open but not whether it was an outage or the client's own quota that
// opened it, which are two different people's problems.
func (b *breaker) failure(err error) (cooldown time.Duration, tripped bool) {
	if !b.enabled() {
		return 0, false
	}

	resetIn, rateLimited := resetInFor(err)

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == breakerHalfOpen {
		// A failed probe is a run of one, so this result alone decides the
		// cooldown for the new open state.
		b.rateLimitRun = rateLimited

		return b.trip(resetIn), true
	}

	// Same straggler case as in success: re-stamping openedAt would push the
	// cooldown further out on every late failure from before the trip.
	if b.state == breakerOpen {
		return 0, false
	}

	// The run stays "rate limits only" until a failure of another kind joins
	// it, and is re-armed by the first failure after a success.
	b.rateLimitRun = rateLimited && (b.failures == 0 || b.rateLimitRun)

	b.failures++
	if b.failures >= b.threshold {
		return b.trip(resetIn), true
	}

	return 0, false
}

// trip opens the circuit, fixes the cooldown for this open state and returns
// it. The caller holds mu.
//
// openCooldown is assigned on every path, never only on the rate-limit one.
// Left over from an earlier trip it would silently shorten the wait an outage
// gets, which is the opposite of what the override is for.
func (b *breaker) trip(resetIn time.Duration) time.Duration {
	b.state = breakerOpen
	b.openedAt = b.clock()

	b.openCooldown = 0
	if b.rateLimitRun && resetIn > 0 {
		b.openCooldown = resetIn
	}

	return b.effectiveCooldown()
}

// abort discards a probe that returned no verdict about the API's health.
//
// Only success and failure leave half-open, and allow rejects everything while
// it lasts, so without this the circuit would stay there for the life of the
// process. openedAt is left untouched: the cooldown stays elapsed and the next
// caller probes at once rather than serving time for someone else's cancelled
// request.
func (b *breaker) abort() {
	if !b.enabled() {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state != breakerHalfOpen {
		return
	}

	b.state = breakerOpen
}
