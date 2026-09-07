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
func (b *breaker) allow() bool {
	if !b.enabled() {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case breakerOpen:
		if b.clock().Sub(b.openedAt) < b.cooldown {
			return false
		}
		// Cooldown elapsed: let exactly one probe through.
		b.state = breakerHalfOpen

		return true
	case breakerHalfOpen:
		// A probe is already in flight; keep short-circuiting the rest.
		return false
	default: // breakerClosed
		return true
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
}

// failure records a failed request, tripping the circuit at the threshold. A
// failed probe re-opens it immediately and restarts the cooldown.
func (b *breaker) failure() {
	if !b.enabled() {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == breakerHalfOpen {
		b.state = breakerOpen
		b.openedAt = b.clock()

		return
	}

	// Same straggler case as in success: re-stamping openedAt would push the
	// cooldown further out on every late failure from before the trip.
	if b.state == breakerOpen {
		return
	}

	b.failures++
	if b.failures >= b.threshold {
		b.state = breakerOpen
		b.openedAt = b.clock()
	}
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
