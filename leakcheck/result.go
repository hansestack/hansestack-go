package leakcheck

import (
	"context"
	"errors"
	"fmt"
)

// Outcome reports whether a check actually reached the API, and if not, why.
//
// Under fail-open a skipped check and a clean miss are both reported as "not
// leaked" — correct for availability, but on its own it hides how often the
// control did not run. Outcome exposes that without changing the policy, as a
// metric label or an input to a risk decision.
type Outcome uint8

const (
	// OutcomeUnknown is the zero value and is never returned by this package.
	// It exists so that a Result{} that was never populated cannot pass
	// itself off as a completed check.
	OutcomeUnknown Outcome = iota

	// OutcomeChecked means the API answered and the verdict in
	// [Result.Leaked] is authoritative.
	OutcomeChecked

	// OutcomeSkippedTimeout means the request did not complete within the
	// deadline, either the client timeout or an earlier one carried by the
	// caller's context.
	OutcomeSkippedTimeout

	// OutcomeSkippedRateLimited means the API answered 429. It is reported
	// separately because it is the one skip reason that is self-inflicted and
	// resolved by changing the caller's request rate or plan.
	OutcomeSkippedRateLimited

	// OutcomeSkippedError covers every other failure: connection errors,
	// upstream 5xx, an unreadable body, and misconfiguration such as an
	// invalid API key.
	OutcomeSkippedError

	// OutcomeSkippedCanceled means the caller's context was cancelled — a
	// user who navigated away. Kept apart from OutcomeSkippedTimeout so a
	// rise in timeouts still means the API got slow, which is what someone
	// reading the dashboard will assume.
	//
	// Appended rather than inserted: the numeric values never shift.
	OutcomeSkippedCanceled

	// OutcomeSkippedCircuitOpen means [WithCircuitBreaker] short-circuited the
	// call and no request was sent. Kept apart from OutcomeSkippedError for
	// the same reason: during an outage the two describe different things —
	// one call paid the timeout, the rest cost nothing — and a dashboard that
	// merges them cannot show that the breaker is doing its job.
	OutcomeSkippedCircuitOpen
)

// String returns a short, stable, lower-case identifier suitable for use as a
// metric label or a log attribute.
func (o Outcome) String() string {
	switch o {
	case OutcomeChecked:
		return "checked"
	case OutcomeSkippedTimeout:
		return "skipped_timeout"
	case OutcomeSkippedRateLimited:
		return "skipped_rate_limited"
	case OutcomeSkippedError:
		return "skipped_error"
	case OutcomeSkippedCanceled:
		return "skipped_canceled"
	case OutcomeSkippedCircuitOpen:
		return "skipped_circuit_open"
	case OutcomeUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("Outcome(%d)", uint8(o))
	}
}

// MarshalText implements [encoding.TextMarshaler], so a [Result] in a JSON
// log line carries the label. Without it encoding/json writes the integer
// behind the constant: nothing to group by, and a different meaning as soon
// as the constants are reordered.
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText implements [encoding.TextUnmarshaler], so a [Result] that
// marshals still decodes.
//
// An unrecognised label is an error, not [OutcomeUnknown]: falling back to the
// zero value would report a label this version does not know yet as "the check
// never ran", which is not something to guess at.
func (o *Outcome) UnmarshalText(text []byte) error {
	switch string(text) {
	case "checked":
		*o = OutcomeChecked
	case "skipped_timeout":
		*o = OutcomeSkippedTimeout
	case "skipped_rate_limited":
		*o = OutcomeSkippedRateLimited
	case "skipped_error":
		*o = OutcomeSkippedError
	case "skipped_canceled":
		*o = OutcomeSkippedCanceled
	case "skipped_circuit_open":
		*o = OutcomeSkippedCircuitOpen
	case "unknown":
		*o = OutcomeUnknown
	default:
		return fmt.Errorf("leakcheck: unknown outcome %q", text)
	}

	return nil
}

// Checked reports whether the API answered, and therefore whether
// [Result.Leaked] carries a verdict rather than a fail-open placeholder.
func (o Outcome) Checked() bool { return o == OutcomeChecked }

// Result is the outcome of a single leak check.
//
// Leaked and Count are only meaningful when [Result.Outcome] is
// [OutcomeChecked]; for every other outcome they hold the neutral fail-open
// values false and 0.
type Result struct {
	// Leaked reports whether the password appears in the breach corpus.
	Leaked bool

	// Count is how many times the password was seen, zero when not leaked.
	Count int

	// Outcome reports whether the check ran, and if not, why not.
	Outcome Outcome
}

// outcomeFor classifies a fetchPrefix error into the skip reason a caller can
// act on. It reads the sentinels the package already returns rather than
// duplicating the status-code logic that produced them.
func outcomeFor(err error) Outcome {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return OutcomeSkippedTimeout
	case errors.Is(err, context.Canceled):
		return OutcomeSkippedCanceled
	case errors.Is(err, ErrRateLimited):
		return OutcomeSkippedRateLimited
	case errors.Is(err, ErrCircuitOpen):
		return OutcomeSkippedCircuitOpen
	default:
		return OutcomeSkippedError
	}
}
