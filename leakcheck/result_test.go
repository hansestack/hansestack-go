package leakcheck

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestCheckOutcomeOnSuccess covers the two outcomes that mean the API
// answered: a hit and a clean miss must both report OutcomeChecked, because
// only then is Leaked authoritative.
func TestCheckOutcomeOnSuccess(t *testing.T) {
	t.Run("leaked", func(t *testing.T) {
		client := newTestClient(t, jsonHandler(`{"`+suffixPassword+`":42}`))

		res, err := client.CheckPassword(context.Background(), pwPassword)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !res.Leaked || res.Count != 42 {
			t.Errorf("got (leaked=%v, count=%d), want (true, 42)", res.Leaked, res.Count)
		}
		if res.Outcome != OutcomeChecked {
			t.Errorf("outcome = %v, want checked", res.Outcome)
		}
		if !res.Outcome.Checked() {
			t.Error("Outcome.Checked() = false, want true")
		}
	})

	t.Run("clean miss", func(t *testing.T) {
		client := newTestClient(t, jsonHandler(`{}`))

		res, err := client.CheckPassword(context.Background(), pwPassword)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if res.Leaked || res.Count != 0 {
			t.Errorf("got (leaked=%v, count=%d), want (false, 0)", res.Leaked, res.Count)
		}
		if res.Outcome != OutcomeChecked {
			t.Errorf("outcome = %v, want checked", res.Outcome)
		}
	})
}

// TestCheckDistinguishesSkipFromMiss is the point of the whole type: under
// fail-open a skipped check and a clean miss return the same Leaked and Count,
// and only Outcome tells them apart.
func TestCheckDistinguishesSkipFromMiss(t *testing.T) {
	miss := newTestClient(t, jsonHandler(`{}`))
	skipped := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	missRes, missErr := miss.CheckPassword(context.Background(), pwPassword)
	skipRes, skipErr := skipped.CheckPassword(context.Background(), pwPassword)

	if missErr != nil || skipErr != nil {
		t.Fatalf("fail-open must not return errors, got %v and %v", missErr, skipErr)
	}
	if missRes.Leaked != skipRes.Leaked || missRes.Count != skipRes.Count {
		t.Fatal("precondition failed: the verdict fields are expected to be identical")
	}
	if missRes.Outcome == skipRes.Outcome {
		t.Fatalf("both outcomes are %v; the skip is indistinguishable from a miss", missRes.Outcome)
	}
	if !missRes.Outcome.Checked() {
		t.Error("miss must report Checked() = true")
	}
	if skipRes.Outcome.Checked() {
		t.Error("skip must report Checked() = false")
	}
}

// TestCheckOutcomeClassification pins each failure class to the outcome a
// caller is expected to alert on.
func TestCheckOutcomeClassification(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		opts    []Option
		want    Outcome
	}{
		{
			name:    "rate limited",
			handler: statusHandler(http.StatusTooManyRequests),
			want:    OutcomeSkippedRateLimited,
		},
		{
			name:    "upstream fault",
			handler: statusHandler(http.StatusBadGateway),
			want:    OutcomeSkippedError,
		},
		{
			name:    "invalid api key",
			handler: statusHandler(http.StatusUnauthorized),
			want:    OutcomeSkippedError,
		},
		{
			name:    "unreadable body",
			handler: jsonHandler(`not json`),
			want:    OutcomeSkippedError,
		},
		{
			name: "timeout",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(200 * time.Millisecond)
			},
			opts: []Option{WithTimeout(20 * time.Millisecond)},
			want: OutcomeSkippedTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestClient(t, tc.handler, tc.opts...)

			res, err := client.CheckPassword(context.Background(), pwPassword)
			if err != nil {
				t.Fatalf("fail-open must swallow the failure, got %v", err)
			}
			if res.Outcome != tc.want {
				t.Errorf("outcome = %v, want %v", res.Outcome, tc.want)
			}
			if res.Leaked || res.Count != 0 {
				t.Errorf("got (leaked=%v, count=%d), want the neutral (false, 0)", res.Leaked, res.Count)
			}
		})
	}
}

// TestCheckFailCloseKeepsOutcome proves the two mechanisms are independent:
// fail-close still returns the sentinel error, and the outcome is populated
// either way.
func TestCheckFailCloseKeepsOutcome(t *testing.T) {
	client := newTestClient(t, statusHandler(http.StatusTooManyRequests), WithFailClose())

	res, err := client.CheckPassword(context.Background(), pwPassword)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if res.Outcome != OutcomeSkippedRateLimited {
		t.Errorf("outcome = %v, want skipped_rate_limited", res.Outcome)
	}
}

// TestOutcomeString locks the identifiers, which are used as metric labels and
// therefore must stay stable.
func TestOutcomeString(t *testing.T) {
	tests := map[Outcome]string{
		OutcomeUnknown:            "unknown",
		OutcomeChecked:            "checked",
		OutcomeSkippedTimeout:     "skipped_timeout",
		OutcomeSkippedRateLimited: "skipped_rate_limited",
		OutcomeSkippedError:       "skipped_error",
		OutcomeSkippedCanceled:    "skipped_canceled",
		OutcomeSkippedCircuitOpen: "skipped_circuit_open",
		Outcome(200):              "Outcome(200)",
	}

	for outcome, want := range tests {
		if got := outcome.String(); got != want {
			t.Errorf("Outcome(%d).String() = %q, want %q", uint8(outcome), got, want)
		}
	}
}

// TestZeroResultIsNotChecked makes sure an unpopulated Result cannot be
// mistaken for a completed check.
func TestZeroResultIsNotChecked(t *testing.T) {
	var res Result

	if res.Outcome.Checked() {
		t.Error("zero Result reports Checked() = true")
	}
	if res.Outcome != OutcomeUnknown {
		t.Errorf("zero outcome = %v, want unknown", res.Outcome)
	}
}

// TestCheckDistinguishesCancellationFromTimeout keeps the two apart at the
// only place it matters: a dashboard. A client disconnect filed under
// skipped_timeout reads as "the API got slow" and sends someone chasing an
// outage that never happened.
func TestCheckDistinguishesCancellationFromTimeout(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hold until the caller gives up
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	res, err := client.CheckPassword(ctx, pwPassword)
	if err != nil {
		t.Fatalf("fail-open must swallow the cancellation, got %v", err)
	}
	if res.Outcome != OutcomeSkippedCanceled {
		t.Errorf("outcome = %v, want skipped_canceled", res.Outcome)
	}
	if res.Outcome.Checked() {
		t.Error("a cancelled check reports Checked() = true")
	}
}

// TestOutcomeTextRoundTrip covers the encoding both ways. Marshalling alone
// would leave a Result that serialises but no longer decodes.
func TestOutcomeTextRoundTrip(t *testing.T) {
	for _, want := range []Outcome{
		OutcomeUnknown,
		OutcomeChecked,
		OutcomeSkippedTimeout,
		OutcomeSkippedRateLimited,
		OutcomeSkippedError,
		OutcomeSkippedCanceled,
		OutcomeSkippedCircuitOpen,
	} {
		text, err := want.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", want, err)
		}
		if string(text) != want.String() {
			t.Errorf("MarshalText = %q, want %q", text, want.String())
		}

		var got Outcome
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if got != want {
			t.Errorf("round trip = %v, want %v", got, want)
		}
	}
}

// TestOutcomeUnmarshalRejectsUnknownLabel guards the decision not to fall back
// to OutcomeUnknown: silently decoding an unrecognised label would claim the
// check never ran, which is a statement about security posture.
func TestOutcomeUnmarshalRejectsUnknownLabel(t *testing.T) {
	var o Outcome

	if err := o.UnmarshalText([]byte("skipped_teapot")); err == nil {
		t.Fatal("UnmarshalText accepted an unknown label")
	}
	if o != OutcomeUnknown {
		t.Errorf("outcome = %v, want it left untouched", o)
	}
}

// TestResultJSONUsesLabels is the reason MarshalText exists: a Result in a
// structured log line has to be readable and groupable, not an integer whose
// meaning depends on the version that wrote it.
func TestResultJSONUsesLabels(t *testing.T) {
	blob, err := json.Marshal(Result{Outcome: OutcomeSkippedRateLimited})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(blob), `{"Leaked":false,"Count":0,"Outcome":"skipped_rate_limited"}`; got != want {
		t.Errorf("json = %s, want %s", got, want)
	}

	var back Result
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Outcome != OutcomeSkippedRateLimited {
		t.Errorf("decoded outcome = %v, want skipped_rate_limited", back.Outcome)
	}
}

// statusHandler serves an empty response with the given status code.
func statusHandler(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}
}
