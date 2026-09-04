package leakcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Known SHA-1 digests, uppercased and split after the 5-character prefix.
// Verified independently with `printf '%s' <password> | shasum -a 1`.
const (
	// SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	pwPassword       = "password"
	prefixPassword   = "5BAA6"
	suffixPassword   = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	pwPasswordDigest = prefixPassword + suffixPassword

	// SHA1("hunter2") = F3BBBD66A63D4BF1747940578EC3D0103530E21D
	pwHunter2     = "hunter2"
	prefixHunter2 = "F3BBB"
	suffixHunter2 = "D66A63D4BF1747940578EC3D0103530E21D"

	// SHA1("") = DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
	prefixEmpty = "DA39A"
	suffixEmpty = "3EE5E6B4B0D3255BFEF95601890AFD80709"
)

// newTestClient starts an httptest server with the given handler and returns a
// client pointed at it. The server is closed automatically when the test ends.
func newTestClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return NewClient("test-key", append([]Option{withBaseURL(srv.URL)}, opts...)...)
}

// jsonHandler serves body as a 200 JSON response.
func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		wantPrefix string
		wantSuffix string
	}{
		{
			name:       "known digest for password",
			password:   pwPassword,
			wantPrefix: prefixPassword,
			wantSuffix: suffixPassword,
		},
		{
			name:       "known digest for hunter2",
			password:   pwHunter2,
			wantPrefix: prefixHunter2,
			wantSuffix: suffixHunter2,
		},
		{
			name:       "empty password still hashes",
			password:   "",
			wantPrefix: prefixEmpty,
			wantSuffix: suffixEmpty,
		},
		{
			name:       "unicode password is hashed over utf-8 bytes",
			password:   "パスワード",
			wantPrefix: "A9694",
			wantSuffix: "DC2E83BF1D3DD839259EAEB984FBBD86B31",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix, suffix := hashPassword(tc.password)

			if prefix != tc.wantPrefix {
				t.Errorf("prefix = %q, want %q", prefix, tc.wantPrefix)
			}
			if suffix != tc.wantSuffix {
				t.Errorf("suffix = %q, want %q", suffix, tc.wantSuffix)
			}
			if len(prefix) != prefixLength {
				t.Errorf("prefix length = %d, want %d", len(prefix), prefixLength)
			}
			if len(suffix) != 40-prefixLength {
				t.Errorf("suffix length = %d, want %d", len(suffix), 40-prefixLength)
			}
			if got := prefix + suffix; got != strings.ToUpper(got) {
				t.Errorf("digest %q is not uppercase", got)
			}
		})
	}
}

// TestCheckPasswordStatuses exercises every documented response shape against
// both failure policies. Fail-open must always report a neutral result with a
// nil error; fail-close must surface the matching sentinel.
func TestCheckPasswordStatuses(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantFound bool
		wantCount int
		wantErr   error // nil means the check succeeds in both modes
	}{
		{
			name: "suffix present reports leaked with count",
			handler: jsonHandler(fmt.Sprintf(
				`{"%s": 12345, "0000000000000000000000000000000000A": 1}`, suffixPassword)),
			wantFound: true,
			wantCount: 12345,
		},
		{
			name: "suffix absent reports not leaked",
			handler: jsonHandler(
				`{"0000000000000000000000000000000000A": 1, "0000000000000000000000000000000000B": 2}`),
		},
		{
			name:    "empty bucket reports not leaked",
			handler: jsonHandler(`{}`),
		},
		{
			name: "lookup is case sensitive so lowercase suffix does not match",
			handler: jsonHandler(fmt.Sprintf(
				`{"%s": 99}`, strings.ToLower(suffixPassword))),
		},
		{
			name:      "count of zero is honoured as reported",
			handler:   jsonHandler(fmt.Sprintf(`{"%s": 0}`, suffixPassword)),
			wantFound: true,
			wantCount: 0,
		},
		{
			name:    "malformed json is an invalid response",
			handler: jsonHandler(`{"truncated":`),
			wantErr: ErrInvalidResponse,
		},
		{
			name:    "json array instead of object is an invalid response",
			handler: jsonHandler(`["not", "an", "object"]`),
			wantErr: ErrInvalidResponse,
		},
		{
			name: "429 is rate limited and never retried",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-RateLimit-Limit", "10")
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "1893456000")
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantErr: ErrRateLimited,
		},
		{
			name: "401 is unauthorized",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "403 is unauthorized",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "400 is a bad request",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			wantErr: ErrBadRequest,
		},
		{
			name: "404 is a bad request",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: ErrBadRequest,
		},
		{
			name: "500 is a server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: ErrServerError,
		},
		{
			name: "503 is a server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantErr: ErrServerError,
		},
		{
			name: "300 is an unexpected status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusMultipleChoices)
			},
			wantErr: ErrUnexpectedStatus,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("fail-open", func(t *testing.T) {
				client := newTestClient(t, tc.handler)

				found, count, err := client.CheckPassword(context.Background(), pwPassword)
				if err != nil {
					t.Fatalf("fail-open returned error %v, want nil", err)
				}
				if found != tc.wantFound {
					t.Errorf("leaked = %v, want %v", found, tc.wantFound)
				}
				if count != tc.wantCount {
					t.Errorf("count = %d, want %d", count, tc.wantCount)
				}
			})

			t.Run("fail-close", func(t *testing.T) {
				client := newTestClient(t, tc.handler, WithFailClose())

				found, count, err := client.CheckPassword(context.Background(), pwPassword)

				if tc.wantErr == nil {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if found != tc.wantFound {
						t.Errorf("leaked = %v, want %v", found, tc.wantFound)
					}
					if count != tc.wantCount {
						t.Errorf("count = %d, want %d", count, tc.wantCount)
					}

					return
				}

				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want errors.Is(_, %v)", err, tc.wantErr)
				}
				if found {
					t.Error("leaked = true on error, want false")
				}
				if count != 0 {
					t.Errorf("count = %d on error, want 0", count)
				}
			})
		})
	}
}

// TestRequestShape pins the wire contract: method, path, headers, and the
// k-anonymity guarantee that nothing beyond the 5-character prefix is sent.
func TestRequestShape(t *testing.T) {
	var got *http.Request
	var body []byte

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		body, _ = readAll(r)
		_, _ = w.Write([]byte(`{}`))
	})

	if _, _, err := client.CheckPassword(context.Background(), pwPassword); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got == nil {
		t.Fatal("handler was never called")
	}
	if got.Method != http.MethodGet {
		t.Errorf("method = %q, want %q", got.Method, http.MethodGet)
	}
	if want := "/v1/prefixes/" + prefixPassword; got.URL.Path != want {
		t.Errorf("path = %q, want %q", got.URL.Path, want)
	}
	if got.URL.RawQuery != "" {
		t.Errorf("query = %q, want empty", got.URL.RawQuery)
	}
	if v := got.Header.Get("X-API-Key"); v != "test-key" {
		t.Errorf("X-API-Key = %q, want %q", v, "test-key")
	}
	if v := got.Header.Get("Accept"); v != "application/json" {
		t.Errorf("Accept = %q, want application/json", v)
	}
	if len(body) != 0 {
		t.Errorf("request body = %q, want empty", body)
	}

	// The k-anonymity guarantee: the plaintext, the full digest and the
	// suffix must appear nowhere in the request.
	var dump strings.Builder
	dump.WriteString(got.URL.String())
	for name, values := range got.Header {
		dump.WriteString(name)
		dump.WriteString(strings.Join(values, ","))
	}
	dump.Write(body)

	haystack := strings.ToUpper(dump.String())
	for _, secret := range []string{
		strings.ToUpper(pwPassword),
		pwPasswordDigest,
		suffixPassword,
	} {
		if strings.Contains(haystack, secret) {
			t.Errorf("request leaked %q; only the prefix may be transmitted", secret)
		}
	}
}

// readAll drains a request body, returning nil when there is none.
func readAll(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// TestPrefixIsDerivedPerPassword guards against a prefix accidentally being
// cached or shared between calls on the same client.
func TestPrefixIsDerivedPerPassword(t *testing.T) {
	var paths []string

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	})

	for _, pw := range []string{pwPassword, pwHunter2, ""} {
		if _, _, err := client.CheckPassword(context.Background(), pw); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	want := []string{
		"/v1/prefixes/" + prefixPassword,
		"/v1/prefixes/" + prefixHunter2,
		"/v1/prefixes/" + prefixEmpty,
	}
	if len(paths) != len(want) {
		t.Fatalf("got %d requests, want %d", len(paths), len(want))
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("request %d path = %q, want %q", i, paths[i], want[i])
		}
	}
}

// TestTimeout verifies the explicit deadline: a slow upstream must not stall
// the caller, and the fail-open path must absorb the expiry.
func TestTimeout(t *testing.T) {
	released := make(chan struct{})
	t.Cleanup(func() { close(released) })

	slow := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-released:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte(`{}`))
	}

	t.Run("fail-open swallows the timeout", func(t *testing.T) {
		client := newTestClient(t, slow, WithTimeout(50*time.Millisecond))

		start := time.Now()
		found, count, err := client.CheckPassword(context.Background(), pwPassword)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("fail-open returned error %v, want nil", err)
		}
		if found || count != 0 {
			t.Errorf("got (%v, %d), want (false, 0)", found, count)
		}
		if elapsed > time.Second {
			t.Errorf("call took %v, want it bounded by the 50ms timeout", elapsed)
		}
	})

	t.Run("fail-close reports the deadline", func(t *testing.T) {
		client := newTestClient(t, slow, WithTimeout(50*time.Millisecond), WithFailClose())

		_, _, err := client.CheckPassword(context.Background(), pwPassword)

		if !errors.Is(err, ErrRequestFailed) {
			t.Fatalf("error = %v, want errors.Is(_, ErrRequestFailed)", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
		}
	})
}

// TestCallerDeadlineWins verifies that a context deadline shorter than the
// client timeout takes precedence.
func TestCallerDeadlineWins(t *testing.T) {
	released := make(chan struct{})
	t.Cleanup(func() { close(released) })

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-released:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte(`{}`))
	}, WithTimeout(10*time.Second), WithFailClose())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := client.CheckPassword(ctx, pwPassword)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("call took %v, want it bounded by the caller's 50ms deadline", elapsed)
	}
}

// TestNetworkError covers a connection that cannot be established at all.
func TestNetworkError(t *testing.T) {
	// Start and immediately stop a server so the port is closed but routable.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	t.Run("fail-open", func(t *testing.T) {
		client := NewClient("k", withBaseURL(deadURL))

		found, count, err := client.CheckPassword(context.Background(), pwPassword)
		if err != nil {
			t.Fatalf("fail-open returned error %v, want nil", err)
		}
		if found || count != 0 {
			t.Errorf("got (%v, %d), want (false, 0)", found, count)
		}
	})

	t.Run("fail-close", func(t *testing.T) {
		client := NewClient("k", withBaseURL(deadURL), WithFailClose())

		if _, _, err := client.CheckPassword(context.Background(), pwPassword); !errors.Is(err, ErrRequestFailed) {
			t.Fatalf("error = %v, want errors.Is(_, ErrRequestFailed)", err)
		}
	})
}

// TestCanceledContext verifies that an already-canceled caller context is
// handled by the configured policy rather than panicking or hanging.
func TestCanceledContext(t *testing.T) {
	handler := jsonHandler(`{}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("fail-open", func(t *testing.T) {
		client := newTestClient(t, handler)

		found, count, err := client.CheckPassword(ctx, pwPassword)
		if err != nil {
			t.Fatalf("fail-open returned error %v, want nil", err)
		}
		if found || count != 0 {
			t.Errorf("got (%v, %d), want (false, 0)", found, count)
		}
	})

	t.Run("fail-close", func(t *testing.T) {
		client := newTestClient(t, handler, WithFailClose())

		_, _, err := client.CheckPassword(ctx, pwPassword)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	})
}

// TestNoRetries pins the single-attempt contract for the statuses most likely
// to tempt a retry.
func TestNoRetries(t *testing.T) {
	for _, status := range []int{
		http.StatusInternalServerError,
		http.StatusTooManyRequests,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32

			client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
			})

			if _, _, err := client.CheckPassword(context.Background(), pwPassword); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("upstream received %d requests, want exactly 1", n)
			}
		})
	}
}

// TestLogLevels pins the operational contract: misconfiguration is logged at
// ERROR because a human must act, while transient faults are WARN.
func TestLogLevels(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantLevel string
		wantAttrs []string
	}{
		{
			name: "401 logs at error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			wantLevel: "ERROR",
		},
		{
			name: "400 logs at error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			wantLevel: "ERROR",
		},
		{
			name: "429 logs at warn with rate limit telemetry",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-RateLimit-Reset", "1893456000")
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantLevel: "WARN",
			wantAttrs: []string{"ratelimit_reset", "1893456000"},
		},
		{
			name: "500 logs at warn",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantLevel: "WARN",
		},
		{
			name:      "malformed body logs at warn",
			handler:   jsonHandler(`{`),
			wantLevel: "WARN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			client := newTestClient(t, tc.handler, WithLogger(logger))
			if _, _, err := client.CheckPassword(context.Background(), pwPassword); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			out := buf.String()
			if out == "" {
				t.Fatal("nothing was logged")
			}

			var rec map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
				t.Fatalf("log record is not valid JSON: %v (%q)", err, out)
			}
			if rec["level"] != tc.wantLevel {
				t.Errorf("level = %v, want %v", rec["level"], tc.wantLevel)
			}
			for _, want := range tc.wantAttrs {
				if !strings.Contains(out, want) {
					t.Errorf("log %q does not contain %q", out, want)
				}
			}

			// The password must never reach the logs.
			if strings.Contains(strings.ToUpper(out), suffixPassword) {
				t.Error("log leaked the digest suffix")
			}
		})
	}
}

// TestSuccessIsNotLogged keeps the hot path quiet: a healthy check should emit
// nothing at warn level or above.
func TestSuccessIsNotLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	client := newTestClient(t, jsonHandler(fmt.Sprintf(`{"%s": 5}`, suffixPassword)), WithLogger(logger))

	leaked, count, err := client.CheckPassword(context.Background(), pwPassword)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !leaked || count != 5 {
		t.Fatalf("got (%v, %d), want (true, 5)", leaked, count)
	}
	if buf.Len() != 0 {
		t.Errorf("successful check logged %q, want silence", buf.String())
	}
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient("key")

	if c.apiKey != "key" {
		t.Errorf("apiKey = %q, want %q", c.apiKey, "key")
	}
	if c.baseURL != defaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultBaseURL)
	}
	if c.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", c.timeout, DefaultTimeout)
	}
	if DefaultTimeout != 500*time.Millisecond {
		t.Errorf("DefaultTimeout = %v, want 500ms", DefaultTimeout)
	}
	if c.failClose {
		t.Error("failClose = true, want fail-open by default")
	}
	if c.logger == nil {
		t.Error("logger is nil, want a discard logger")
	}
	if c.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if c.httpClient.Timeout != DefaultTimeout {
		t.Errorf("httpClient.Timeout = %v, want %v", c.httpClient.Timeout, DefaultTimeout)
	}
}

func TestOptions(t *testing.T) {
	t.Run("WithTimeout applies to client and transport", func(t *testing.T) {
		c := NewClient("k", WithTimeout(2*time.Second))

		if c.timeout != 2*time.Second {
			t.Errorf("timeout = %v, want 2s", c.timeout)
		}
		if c.httpClient.Timeout != 2*time.Second {
			t.Errorf("httpClient.Timeout = %v, want 2s", c.httpClient.Timeout)
		}
	})

	t.Run("WithTimeout ignores non-positive values", func(t *testing.T) {
		for _, d := range []time.Duration{0, -time.Second} {
			c := NewClient("k", WithTimeout(d))
			if c.timeout != DefaultTimeout {
				t.Errorf("WithTimeout(%v): timeout = %v, want default %v", d, c.timeout, DefaultTimeout)
			}
		}
	})

	t.Run("WithFailClose flips the policy", func(t *testing.T) {
		if !NewClient("k", WithFailClose()).failClose {
			t.Error("failClose = false, want true")
		}
	})

	t.Run("WithLogger ignores nil", func(t *testing.T) {
		c := NewClient("k", WithLogger(nil))
		if c.logger == nil {
			t.Fatal("logger = nil, want the default discard logger")
		}
		c.logger.Info("ping") // must not panic
	})

	t.Run("later options win", func(t *testing.T) {
		c := NewClient("k", WithTimeout(time.Second), WithTimeout(3*time.Second))
		if c.timeout != 3*time.Second {
			t.Errorf("timeout = %v, want 3s", c.timeout)
		}
	})
}

// TestConcurrentUse exercises the documented goroutine-safety guarantee; run
// with -race for it to be meaningful.
func TestConcurrentUse(t *testing.T) {
	client := newTestClient(t, jsonHandler(fmt.Sprintf(`{"%s": 7}`, suffixPassword)))

	const goroutines = 16
	errs := make(chan error, goroutines)

	for range goroutines {
		go func() {
			leaked, count, err := client.CheckPassword(context.Background(), pwPassword)
			switch {
			case err != nil:
				errs <- err
			case !leaked || count != 7:
				errs <- fmt.Errorf("got (%v, %d), want (true, 7)", leaked, count)
			default:
				errs <- nil
			}
		}()
	}

	for range goroutines {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

func ExampleClient_CheckPassword() {
	client := NewClient("your-api-key")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	leaked, count, err := client.CheckPassword(ctx, "hunter2")
	if err != nil {
		// Unreachable with the default fail-open policy, which reports
		// transport and upstream failures as "not leaked".
		fmt.Println("check failed:", err)

		return
	}

	if leaked {
		fmt.Printf("password found in %d breaches\n", count)
	} else {
		fmt.Println("password not found in any known breach")
	}
}
