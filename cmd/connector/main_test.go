package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCredManagerReenrollDeduplicatesAndRotates(t *testing.T) {
	calls := 0
	cm := newCredManager("http://api", "boot", "c1", func(_, _, _ string) (string, string, error) {
		calls++
		return "tok-new", "cid-1", nil
	})
	cm.token = "tok-old"
	cm.clusterID = "cid-1"

	if err := cm.reenroll("tok-old"); err != nil {
		t.Fatalf("reenroll failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 enroll call, got %d", calls)
	}
	tok, cid := cm.snapshot()
	if tok != "tok-new" || cid != "cid-1" {
		t.Fatalf("unexpected creds: %q %q", tok, cid)
	}

	// Second concurrent caller that failed with the same stale token should not re-enroll again.
	if err := cm.reenroll("tok-old"); err != nil {
		t.Fatalf("dedup reenroll failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected no extra enroll call, got %d", calls)
	}
}

func TestCredManagerReenrollClearsStaleTokenAndBacksOff(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	cm := newCredManager("http://api", "boot", "c1", func(_, _, _ string) (string, string, error) {
		calls++
		return "", "", errors.New("upstream unavailable")
	})
	cm.nowFn = func() time.Time { return now }
	cm.token = "tok-stale"

	if err := cm.reenroll("tok-stale"); err == nil {
		t.Fatal("expected error on failed reenroll")
	}
	if tok, _ := cm.snapshot(); tok != "" {
		t.Fatalf("expected stale token to be cleared, got %q", tok)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}

	// Immediate retry should be backed off without calling enrollFn.
	if err := cm.reenroll(""); err == nil {
		t.Fatal("expected backoff error")
	}
	if calls != 1 {
		t.Fatalf("expected backoff to prevent tight loop, got %d calls", calls)
	}

	// Advance past initial 1s backoff.
	now = now.Add(2 * time.Second)
	if err := cm.reenroll(""); err == nil {
		t.Fatal("expected error on second attempt")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls after backoff elapsed, got %d", calls)
	}
}

func TestCredManagerHaltsOnBootstrapRejection(t *testing.T) {
	calls := 0
	cm := newCredManager("http://api", "bad-boot", "c1", func(_, _, _ string) (string, string, error) {
		calls++
		return "", "", &httpError{code: http.StatusUnauthorized, body: "invalid bootstrap"}
	})
	cm.sleepFn = func(time.Duration) {}

	if err := cm.enrollWithRetry(10); err == nil {
		t.Fatal("expected error on bootstrap rejection")
	}
	if calls != 1 {
		t.Fatalf("expected immediate stop on 401 bootstrap, got %d calls", calls)
	}

	// Subsequent re-enroll should remain halted without calling enrollFn.
	if err := cm.reenroll(""); err == nil {
		t.Fatal("expected halted error")
	}
	if calls != 1 {
		t.Fatalf("expected halted re-enroll not to call enrollFn, got %d calls", calls)
	}
}

func TestRequireLocalAuth(t *testing.T) {
	okHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Empty token with authDisabled=false must fail closed (401).
	hFailClosed := requireLocalAuth("", false, okHandler)
	for _, hdr := range []string{"", "Bearer ", "Bearer anything"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/local/desired", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		rr := httptest.NewRecorder()
		hFailClosed.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("fail-closed with header %q: got %d, want 401", hdr, rr.Code)
		}
	}

	// Empty token with explicit authDisabled=true preserves local dev opt-out.
	hOpen := requireLocalAuth("", true, okHandler)
	rr := httptest.NewRecorder()
	hOpen.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/local/desired", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when authDisabled=true and token empty, got %d", rr.Code)
	}

	// Configured token enforces Bearer auth regardless of authDisabled.
	hProtected := requireLocalAuth("super-secret", false, okHandler)

	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic super-secret", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"valid token", "Bearer super-secret", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/local/desired", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			hProtected.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
