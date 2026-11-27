package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
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

func TestCredManagerReenrollPreservesTokenOnTransientFailureAndBacksOff(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	cm := newCredManager("http://api", "boot", "c1", func(_, _, _ string) (string, string, error) {
		calls++
		return "", "", errors.New("upstream unavailable")
	})
	cm.nowFn = func() time.Time { return now }
	cm.token = "tok-existing"

	if err := cm.reenroll("tok-existing"); err == nil {
		t.Fatal("expected error on failed reenroll")
	}
	if tok, _ := cm.snapshot(); tok != "tok-existing" {
		t.Fatalf("expected existing token to be preserved on transient failure, got %q", tok)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}

	// Immediate retry should be backed off without calling enrollFn.
	if err := cm.reenroll("tok-existing"); err == nil {
		t.Fatal("expected backoff error")
	}
	if calls != 1 {
		t.Fatalf("expected backoff to prevent tight loop, got %d calls", calls)
	}

	// Advance past initial 1s backoff.
	now = now.Add(2 * time.Second)
	if err := cm.reenroll("tok-existing"); err == nil {
		t.Fatal("expected error on second attempt")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls after backoff elapsed, got %d", calls)
	}
}

func TestCredManagerReenrollNonBlockingSnapshotAndCoalescesConcurrent401s(t *testing.T) {
	enrollStarted := make(chan struct{})
	releaseEnroll := make(chan struct{})
	var calls atomic.Int32

	cm := newCredManager("http://api", "boot", "c1", func(_, _, _ string) (string, string, error) {
		if calls.Add(1) == 1 {
			close(enrollStarted)
		}
		<-releaseEnroll
		return "tok-rotated", "cid-1", nil
	})
	cm.token = "tok-old"
	cm.clusterID = "cid-1"

	const workers = 8
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- cm.reenroll("tok-old")
		}()
	}

	// Wait until enrollFn is actively in flight.
	select {
	case <-enrollStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for enrollFn to start")
	}

	// snapshot() must NOT block while enrollFn is in flight, and must still return the old token.
	snapDone := make(chan string, 1)
	go func() {
		tok, _ := cm.snapshot()
		snapDone <- tok
	}()
	select {
	case got := <-snapDone:
		if got != "tok-old" {
			t.Fatalf("snapshot() while reenrolling = %q, want %q", got, "tok-old")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("snapshot() blocked while reenroll was in flight")
	}

	close(releaseEnroll)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent reenroll returned error: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected concurrent 401s to coalesce into 1 enrollFn call, got %d", got)
	}
	if tok, _ := cm.snapshot(); tok != "tok-rotated" {
		t.Fatalf("expected rotated token, got %q", tok)
	}
}

func TestIsUnauthorizedOnlyMatchesHTTP401(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"http 401", &httpError{code: http.StatusUnauthorized, body: "nope"}, true},
		{"wrapped http 401", fmt.Errorf("wrap: %w", &httpError{code: http.StatusUnauthorized, body: "expired"}), true},
		{"http 400 with unauthorized body", &httpError{code: http.StatusBadRequest, body: "unauthorized action"}, false},
		{"http 403 with unauthorized body", &httpError{code: http.StatusForbidden, body: "unauthorized"}, false},
		{"http 500 with unauthorized body", &httpError{code: http.StatusInternalServerError, body: "unauthorized"}, false},
		{"plain error with unauthorized text", errors.New("upstream said unauthorized"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUnauthorized(tc.err); got != tc.want {
				t.Fatalf("isUnauthorized(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsLoopbackListenAddr(t *testing.T) {
	accept := []string{
		"127.0.0.1:8090",
		"[::1]:8090",
		"localhost:8090",
		"LOCALHOST:8090",
	}
	for _, addr := range accept {
		if !isLoopbackListenAddr(addr) {
			t.Errorf("isLoopbackListenAddr(%q) = false, want true", addr)
		}
	}

	reject := []string{
		":8090",
		"0.0.0.0:8090",
		"[::]:8090",
		"10.0.0.5:8090",
		"192.168.1.10:8090",
		"example.com:8090",
		"127.0.0.1",
		"",
	}
	for _, addr := range reject {
		if isLoopbackListenAddr(addr) {
			t.Errorf("isLoopbackListenAddr(%q) = true, want false", addr)
		}
	}
}

func TestConnectorStateEvictsStaleAgentsBeforeAttestReadiness(t *testing.T) {
	now := time.Unix(1000, 0)
	st := newConnectorState()
	st.nowFn = func() time.Time { return now }
	st.staleTTL = 5 * time.Minute

	// Two nodes report initially.
	st.recordReports("cid-1", []types.AgentReport{
		{Node: types.Node{ID: "node-alive"}},
		{Node: types.Node{ID: "node-dead"}},
	})

	// Advance 6 minutes; only node-alive reports again.
	now = now.Add(6 * time.Minute)
	st.recordReports("cid-1", []types.AgentReport{
		{Node: types.Node{ID: "node-alive"}},
	})

	st.setPending(&types.PendingAttest{ID: "camp-1", Nonce: "abcd1234abcd1234"})

	// Only node-alive submits a quote; dead node must have been evicted so readiness is true.
	campID, batch, shouldSubmit, hasPending := st.recordAttestResults([]types.AttestResult{
		{NodeID: "node-alive", Quote: "q1"},
	})
	if !hasPending || !shouldSubmit || campID != "camp-1" || len(batch) != 1 {
		t.Fatalf("unexpected attest state: campID=%q batch=%d shouldSubmit=%v hasPending=%v", campID, len(batch), shouldSubmit, hasPending)
	}

	// Concurrent second submission for same campaign while inFlight must not double-submit.
	_, _, shouldSubmit2, hasPending2 := st.recordAttestResults([]types.AttestResult{
		{NodeID: "node-alive", Quote: "q1"},
	})
	if !hasPending2 || shouldSubmit2 {
		t.Fatalf("expected inFlight to block double-submit: shouldSubmit=%v hasPending=%v", shouldSubmit2, hasPending2)
	}

	// If submit fails, inFlight is cleared so a retry can proceed.
	st.finishAttestSubmit("camp-1", false)
	_, _, shouldSubmit3, _ := st.recordAttestResults([]types.AttestResult{
		{NodeID: "node-alive", Quote: "q1"},
	})
	if !shouldSubmit3 {
		t.Fatal("expected retry after failed submit to be allowed")
	}

	// On success, campaign is marked submitted and pending cleared.
	st.finishAttestSubmit("camp-1", true)
	if st.getPending() != nil {
		t.Fatal("expected pending campaign to be cleared after successful submit")
	}
}

func TestConnectorStateEvictsStaleAgentsDuringAttestEvenWithoutNewReport(t *testing.T) {
	now := time.Unix(2000, 0)
	st := newConnectorState()
	st.nowFn = func() time.Time { return now }
	st.staleTTL = 5 * time.Minute

	st.recordReports("cid-1", []types.AgentReport{
		{Node: types.Node{ID: "node-dead"}},
	})
	now = now.Add(4 * time.Minute)
	st.recordReports("cid-1", []types.AgentReport{
		{Node: types.Node{ID: "node-alive"}},
	})
	st.setPending(&types.PendingAttest{ID: "camp-2", Nonce: "1111222233334444"})

	// Advance 2 more minutes: node-dead is now 6m old (>5m), node-alive is 2m old.
	now = now.Add(2 * time.Minute)
	_, batch, shouldSubmit, _ := st.recordAttestResults([]types.AttestResult{
		{NodeID: "node-alive", Quote: "q-alive"},
	})
	if !shouldSubmit || len(batch) != 1 {
		t.Fatalf("expected stale node-dead to be evicted during attest readiness check, got shouldSubmit=%v len(batch)=%d", shouldSubmit, len(batch))
	}
}

func TestConnectorStateBoundsAgentsAndSubmitted(t *testing.T) {
	now := time.Unix(3000, 0)
	st := newConnectorState()
	st.nowFn = func() time.Time { return now }
	st.maxAgents = 3
	st.maxSubmitted = 2

	st.recordReports("cid-1", []types.AgentReport{
		{Node: types.Node{ID: "n1"}},
		{Node: types.Node{ID: "n2"}},
		{Node: types.Node{ID: "n3"}},
		{Node: types.Node{ID: "n4"}},
	})
	nodes, _ := st.snapshotForSync("cid-1")
	if len(nodes) != 3 {
		t.Fatalf("expected tracked agents capped at 3, got %d", len(nodes))
	}

	st.finishAttestSubmit("c1", true)
	now = now.Add(time.Second)
	st.finishAttestSubmit("c2", true)
	now = now.Add(time.Second)
	st.finishAttestSubmit("c3", true)

	st.mu.Lock()
	gotSubmitted := len(st.submitted)
	_, hasC1 := st.submitted["c1"]
	st.mu.Unlock()
	if gotSubmitted != 2 {
		t.Fatalf("expected submitted map capped at 2, got %d", gotSubmitted)
	}
	if hasC1 {
		t.Fatal("expected oldest submitted campaign c1 to be pruned")
	}
}

func TestReadBodyBounded(t *testing.T) {
	data, err := readBodyBounded(bytes.NewReader([]byte("hello")), 5)
	if err != nil || string(data) != "hello" {
		t.Fatalf("readBodyBounded exact limit: data=%q err=%v", data, err)
	}
	if _, err := readBodyBounded(bytes.NewReader([]byte("hello!")), 5); err == nil {
		t.Fatal("expected error when body exceeds limit")
	}
}

func TestHTTPClientDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer srv.Close()

	res, err := httpClient.Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("httpClient.Get failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("got status %d, want 302", res.StatusCode)
	}
	if redirected {
		t.Fatal("httpClient followed redirect unexpectedly")
	}
}

func TestCredManagerHaltsOnEnrollTokenRejection(t *testing.T) {
	calls := 0
	cm := newCredManager("http://api", "bad-enroll", "c1", func(_, _, _ string) (string, string, error) {
		calls++
		return "", "", &httpError{code: http.StatusUnauthorized, body: "invalid enroll token"}
	})
	cm.sleepFn = func(time.Duration) {}

	if err := cm.enrollWithRetry(10); err == nil {
		t.Fatal("expected error on enroll token rejection")
	}
	if calls != 1 {
		t.Fatalf("expected immediate stop on 401 enroll token, got %d calls", calls)
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

func TestConnectorListenAddrDefault(t *testing.T) {
	t.Setenv("TREEWARD_CONNECTOR_ADDR", "")
	if got := connectorListenAddr(); got != "127.0.0.1:8090" {
		t.Fatalf("default connectorListenAddr() = %q, want %q", got, "127.0.0.1:8090")
	}

	t.Setenv("TREEWARD_CONNECTOR_ADDR", ":8090")
	if got := connectorListenAddr(); got != ":8090" {
		t.Fatalf("override connectorListenAddr() = %q, want %q", got, ":8090")
	}
}
