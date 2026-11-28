package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

func TestK8sAuthMode_ReportAttestAndCache(t *testing.T) {
	var reviewCalls atomic.Int32
	var podCalls atomic.Int32

	fakeK8s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer connector-sa-token" {
			http.Error(w, "unauthorized connector sa", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			reviewCalls.Add(1)
			var req k8sTokenReviewRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var resp k8sTokenReviewResponse
			switch req.Spec.Token {
			case "tok-node-a":
				resp.Status.Authenticated = true
				resp.Status.Audiences = []string{"treeward-connector"}
				resp.Status.User.Username = "system:serviceaccount:treeward:treeward-agent"
				resp.Status.User.Extra = map[string][]string{
					"authentication.kubernetes.io/pod-name": {"treeward-agent-aaa"},
					"authentication.kubernetes.io/pod-uid":  {"uid-aaa"},
				}
			case "tok-wrong-aud":
				resp.Status.Authenticated = true
				resp.Status.Audiences = []string{"https://kubernetes.default.svc"}
				resp.Status.User.Username = "system:serviceaccount:treeward:treeward-agent"
				resp.Status.User.Extra = map[string][]string{
					"authentication.kubernetes.io/pod-name": {"treeward-agent-aaa"},
				}
			case "tok-bad-uid":
				resp.Status.Authenticated = true
				resp.Status.Audiences = []string{"treeward-connector"}
				resp.Status.User.Username = "system:serviceaccount:treeward:treeward-agent"
				resp.Status.User.Extra = map[string][]string{
					"authentication.kubernetes.io/pod-name": {"treeward-agent-aaa"},
					"authentication.kubernetes.io/pod-uid":  {"uid-stale"},
				}
			default:
				resp.Status.Authenticated = false
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/treeward/pods/treeward-agent-aaa":
			podCalls.Add(1)
			var pod k8sPodResponse
			pod.Metadata.Name = "treeward-agent-aaa"
			pod.Metadata.Namespace = "treeward"
			pod.Metadata.UID = "uid-aaa"
			pod.Spec.NodeName = "worker-node-a"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pod)

		default:
			http.NotFound(w, r)
		}
	}))
	defer fakeK8s.Close()

	// Fake upstream control plane for attest submission.
	fakeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fakeAPI.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("connector-sa-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	now := time.Unix(10000, 0)
	auth := newK8sAuthenticator(fakeK8s.URL, "treeward-connector", tokenFile, fakeK8s.Client())
	auth.nowFn = func() time.Time { return now }
	auth.cacheTTL = 60 * time.Second

	creds := newCredManager(fakeAPI.URL, "boot", "cluster-1", nil)
	creds.token = "ctok-1"
	creds.clusterID = "cluster-1"
	state := newConnectorState()
	mux := newConnectorMux(fakeAPI.URL, creds, state, auth.Middleware, false)

	post := func(path, token string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Matching nodeName on /v1/local/report passes (200).
	rec := post("/v1/local/report", "tok-node-a", []types.AgentReport{
		{Node: types.Node{ID: "worker-node-a", Hostname: "worker-node-a"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("report matching node: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if reviewCalls.Load() != 1 || podCalls.Load() != 1 {
		t.Fatalf("expected 1 TokenReview and 1 pod lookup, got reviews=%d pods=%d", reviewCalls.Load(), podCalls.Load())
	}

	// 2. Second request with same token within TTL hits cache (no second TokenReview or pod lookup).
	state.setPending(&types.PendingAttest{ID: "camp-1", Nonce: "0123456789abcdef"})
	rec = post("/v1/local/attest", "tok-node-a", []types.AttestResult{
		{NodeID: "worker-node-a", Quote: "q-ok"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("attest matching node: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if reviewCalls.Load() != 1 || podCalls.Load() != 1 {
		t.Fatalf("cache hit should avoid second TokenReview/pod lookup, got reviews=%d pods=%d", reviewCalls.Load(), podCalls.Load())
	}

	// 3. Mismatched nodeName on /v1/local/report -> 403 Forbidden (and not recorded).
	rec = post("/v1/local/report", "tok-node-a", []types.AgentReport{
		{Node: types.Node{ID: "worker-node-b", Hostname: "worker-node-b"}},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("report mismatched node: got %d (%s), want 403", rec.Code, rec.Body.String())
	}
	nodes, _ := state.snapshotForSync("cluster-1")
	for _, n := range nodes {
		if n.ID == "worker-node-b" {
			t.Fatalf("spoofed node worker-node-b should not have been recorded")
		}
	}

	// 4. Mismatched nodeName on /v1/local/attest -> 403 Forbidden.
	state.setPending(&types.PendingAttest{ID: "camp-2", Nonce: "fedcba9876543210"})
	rec = post("/v1/local/attest", "tok-node-a", []types.AttestResult{
		{NodeID: "worker-node-b", Quote: "q-spoof"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attest mismatched node: got %d (%s), want 403", rec.Code, rec.Body.String())
	}

	// 5. Wrong audience -> 401 Unauthorized.
	rec = post("/v1/local/report", "tok-wrong-aud", []types.AgentReport{
		{Node: types.Node{ID: "worker-node-a"}},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong audience: got %d (%s), want 401", rec.Code, rec.Body.String())
	}

	// 6. Unauthenticated token -> 401 Unauthorized.
	rec = post("/v1/local/report", "tok-invalid", []types.AgentReport{
		{Node: types.Node{ID: "worker-node-a"}},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token: got %d (%s), want 401", rec.Code, rec.Body.String())
	}

	// 7. Pod UID mismatch -> 401 Unauthorized.
	rec = post("/v1/local/report", "tok-bad-uid", []types.AgentReport{
		{Node: types.Node{ID: "worker-node-a"}},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pod UID mismatch: got %d (%s), want 401", rec.Code, rec.Body.String())
	}

	// 8. After cache TTL expires, TokenReview is called again.
	beforeReviews := reviewCalls.Load()
	now = now.Add(61 * time.Second)
	rec = post("/v1/local/report", "tok-node-a", []types.AgentReport{
		{Node: types.Node{ID: "worker-node-a"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("report after cache expiry: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if reviewCalls.Load() != beforeReviews+1 {
		t.Fatalf("expected TokenReview after cache expiry: got %d, want %d", reviewCalls.Load(), beforeReviews+1)
	}
}
