package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/treeward-ai/treeward/internal/types"
)

func TestAgentSendsBearerAuthWhenLocalTokenSet(t *testing.T) {
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/v1/local/desired":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		case "/v1/local/attest":
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/v1/local/report":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	if _, err := getDesired(srv.URL, "local-secret"); err != nil {
		t.Fatalf("getDesired: %v", err)
	}
	if _, err := getPendingAttest(srv.URL, "local-secret"); err != nil {
		t.Fatalf("getPendingAttest: %v", err)
	}
	if err := postReport(srv.URL, "local-secret", []types.AgentReport{}); err != nil {
		t.Fatalf("postReport: %v", err)
	}
	if err := postAttest(srv.URL, "local-secret", []types.AttestResult{}); err != nil {
		t.Fatalf("postAttest: %v", err)
	}

	if len(gotAuth) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(gotAuth))
	}
	for i, h := range gotAuth {
		if h != "Bearer local-secret" {
			t.Fatalf("request %d auth = %q, want %q", i, h, "Bearer local-secret")
		}
	}

	// When token is empty, Authorization header should not be sent.
	gotAuth = nil
	if _, err := getDesired(srv.URL, ""); err != nil {
		t.Fatalf("getDesired empty token: %v", err)
	}
	if len(gotAuth) != 1 || gotAuth[0] != "" {
		t.Fatalf("expected empty Authorization header, got %v", gotAuth)
	}
}
