package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyUpatchNormalizesUppercaseSHA(t *testing.T) {
	upperSHA := strings.Repeat("AB", 32)
	lowerSHA := strings.ToLower(upperSHA)

	var gotPath string
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("x-upatch-sha256", lowerSHA)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("signed-payload"))
	}))
	defer upstream.Close()

	cm := newCredManager(upstream.URL, "boot", "c1", func(_, _, _ string) (string, string, error) {
		return "tok-1", "cid-1", nil
	})
	cm.token = "tok-1"

	mux := http.NewServeMux()
	registerUpatchRoutes(mux, upstream.URL, cm, "local-secret", false)

	req := httptest.NewRequest(http.MethodGet, "/v1/upatches/"+upperSHA, nil)
	req.Header.Set("Authorization", "Bearer local-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d (%s), want 200", rec.Code, rec.Body.String())
	}
	wantPath := "/v1/upatches/" + lowerSHA
	if gotPath != wantPath {
		t.Fatalf("upstream path = %q, want %q", gotPath, wantPath)
	}
	if gotAuth != "Bearer tok-1" {
		t.Fatalf("upstream auth = %q, want Bearer tok-1", gotAuth)
	}
	if rec.Body.String() != "signed-payload" {
		t.Fatalf("body = %q, want signed-payload", rec.Body.String())
	}
}

func TestProxyUpatchRejectsInvalidSHA(t *testing.T) {
	cm := newCredManager("http://unused", "boot", "c1", nil)
	mux := http.NewServeMux()
	registerUpatchRoutes(mux, "http://unused", cm, "local-secret", false)

	req := httptest.NewRequest(http.MethodGet, "/v1/upatches/not-a-valid-sha", nil)
	req.Header.Set("Authorization", "Bearer local-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}
