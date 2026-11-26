package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/store"
	"github.com/treeward-ai/treeward/internal/types"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	sig, err := signer.NewLocal(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	st := store.New("test-bootstrap", sig)
	return New(st)
}

func doReq(t *testing.T, srv *Server, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	return rec
}

func TestAdminAuth_MissingBadRevokedExpiredAndValid(t *testing.T) {
	srv := newTestServer(t)

	// Missing token -> 401 on admin routes.
	adminRoutes := []struct{ method, path string }{
		{http.MethodGet, "/v1/nodes"},
		{http.MethodGet, "/v1/artifacts"},
		{http.MethodGet, "/v1/bindings"},
		{http.MethodGet, "/v1/tree"},
		{http.MethodGet, "/v1/audit"},
		{http.MethodGet, "/v1/attest/campaigns"},
		{http.MethodGet, "/v1/tokens"},
	}
	for _, rt := range adminRoutes {
		rec := doReq(t, srv, rt.method, rt.path, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: got %d, want 401", rt.method, rt.path, rec.Code)
		}
	}

	// Bad token -> 401.
	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", "tw_not-a-real-token", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", rec.Code)
	}

	// POST /v1/tokens requires bootstrap token.
	if rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "", types.CreateTokenRequest{Name: "op"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/tokens without bootstrap: got %d, want 401", rec.Code)
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "wrong-bootstrap", types.CreateTokenRequest{Name: "op"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/tokens wrong bootstrap: got %d, want 401", rec.Code)
	}

	// Mint a valid token with bootstrap token.
	rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "test-bootstrap", types.CreateTokenRequest{Name: "damian-op"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/tokens: got %d (%s), want 201", rec.Code, rec.Body.String())
	}
	var minted types.CreateTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode minted token: %v", err)
	}

	// Valid token passes.
	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", minted.Token, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/nodes with valid token: got %d, want 200", rec.Code)
	}

	// Expired token -> 401.
	past := time.Now().UTC().Add(-time.Minute)
	expResp, err := srv.Store.CreateToken("expired", &past)
	if err != nil {
		t.Fatalf("CreateToken expired: %v", err)
	}
	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", expResp.Token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/nodes with expired token: got %d, want 401", rec.Code)
	}

	// Revoke token via DELETE /v1/tokens/{id} -> subsequent request returns 401.
	if rec := doReq(t, srv, http.MethodDelete, "/v1/tokens/"+minted.ID, minted.Token, nil); rec.Code != http.StatusOK {
		t.Fatalf("DELETE /v1/tokens/{id}: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", minted.Token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/nodes with revoked token: got %d, want 401", rec.Code)
	}
}

func TestHealthzOpenAndConnectorRoutesUnaffected(t *testing.T) {
	srv := newTestServer(t)

	// /healthz is open without any token.
	if rec := doReq(t, srv, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz: got %d, want 200", rec.Code)
	}

	// Connector enroll works with bootstrapToken in body (no operator token).
	rec := doReq(t, srv, http.MethodPost, "/v1/connectors/enroll", "", types.EnrollRequest{
		BootstrapToken: "test-bootstrap",
		ClusterName:    "lab",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/connectors/enroll: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var enrolled types.EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}

	// Connector routes work with connector token.
	if rec := doReq(t, srv, http.MethodGet, "/v1/desired", enrolled.Token, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/desired with connector token: got %d, want 200", rec.Code)
	}
	if rec := doReq(t, srv, http.MethodGet, "/v1/attest/active", enrolled.Token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("GET /v1/attest/active with connector token: got %d, want 204", rec.Code)
	}
	// Connector token cannot access operator routes.
	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", enrolled.Token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/nodes with connector token: got %d, want 401", rec.Code)
	}
}

func TestActorDerivedFromAuthenticatedToken(t *testing.T) {
	srv := newTestServer(t)
	minted, err := srv.Store.CreateToken("alice-ci", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	// Create artifact & binding.
	artRec := doReq(t, srv, http.MethodPost, "/v1/artifacts", minted.Token, types.Artifact{Name: "p1", Type: "bpf"})
	if artRec.Code != http.StatusCreated {
		t.Fatalf("create artifact: %d", artRec.Code)
	}
	var art types.Artifact
	_ = json.Unmarshal(artRec.Body.Bytes(), &art)

	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", minted.Token, types.Binding{
		ArtifactDigest: art.Digest,
		TreeRef:        "default",
	})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("create binding: %d", bindRec.Code)
	}
	var bind types.Binding
	_ = json.Unmarshal(bindRec.Body.Bytes(), &bind)

	// Approve with a spoofed body actor -> should record "alice-ci".
	appRec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", minted.Token, types.ApproveRequest{Actor: "spoofed"})
	if appRec.Code != http.StatusOK {
		t.Fatalf("approve: %d (%s)", appRec.Code, appRec.Body.String())
	}
	var approved types.Binding
	_ = json.Unmarshal(appRec.Body.Bytes(), &approved)
	if approved.ApprovedBy != "alice-ci" {
		t.Fatalf("ApprovedBy = %q, want %q", approved.ApprovedBy, "alice-ci")
	}

	// Start attest campaign -> audit actor should be "alice-ci".
	attRec := doReq(t, srv, http.MethodPost, "/v1/attest/campaigns", minted.Token, map[string]any{})
	if attRec.Code != http.StatusCreated {
		t.Fatalf("start attest: %d", attRec.Code)
	}

	audit := srv.Store.ListAudit()
	foundApprove, foundAttest := false, false
	for _, ev := range audit {
		if ev.Action == "approve" && ev.Actor == "alice-ci" {
			foundApprove = true
		}
		if ev.Action == "attest.start" && ev.Actor == "alice-ci" {
			foundAttest = true
		}
	}
	if !foundApprove || !foundAttest {
		t.Fatalf("expected audit events with actor=alice-ci (approve=%v attest=%v): %+v", foundApprove, foundAttest, audit)
	}
}

func TestAuthDisabledToggle(t *testing.T) {
	srv := newTestServer(t)
	srv.AuthDisabled = true

	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/nodes with AuthDisabled=true: got %d, want 200", rec.Code)
	}
}
