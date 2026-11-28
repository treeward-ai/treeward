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
	st := store.New("test-enroll", "test-admin-bootstrap", sig)
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

	// POST /v1/tokens requires admin bootstrap token.
	if rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "", types.CreateTokenRequest{Name: "op"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/tokens without admin bootstrap: got %d, want 401", rec.Code)
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "wrong-bootstrap", types.CreateTokenRequest{Name: "op"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/tokens wrong admin bootstrap: got %d, want 401", rec.Code)
	}

	// Mint a valid token with admin bootstrap token.
	rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "test-admin-bootstrap", types.CreateTokenRequest{Name: "damian-op"})
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

	// Connector enroll works with enroll token in body (no operator token).
	rec := doReq(t, srv, http.MethodPost, "/v1/connectors/enroll", "", types.EnrollRequest{
		BootstrapToken: "test-enroll",
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
	alice, err := srv.Store.CreateTokenWithRole("alice-ci", types.RoleOperator, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole alice: %v", err)
	}
	bob, err := srv.Store.CreateTokenWithRole("bob-approver", types.RoleApprover, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole bob: %v", err)
	}

	// Create artifact & binding (attempting to spoof createdBy in JSON body must be ignored).
	artRec := doReq(t, srv, http.MethodPost, "/v1/artifacts", alice.Token, types.Artifact{Name: "p1", Type: "bpf"})
	if artRec.Code != http.StatusCreated {
		t.Fatalf("create artifact: %d", artRec.Code)
	}
	var art types.Artifact
	_ = json.Unmarshal(artRec.Body.Bytes(), &art)

	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", alice.Token, types.Binding{
		ArtifactDigest: art.Digest,
		TreeRef:        "default",
		CreatedBy:      "spoofed-creator",
	})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("create binding: %d", bindRec.Code)
	}
	var bind types.Binding
	_ = json.Unmarshal(bindRec.Body.Bytes(), &bind)
	if bind.CreatedBy != "alice-ci" {
		t.Fatalf("CreatedBy = %q, want %q", bind.CreatedBy, "alice-ci")
	}

	// Approve with a spoofed body actor as bob-approver -> should record "bob-approver".
	appRec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", bob.Token, types.ApproveRequest{Actor: "spoofed"})
	if appRec.Code != http.StatusOK {
		t.Fatalf("approve: %d (%s)", appRec.Code, appRec.Body.String())
	}
	var approved types.Binding
	_ = json.Unmarshal(appRec.Body.Bytes(), &approved)
	if approved.ApprovedBy != "bob-approver" {
		t.Fatalf("ApprovedBy = %q, want %q", approved.ApprovedBy, "bob-approver")
	}

	// Start attest campaign -> audit actor should be "alice-ci".
	attRec := doReq(t, srv, http.MethodPost, "/v1/attest/campaigns", alice.Token, map[string]any{})
	if attRec.Code != http.StatusCreated {
		t.Fatalf("start attest: %d", attRec.Code)
	}

	audit := srv.Store.ListAudit()
	foundArtifact, foundBinding, foundApprove, foundAttest := false, false, false, false
	for _, ev := range audit {
		if ev.Action == "artifact.create" && ev.Actor == "alice-ci" {
			foundArtifact = true
		}
		if ev.Action == "binding.create" && ev.Actor == "alice-ci" {
			foundBinding = true
		}
		if ev.Action == "approve" && ev.Actor == "bob-approver" {
			foundApprove = true
		}
		if ev.Action == "attest.start" && ev.Actor == "alice-ci" {
			foundAttest = true
		}
	}
	if !foundArtifact || !foundBinding || !foundApprove || !foundAttest {
		t.Fatalf("expected audit events bound to authenticated principals (art=%v bind=%v approve=%v attest=%v): %+v",
			foundArtifact, foundBinding, foundApprove, foundAttest, audit)
	}
}

func TestRBACRoleMatrix(t *testing.T) {
	srv := newTestServer(t)

	// Mint tokens via HTTP API to also exercise role validation and default role.
	if rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "test-admin-bootstrap", types.CreateTokenRequest{
		Name: "bad-role",
		Role: "root",
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /v1/tokens invalid role: got %d, want 400", rec.Code)
	}

	mint := func(name, role string) types.CreateTokenResponse {
		t.Helper()
		rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "test-admin-bootstrap", types.CreateTokenRequest{
			Name: name,
			Role: role,
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("mint %s (%s): got %d (%s)", name, role, rec.Code, rec.Body.String())
		}
		var out types.CreateTokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode minted %s: %v", name, err)
		}
		return out
	}

	viewer := mint("v-user", types.RoleViewer)
	operator := mint("o-user", types.RoleOperator)
	approver := mint("a-user", types.RoleApprover)
	admin := mint("adm-user", "") // omitted -> defaults to admin
	if admin.Role != types.RoleAdmin {
		t.Fatalf("omitted role = %q, want admin", admin.Role)
	}
	disposable := mint("temp-viewer", types.RoleViewer)

	// Seed an artifact, binding, and campaign via operator so read & transition routes have IDs.
	artRec := doReq(t, srv, http.MethodPost, "/v1/artifacts", operator.Token, types.Artifact{Name: "shield", Type: "bpf"})
	if artRec.Code != http.StatusCreated {
		t.Fatalf("operator create artifact: got %d", artRec.Code)
	}
	var art types.Artifact
	_ = json.Unmarshal(artRec.Body.Bytes(), &art)

	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", operator.Token, types.Binding{ArtifactDigest: art.Digest})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("operator create binding: got %d", bindRec.Code)
	}
	var bind types.Binding
	_ = json.Unmarshal(bindRec.Body.Bytes(), &bind)

	campRec := doReq(t, srv, http.MethodPost, "/v1/attest/campaigns", operator.Token, map[string]any{})
	if campRec.Code != http.StatusCreated {
		t.Fatalf("operator start attest: got %d", campRec.Code)
	}
	var camp types.AttestCampaign
	_ = json.Unmarshal(campRec.Body.Bytes(), &camp)

	// 1. Read-only routes: all 4 roles allowed.
	readRoutes := []string{
		"/v1/nodes",
		"/v1/artifacts",
		"/v1/bindings",
		"/v1/bindings/" + bind.ID,
		"/v1/tree",
		"/v1/audit",
		"/v1/attest/campaigns",
		"/v1/attest/campaigns/" + camp.ID,
	}
	for _, tok := range []types.CreateTokenResponse{viewer, operator, approver, admin} {
		for _, path := range readRoutes {
			if rec := doReq(t, srv, http.MethodGet, path, tok.Token, nil); rec.Code != http.StatusOK {
				t.Errorf("role=%s GET %s: got %d, want 200", tok.Role, path, rec.Code)
			}
		}
	}

	// 2. Viewer is denied (403) on all mutating & token-admin routes.
	viewerDenied := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/v1/artifacts", types.Artifact{Name: "x", Type: "bpf"}},
		{http.MethodPost, "/v1/bindings", types.Binding{ArtifactDigest: art.Digest}},
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/approve", types.ApproveRequest{}},
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/canary", types.ApproveRequest{}},
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/promote", types.ApproveRequest{}},
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/revert", types.ApproveRequest{}},
		{http.MethodPost, "/v1/attest/campaigns", map[string]any{}},
		{http.MethodGet, "/v1/tokens", nil},
		{http.MethodDelete, "/v1/tokens/" + disposable.ID, nil},
	}
	for _, tc := range viewerDenied {
		if rec := doReq(t, srv, tc.method, tc.path, viewer.Token, tc.body); rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s %s: got %d, want 403", tc.method, tc.path, rec.Code)
		}
	}

	// 3. Operator cannot approve or manage tokens (403).
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/approve", types.ApproveRequest{}},
		{http.MethodGet, "/v1/tokens", nil},
		{http.MethodDelete, "/v1/tokens/" + disposable.ID, nil},
	} {
		if rec := doReq(t, srv, tc.method, tc.path, operator.Token, tc.body); rec.Code != http.StatusForbidden {
			t.Errorf("operator %s %s: got %d, want 403", tc.method, tc.path, rec.Code)
		}
	}

	// 4. Approver cannot create artifacts/bindings, canary, promote, attest, or manage tokens (403).
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/v1/artifacts", types.Artifact{Name: "y", Type: "bpf"}},
		{http.MethodPost, "/v1/bindings", types.Binding{ArtifactDigest: art.Digest}},
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/canary", types.ApproveRequest{}},
		{http.MethodPost, "/v1/bindings/" + bind.ID + "/promote", types.ApproveRequest{}},
		{http.MethodPost, "/v1/attest/campaigns", map[string]any{}},
		{http.MethodGet, "/v1/tokens", nil},
		{http.MethodDelete, "/v1/tokens/" + disposable.ID, nil},
	} {
		if rec := doReq(t, srv, tc.method, tc.path, approver.Token, tc.body); rec.Code != http.StatusForbidden {
			t.Errorf("approver %s %s: got %d, want 403", tc.method, tc.path, rec.Code)
		}
	}

	// 5. Full separated workflow: approver approves -> operator canaries & promotes -> approver reverts.
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", approver.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("approver approve: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/canary", operator.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("operator canary: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/promote", operator.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("operator promote: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/revert", approver.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("approver revert: got %d (%s), want 200", rec.Code, rec.Body.String())
	}

	// 6. Admin can list and revoke tokens.
	listRec := doReq(t, srv, http.MethodGet, "/v1/tokens", admin.Token, nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("admin GET /v1/tokens: got %d, want 200", listRec.Code)
	}
	var listed []types.APIToken
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode token list: %v", err)
	}
	if len(listed) < 5 {
		t.Fatalf("expected >=5 tokens, got %d", len(listed))
	}
	if rec := doReq(t, srv, http.MethodDelete, "/v1/tokens/"+disposable.ID, admin.Token, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin DELETE /v1/tokens: got %d, want 200", rec.Code)
	}
}

func TestSeparationOfDutiesAndSelfApproveOptIn(t *testing.T) {
	srv := newTestServer(t)

	adminAlice, err := srv.Store.CreateTokenWithRole("alice-admin", types.RoleAdmin, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole alice: %v", err)
	}
	approverBob, err := srv.Store.CreateTokenWithRole("bob-approver", types.RoleApprover, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole bob: %v", err)
	}

	artRec := doReq(t, srv, http.MethodPost, "/v1/artifacts", adminAlice.Token, types.Artifact{Name: "p-sod", Type: "bpf"})
	if artRec.Code != http.StatusCreated {
		t.Fatalf("create artifact: got %d", artRec.Code)
	}
	var art types.Artifact
	_ = json.Unmarshal(artRec.Body.Bytes(), &art)

	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", adminAlice.Token, types.Binding{ArtifactDigest: art.Digest})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("create binding: got %d", bindRec.Code)
	}
	var bind types.Binding
	_ = json.Unmarshal(bindRec.Body.Bytes(), &bind)

	// Even an admin cannot self-approve by default (fail-closed two-person rule).
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", adminAlice.Token, types.ApproveRequest{}); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approve by admin creator: got %d (%s), want 403", rec.Code, rec.Body.String())
	}

	// Distinct approver succeeds.
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", approverBob.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("approve by distinct approver: got %d (%s), want 200", rec.Code, rec.Body.String())
	}

	// Explicit opt-in (TREEWARD_ALLOW_SELF_APPROVE=true) permits self-approval.
	srv.Store.AllowSelfApprove = true
	bind2Rec := doReq(t, srv, http.MethodPost, "/v1/bindings", adminAlice.Token, types.Binding{ArtifactDigest: art.Digest})
	if bind2Rec.Code != http.StatusCreated {
		t.Fatalf("create binding 2: got %d", bind2Rec.Code)
	}
	var bind2 types.Binding
	_ = json.Unmarshal(bind2Rec.Body.Bytes(), &bind2)

	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind2.ID+"/approve", adminAlice.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("self-approve with AllowSelfApprove=true: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
}

func TestAuthDisabledToggle(t *testing.T) {
	srv := newTestServer(t)
	srv.AuthDisabled = true

	if rec := doReq(t, srv, http.MethodGet, "/v1/nodes", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/nodes with AuthDisabled=true: got %d, want 200", rec.Code)
	}
}

func TestSplitBootstrapSecretsCannotCrossAuthenticate(t *testing.T) {
	srv := newTestServer(t)

	// Security regression test: a connector's EnrollToken MUST NOT mint admin operator tokens.
	if rec := doReq(t, srv, http.MethodPost, "/v1/tokens", "test-enroll", types.CreateTokenRequest{Name: "escalated-op"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/tokens with EnrollToken: got %d (%s), want 401", rec.Code, rec.Body.String())
	}

	// Security regression test: the AdminBootstrapToken MUST NOT enroll connectors.
	if rec := doReq(t, srv, http.MethodPost, "/v1/connectors/enroll", "", types.EnrollRequest{
		BootstrapToken: "test-admin-bootstrap",
		ClusterName:    "lab",
	}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/connectors/enroll with AdminBootstrapToken: got %d (%s), want 401", rec.Code, rec.Body.String())
	}

	// Defense-in-depth: if a store is misconfigured with identical tokens, POST /v1/tokens rejects it.
	sig, err := signer.NewLocal(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	misconfigured := New(store.New("same-secret", "same-secret", sig))
	if rec := doReq(t, misconfigured, http.MethodPost, "/v1/tokens", "same-secret", types.CreateTokenRequest{Name: "op"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/tokens with identical enroll/admin secrets: got %d, want 401", rec.Code)
	}
}

func TestApproveRejectsReapprovalWith409(t *testing.T) {
	srv := newTestServer(t)

	op, err := srv.Store.CreateTokenWithRole("op-1", types.RoleOperator, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole op: %v", err)
	}
	approver1, err := srv.Store.CreateTokenWithRole("approver-1", types.RoleApprover, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole approver1: %v", err)
	}
	approver2, err := srv.Store.CreateTokenWithRole("approver-2", types.RoleApprover, nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole approver2: %v", err)
	}

	art := srv.Store.CreateArtifact(types.Artifact{Name: "p-reapprove", Type: "bpf"})
	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", op.Token, types.Binding{ArtifactDigest: art.Digest})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("create binding: got %d (%s)", bindRec.Code, bindRec.Body.String())
	}
	var bind types.Binding
	_ = json.Unmarshal(bindRec.Body.Bytes(), &bind)

	// First approval succeeds.
	rec1 := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", approver1.Token, types.ApproveRequest{})
	if rec1.Code != http.StatusOK {
		t.Fatalf("first approve: got %d (%s), want 200", rec1.Code, rec1.Body.String())
	}
	var firstApproved types.Binding
	_ = json.Unmarshal(rec1.Body.Bytes(), &firstApproved)
	if firstApproved.ApprovedBy != "approver-1" || firstApproved.ApprovedAt.IsZero() {
		t.Fatalf("unexpected first approval metadata: %+v", firstApproved)
	}

	// Re-approving an already-approved binding must fail with 409 Conflict and preserve original approver metadata.
	rec2 := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", approver2.Token, types.ApproveRequest{})
	if rec2.Code != http.StatusConflict {
		t.Fatalf("re-approve: got %d (%s), want 409", rec2.Code, rec2.Body.String())
	}
	got, ok := srv.Store.GetBinding(bind.ID)
	if !ok {
		t.Fatalf("binding disappeared")
	}
	if got.ApprovedBy != firstApproved.ApprovedBy || !got.ApprovedAt.Equal(firstApproved.ApprovedAt) {
		t.Fatalf("re-approve mutated approval metadata: got (%q, %v), want (%q, %v)",
			got.ApprovedBy, got.ApprovedAt, firstApproved.ApprovedBy, firstApproved.ApprovedAt)
	}

	// Approving after canary must also return 409 Conflict.
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/canary", op.Token, types.ApproveRequest{}); rec.Code != http.StatusOK {
		t.Fatalf("canary: got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", approver2.Token, types.ApproveRequest{}); rec.Code != http.StatusConflict {
		t.Fatalf("approve in canary: got %d (%s), want 409", rec.Code, rec.Body.String())
	}
}
