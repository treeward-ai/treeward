package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/treeward-ai/treeward/internal/runtime"
	"github.com/treeward-ai/treeward/internal/types"
)

type uploadFixture struct {
	upatch, unload       []byte
	upatchB64, unloadB64 string
	upatchSHA            string
}

func newUploadFixture(t *testing.T) uploadFixture {
	t.Helper()
	up := []byte("signed-upatch-bytes-for-test")
	un := []byte("signed-unload-directive-for-test")
	sum := sha256.Sum256(up)
	return uploadFixture{
		upatch:    up,
		unload:    un,
		upatchB64: base64.StdEncoding.EncodeToString(up),
		unloadB64: base64.StdEncoding.EncodeToString(un),
		upatchSHA: hex.EncodeToString(sum[:]),
	}
}

func uploadBody(name string, f uploadFixture) map[string]any {
	return map[string]any{
		"name":            name,
		"type":            "bpf",
		"fixes":           []string{"CVE-2026-31431"},
		"upatchB64":       f.upatchB64,
		"upatchUnloadB64": f.unloadB64,
	}
}

func decodeArtifact(t *testing.T, rec *httptest.ResponseRecorder) types.Artifact {
	t.Helper()
	var a types.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode artifact: %v (%s)", err, rec.Body.String())
	}
	return a
}

func TestUploadArtifactDerivesAgentDigest(t *testing.T) {
	srv := newTestServer(t)
	op, err := srv.Store.CreateToken("op", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	f := newUploadFixture(t)

	rec := doReq(t, srv, http.MethodPost, "/v1/artifacts", op.Token, uploadBody("cve-2026-31431-alg-splice-block", f))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: got %d (%s), want 201", rec.Code, rec.Body.String())
	}
	a := decodeArtifact(t, rec)
	wantDigest := "cve-2026-31431-alg-splice-block@sha256:" + f.upatchSHA
	if a.Digest != wantDigest {
		t.Fatalf("digest = %q, want %q", a.Digest, wantDigest)
	}
	if a.UpatchSHA256 != f.upatchSHA || a.Type != "bpf" {
		t.Fatalf("artifact = %+v", a)
	}
	// The digest must be accepted by the Shirudo runtime's desired-state parser.
	if _, err := runtime.ParseDesiredUpatch(a.Digest); err != nil {
		t.Fatalf("ParseDesiredUpatch(%q): %v", a.Digest, err)
	}
	// The binding flow must find the artifact by this digest.
	if rec := doReq(t, srv, http.MethodPost, "/v1/bindings", op.Token, types.Binding{ArtifactDigest: a.Digest}); rec.Code != http.StatusCreated {
		t.Fatalf("create binding: got %d (%s)", rec.Code, rec.Body.String())
	}
	// List must not leak the signed bytes.
	list := doReq(t, srv, http.MethodGet, "/v1/artifacts", op.Token, nil)
	if strings.Contains(list.Body.String(), f.upatchB64) {
		t.Fatalf("GET /v1/artifacts leaked upatch bytes")
	}
}

func TestUploadArtifactRejectsBadInput(t *testing.T) {
	srv := newTestServer(t)
	op, err := srv.Store.CreateToken("op", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	f := newUploadFixture(t)

	cases := map[string]func(map[string]any){
		"java type": func(b map[string]any) { b["type"] = "java" },
		"missing unload": func(b map[string]any) {
			delete(b, "upatchUnloadB64")
		},
		"bad base64": func(b map[string]any) { b["upatchB64"] = "!!!not-base64!!!" },
		"empty upatch": func(b map[string]any) {
			b["upatchB64"] = base64.StdEncoding.EncodeToString(nil)
		},
		"path-like name": func(b map[string]any) { b["name"] = "../escape" },
		"digest mismatch": func(b map[string]any) {
			b["digest"] = "sha256:" + f.upatchSHA
		},
	}
	for label, mutate := range cases {
		body := uploadBody("cve-bad-input", f)
		mutate(body)
		rec := doReq(t, srv, http.MethodPost, "/v1/artifacts", op.Token, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d (%s), want 400", label, rec.Code, rec.Body.String())
		}
	}
}

func TestUploadArtifactDuplicateConflicts(t *testing.T) {
	srv := newTestServer(t)
	op, err := srv.Store.CreateToken("op", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	f := newUploadFixture(t)
	if rec := doReq(t, srv, http.MethodPost, "/v1/artifacts", op.Token, uploadBody("dup-shield", f)); rec.Code != http.StatusCreated {
		t.Fatalf("first upload: got %d", rec.Code)
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/artifacts", op.Token, uploadBody("dup-shield", f)); rec.Code != http.StatusConflict {
		t.Fatalf("second upload: got %d (%s), want 409", rec.Code, rec.Body.String())
	}
}

func TestConnectorServesUpatchBytes(t *testing.T) {
	srv := newTestServer(t)
	op, err := srv.Store.CreateToken("op", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	conn, err := srv.Store.Enroll(types.EnrollRequest{BootstrapToken: "test-enroll", ClusterName: "lab"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	f := newUploadFixture(t)
	if rec := doReq(t, srv, http.MethodPost, "/v1/artifacts", op.Token, uploadBody("served-shield", f)); rec.Code != http.StatusCreated {
		t.Fatalf("upload: got %d", rec.Code)
	}

	get := func(path, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/v1/upatches/"+f.upatchSHA, conn.Token)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), f.upatch) {
		t.Fatalf("GET upatch: got %d, body mismatch", rec.Code)
	}
	if got := rec.Header().Get("x-upatch-sha256"); got != f.upatchSHA {
		t.Fatalf("x-upatch-sha256 = %q, want %q", got, f.upatchSHA)
	}

	unSum := sha256.Sum256(f.unload)
	rec = get("/v1/upatches/"+f.upatchSHA+"/unload", conn.Token)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), f.unload) {
		t.Fatalf("GET unload: got %d, body mismatch", rec.Code)
	}
	if got := rec.Header().Get("x-upatch-sha256"); got != hex.EncodeToString(unSum[:]) {
		t.Fatalf("unload x-upatch-sha256 = %q", got)
	}

	// Operator tokens are not connector credentials.
	if rec := get("/v1/upatches/"+f.upatchSHA, op.Token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("operator token on upatch route: got %d, want 401", rec.Code)
	}
	if rec := get("/v1/upatches/"+f.upatchSHA, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous upatch fetch: got %d, want 401", rec.Code)
	}
	if rec := get("/v1/upatches/"+strings.Repeat("0", 64), conn.Token); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown sha: got %d, want 404", rec.Code)
	}
	if rec := get("/v1/upatches/not-a-sha", conn.Token); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid sha: got %d, want 400", rec.Code)
	}
}
