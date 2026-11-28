package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/treeward-ai/treeward/internal/types"
)

func TestShieldLibrary_ArchiveRestoreAndLifecycle(t *testing.T) {
	srv := newTestServer(t)
	st := srv.Store
	op, err := st.CreateToken("op", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	art := st.CreateArtifact(types.Artifact{
		Name:   "cve-test-shield",
		Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Type:   "bpf",
		Fixes:  []string{"CVE-2026-31431"},
	})

	// Default lifecycle is "new".
	listRec := doReq(t, srv, http.MethodGet, "/v1/artifacts", op.Token, nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/artifacts: got %d (%s)", listRec.Code, listRec.Body.String())
	}
	var listed []types.Artifact
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(listed) != 1 || listed[0].Lifecycle != "new" || listed[0].Archived {
		t.Fatalf("unexpected initial artifact: %+v", listed)
	}

	// Archive blocks new bindings and rejects double-archive.
	if rec := doReq(t, srv, http.MethodPost, "/v1/artifacts/"+art.ID+"/archive", op.Token, nil); rec.Code != http.StatusOK {
		t.Fatalf("archive: got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/artifacts/"+art.ID+"/archive", op.Token, nil); rec.Code != http.StatusConflict {
		t.Fatalf("double archive: want 409, got %d", rec.Code)
	}
	bindBlocked := doReq(t, srv, http.MethodPost, "/v1/bindings", op.Token, types.Binding{ArtifactDigest: art.Digest})
	if bindBlocked.Code != http.StatusConflict {
		t.Fatalf("bind archived: want 409, got %d (%s)", bindBlocked.Code, bindBlocked.Body.String())
	}

	// Restore re-enables binding creation.
	if rec := doReq(t, srv, http.MethodPost, "/v1/artifacts/"+art.ID+"/restore", op.Token, nil); rec.Code != http.StatusOK {
		t.Fatalf("restore: got %d (%s)", rec.Code, rec.Body.String())
	}
	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", op.Token, types.Binding{ArtifactDigest: art.Digest})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("bind after restore: want 201, got %d (%s)", bindRec.Code, bindRec.Body.String())
	}
	var b types.Binding
	if err := json.Unmarshal(bindRec.Body.Bytes(), &b); err != nil {
		t.Fatalf("unmarshal binding: %v", err)
	}

	// Promote -> revert marks artifact validated.
	if _, err := st.Approve(b.ID, "approver@test"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := st.Canary(b.ID, "op@test"); err != nil {
		t.Fatalf("canary: %v", err)
	}
	if _, err := st.Promote(b.ID, "op@test"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := st.Revert(b.ID, "op@test"); err != nil {
		t.Fatalf("revert: %v", err)
	}

	after := st.ListArtifacts()
	if len(after) != 1 || after[0].Lifecycle != "validated" || after[0].ValidatedAt == nil {
		t.Fatalf("expected validated artifact after promote->revert, got %+v", after)
	}
}
