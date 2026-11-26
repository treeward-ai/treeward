package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/treeward-ai/treeward/internal/types"
)

func TestOversizedJSONBodyRejected(t *testing.T) {
	srv := newTestServer(t)
	minted, err := srv.Store.CreateToken("size-test", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	// Build a valid JSON payload larger than the 4 MiB limit.
	oversized := `{"name":"` + strings.Repeat("a", maxJSONBodyBytes+1024) + `","type":"bpf"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/artifacts", bytes.NewBufferString(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /v1/artifacts with >4MiB body: got %d (%s), want %d", rec.Code, rec.Body.String(), http.StatusRequestEntityTooLarge)
	}

	// Also verify optional-body handlers (e.g. approve) accept empty bodies and reject oversized bodies with 413.
	artRec := doReq(t, srv, http.MethodPost, "/v1/artifacts", minted.Token, types.Artifact{Name: "small", Type: "bpf"})
	if artRec.Code != http.StatusCreated {
		t.Fatalf("create artifact: %d", artRec.Code)
	}
	var art types.Artifact
	if err := json.Unmarshal(artRec.Body.Bytes(), &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	bindRec := doReq(t, srv, http.MethodPost, "/v1/bindings", minted.Token, types.Binding{
		ArtifactDigest: art.Digest,
		TreeRef:        "default",
	})
	if bindRec.Code != http.StatusCreated {
		t.Fatalf("create binding: %d", bindRec.Code)
	}
	var bind types.Binding
	if err := json.Unmarshal(bindRec.Body.Bytes(), &bind); err != nil {
		t.Fatalf("unmarshal binding: %v", err)
	}

	// Oversized approve body -> 413.
	oversizedApprove := `{"actor":"` + strings.Repeat("b", maxJSONBodyBytes+1024) + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", bytes.NewBufferString(oversizedApprove))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+minted.Token)
	rec2 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /v1/bindings/{id}/approve with >4MiB body: got %d (%s), want %d", rec2.Code, rec2.Body.String(), http.StatusRequestEntityTooLarge)
	}

	// Empty approve body -> 200.
	req3 := httptest.NewRequest(http.MethodPost, "/v1/bindings/"+bind.ID+"/approve", nil)
	req3.Header.Set("Authorization", "Bearer "+minted.Token)
	rec3 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("POST /v1/bindings/{id}/approve with empty body: got %d (%s), want 200", rec3.Code, rec3.Body.String())
	}
}
