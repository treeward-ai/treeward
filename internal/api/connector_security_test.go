package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/treeward-ai/treeward/internal/types"
)

func TestWithConnector_RequiresBearerPrefix(t *testing.T) {
	srv := newTestServer(t)
	enrolled, err := srv.Store.Enroll(types.EnrollRequest{
		BootstrapToken: "test-enroll",
		ClusterName:    "cluster-a",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	cases := []struct {
		name      string
		authHdr   string
		legacyHdr string
		wantCode  int
	}{
		{"missing auth", "", "", http.StatusUnauthorized},
		{"raw token without Bearer prefix", enrolled.Token, "", http.StatusUnauthorized},
		{"legacy X-Treeward-Token header", "", enrolled.Token, http.StatusUnauthorized},
		{"wrong scheme Basic", "Basic " + enrolled.Token, "", http.StatusUnauthorized},
		{"valid Bearer token", "Bearer " + enrolled.Token, "", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/desired", nil)
			if tc.authHdr != "" {
				req.Header.Set("Authorization", tc.authHdr)
			}
			if tc.legacyHdr != "" {
				req.Header.Set("X-Treeward-Token", tc.legacyHdr)
			}
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("got %d (%s), want %d", rec.Code, rec.Body.String(), tc.wantCode)
			}
		})
	}
}

func TestCrossClusterIsolation(t *testing.T) {
	srv := newTestServer(t)

	connA, err := srv.Store.Enroll(types.EnrollRequest{
		BootstrapToken: "test-enroll",
		ClusterName:    "cluster-a",
	})
	if err != nil {
		t.Fatalf("enroll A: %v", err)
	}
	connB, err := srv.Store.Enroll(types.EnrollRequest{
		BootstrapToken: "test-enroll",
		ClusterName:    "cluster-b",
	})
	if err != nil {
		t.Fatalf("enroll B: %v", err)
	}

	// Each cluster upserts its own node.
	if rec := doReq(t, srv, http.MethodPost, "/v1/inventory", connA.Token, types.InventoryUpsert{
		ClusterID: "cluster-a",
		Nodes:     []types.Node{{ID: "node-a", Hostname: "host-a", Labels: map[string]string{"app": "web"}}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("upsert A: got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/inventory", connB.Token, types.InventoryUpsert{
		ClusterID: "cluster-b",
		Nodes:     []types.Node{{ID: "node-b", Hostname: "host-b", Labels: map[string]string{"app": "web"}}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("upsert B: got %d (%s)", rec.Code, rec.Body.String())
	}

	// Create and promote a binding so desired state has digests for matching nodes.
	art := srv.Store.CreateArtifact(types.Artifact{Name: "shield", Digest: "sha256:aaa", Type: "bpf"})
	b, err := srv.Store.CreateBinding(types.Binding{ArtifactDigest: art.Digest})
	if err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	if _, err := srv.Store.Approve(b.ID, "op"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := srv.Store.Canary(b.ID, "op"); err != nil {
		t.Fatalf("Canary: %v", err)
	}
	if _, err := srv.Store.Promote(b.ID, "op"); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// 1. Cluster A desired state must only include node-a, never node-b.
	rec := doReq(t, srv, http.MethodGet, "/v1/desired", connA.Token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("desired A: got %d", rec.Code)
	}
	var desiredA types.DesiredState
	if err := json.Unmarshal(rec.Body.Bytes(), &desiredA); err != nil {
		t.Fatalf("decode desired A: %v", err)
	}
	if _, ok := desiredA.Nodes["node-a"]; !ok {
		t.Fatalf("expected node-a in cluster-a desired state: %+v", desiredA.Nodes)
	}
	if _, ok := desiredA.Nodes["node-b"]; ok {
		t.Fatalf("cluster-a desired state leaked node-b: %+v", desiredA.Nodes)
	}

	// 2. Cluster A cannot spoof req.ClusterID="cluster-b" on /v1/inventory.
	if rec := doReq(t, srv, http.MethodPost, "/v1/inventory", connA.Token, types.InventoryUpsert{
		ClusterID: "cluster-b",
		Nodes:     []types.Node{{ID: "node-spoof", Hostname: "spoof"}},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed clusterId inventory: got %d, want 403", rec.Code)
	}

	// 3. Cluster A cannot overwrite Cluster B's node-b via /v1/inventory.
	if rec := doReq(t, srv, http.MethodPost, "/v1/inventory", connA.Token, types.InventoryUpsert{
		ClusterID: "cluster-a",
		Nodes:     []types.Node{{ID: "node-b", Hostname: "hijacked-b"}},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-cluster node overwrite in inventory: got %d, want 403", rec.Code)
	}

	// 4. Cluster A cannot report with Node.ClusterID="cluster-b" on /v1/agents/report.
	if rec := doReq(t, srv, http.MethodPost, "/v1/agents/report", connA.Token, []types.AgentReport{
		{Node: types.Node{ID: "node-a", ClusterID: "cluster-b"}, Loaded: []string{"sha256:aaa"}},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed clusterId agent report: got %d, want 403", rec.Code)
	}

	// 5. Cluster A cannot overwrite Cluster B's node-b via /v1/agents/report.
	if rec := doReq(t, srv, http.MethodPost, "/v1/agents/report", connA.Token, []types.AgentReport{
		{Node: types.Node{ID: "node-b", Hostname: "hijacked-report"}, Loaded: []string{}},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-cluster node overwrite in agent report: got %d, want 403", rec.Code)
	}

	// Verify node-b is completely intact in cluster-b.
	for _, n := range srv.Store.ListNodes() {
		if n.ID == "node-b" && (n.ClusterID != "cluster-b" || n.Hostname != "host-b") {
			t.Fatalf("node-b was modified by cluster-a: %+v", n)
		}
	}

	// 6. Attestation results: Cluster A cannot submit results for Cluster B's node-b or an unknown node.
	camp := srv.Store.StartAttestCampaign()
	if rec := doReq(t, srv, http.MethodPost, "/v1/attest/campaigns/"+camp.ID+"/results", connA.Token, []types.AttestResult{
		{NodeID: "node-b", Quote: "mock-" + camp.Nonce},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-cluster attest submit: got %d (%s), want 403", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/v1/attest/campaigns/"+camp.ID+"/results", connA.Token, []types.AttestResult{
		{NodeID: "node-unknown", Quote: "mock-" + camp.Nonce},
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown node attest submit: got %d (%s), want 403", rec.Code, rec.Body.String())
	}

	// Cluster B CAN submit attestation results for its own node-b.
	body, _ := json.Marshal([]types.AttestResult{{NodeID: "node-b", Quote: "mock-" + camp.Nonce}})
	req := httptest.NewRequest(http.MethodPost, "/v1/attest/campaigns/"+camp.ID+"/results", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+connB.Token)
	recB := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recB, req)
	if recB.Code != http.StatusOK {
		t.Fatalf("cluster-b attest submit for node-b: got %d (%s), want 200", recB.Code, recB.Body.String())
	}
}
