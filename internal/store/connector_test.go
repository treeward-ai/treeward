package store

import (
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

func TestConnectorTokenHashingAndPersistence(t *testing.T) {
	dir := t.TempDir()
	sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	dbPath := filepath.Join(dir, "treeward.db")
	st, err := Open(dbPath, "test-enroll", "test-admin", sig)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Empty or wrong bootstrap token must be rejected.
	if _, err := st.Enroll(types.EnrollRequest{BootstrapToken: "", ClusterName: "c1"}); err == nil {
		t.Fatal("expected empty bootstrap token to fail")
	}
	if _, err := st.Enroll(types.EnrollRequest{BootstrapToken: "wrong", ClusterName: "c1"}); err == nil {
		t.Fatal("expected wrong bootstrap token to fail")
	}

	// Store with empty bootstrap token must reject even empty request token.
	emptyBootStore := New("", "test-admin", sig)
	if _, err := emptyBootStore.Enroll(types.EnrollRequest{BootstrapToken: "", ClusterName: "c1"}); err == nil {
		t.Fatal("expected store with empty bootstrap token to reject enroll")
	}

	resp, err := st.Enroll(types.EnrollRequest{
		BootstrapToken: "test-enroll",
		ClusterName:    "cluster-a",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Token must be 256-bit: "ctok_" + 64 hex characters.
	if !strings.HasPrefix(resp.Token, "ctok_") {
		t.Fatalf("connector token %q missing ctok_ prefix", resp.Token)
	}
	hexPart := strings.TrimPrefix(resp.Token, "ctok_")
	if len(hexPart) != 64 {
		t.Fatalf("connector token hex length = %d, want 64", len(hexPart))
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Fatalf("connector token hex part invalid: %v", err)
	}

	// Raw connector token must NOT appear anywhere in the SQLite kv.state blob.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	var rawState []byte
	if err := db.QueryRow(`SELECT value FROM kv WHERE key = ?`, "state").Scan(&rawState); err != nil {
		t.Fatalf("query kv state: %v", err)
	}
	if strings.Contains(string(rawState), resp.Token) {
		t.Fatal("raw connector token was persisted in SQLite kv.state blob")
	}
	if !strings.Contains(string(rawState), hashToken(resp.Token)) {
		t.Fatal("expected SHA-256 hash of connector token in SQLite kv.state blob")
	}

	// Reopen DB and verify LookupConnector still succeeds with the raw token.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := Open(dbPath, "test-enroll", "test-admin", sig)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	conn, ok := st2.LookupConnector(resp.Token)
	if !ok || conn == nil {
		t.Fatalf("LookupConnector failed after DB reopen")
	}
	if conn.ID != resp.ConnectorID || conn.ClusterID != "cluster-a" {
		t.Fatalf("unexpected connector after reopen: %+v", conn)
	}
	if conn.Token != "" {
		t.Fatalf("connector Token field should remain empty, got %q", conn.Token)
	}
	if _, ok := st2.LookupConnector("ctok_" + strings.Repeat("0", 64)); ok {
		t.Fatal("expected unknown connector token to fail lookup")
	}
	if _, ok := st2.LookupConnector(""); ok {
		t.Fatal("expected empty connector token to fail lookup")
	}
}

func TestUpsertInventoryPreventsCrossClusterHijack(t *testing.T) {
	s := testStore(t)
	s.UpsertInventory([]types.Node{
		{ID: "node-b", Hostname: "host-b", Labels: map[string]string{"env": "prod"}},
	}, "cluster-b")

	// Direct UpsertInventory from cluster-a must not overwrite node-b.
	s.UpsertInventory([]types.Node{
		{ID: "node-b", Hostname: "hijacked", Labels: map[string]string{"env": "evil"}},
	}, "cluster-a")

	nodes := s.ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].ClusterID != "cluster-b" || nodes[0].Hostname != "host-b" {
		t.Fatalf("node-b was hijacked: %+v", nodes[0])
	}
}
