package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

func TestSQLiteTokenHashingAndPersistence(t *testing.T) {
	dir := t.TempDir()
	sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	dbPath := filepath.Join(dir, "treeward.db")
	st, err := Open(dbPath, "test-enroll", "test-admin-bootstrap", sig)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	created, err := st.CreateToken("alice", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if created.Token == "" || !strings.HasPrefix(created.Token, "tw_") {
		t.Fatalf("unexpected raw token: %q", created.Token)
	}

	// Verify raw token is never stored in SQLite; only its SHA-256 hash is stored.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	var storedID, storedName, storedHash string
	var revoked int
	if err := db.QueryRow(`SELECT id, name, token_hash, revoked FROM api_tokens WHERE id = ?`, created.ID).
		Scan(&storedID, &storedName, &storedHash, &revoked); err != nil {
		t.Fatalf("query api_tokens: %v", err)
	}
	if storedHash == created.Token {
		t.Fatalf("raw token was stored in api_tokens!")
	}
	if storedHash != hashToken(created.Token) {
		t.Fatalf("stored hash = %q, want %q", storedHash, hashToken(created.Token))
	}
	if revoked != 0 {
		t.Fatalf("revoked = %d, want 0", revoked)
	}

	// Reopen store and verify token still authenticates.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := Open(dbPath, "test-enroll", "test-admin-bootstrap", sig)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	tok, ok := st2.AuthenticateToken(created.Token)
	if !ok || tok == nil || tok.Name != "alice" {
		t.Fatalf("AuthenticateToken after reopen failed: ok=%v tok=%+v", ok, tok)
	}

	// Revoke and verify it fails authentication and persists.
	if _, err := st2.RevokeToken(created.ID, "alice"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, ok := st2.AuthenticateToken(created.Token); ok {
		t.Fatalf("revoked token should not authenticate")
	}
}

func TestTokenExpiry(t *testing.T) {
	st := New("test-enroll", "test-admin-bootstrap", nil)
	past := time.Now().UTC().Add(-time.Minute)
	expired, err := st.CreateToken("expired-op", &past)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, ok := st.AuthenticateToken(expired.Token); ok {
		t.Fatalf("expired token should not authenticate")
	}

	future := time.Now().UTC().Add(time.Hour)
	valid, err := st.CreateToken("valid-op", &future)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok, ok := st.AuthenticateToken(valid.Token); !ok || tok.Name != "valid-op" {
		t.Fatalf("valid future token failed: ok=%v tok=%+v", ok, tok)
	}
}

func TestSQLiteTokenRolesAndPersistence(t *testing.T) {
	dir := t.TempDir()
	sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	dbPath := filepath.Join(dir, "treeward.db")
	st, err := Open(dbPath, "test-enroll", "test-admin-bootstrap", sig)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Omitted role defaults to admin.
	defTok, err := st.CreateTokenWithRole("default-admin", "", nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole default: %v", err)
	}
	if defTok.Role != "admin" {
		t.Fatalf("default role = %q, want admin", defTok.Role)
	}

	// Invalid role is rejected.
	if _, err := st.CreateTokenWithRole("bad", "superuser", nil); err == nil {
		t.Fatalf("expected error for invalid role")
	}

	roles := []string{"viewer", "operator", "approver", "admin"}
	minted := map[string]string{}
	for _, r := range roles {
		resp, err := st.CreateTokenWithRole("user-"+r, r, nil)
		if err != nil {
			t.Fatalf("CreateTokenWithRole(%s): %v", r, err)
		}
		if resp.Role != r {
			t.Fatalf("created role = %q, want %q", resp.Role, r)
		}
		minted[r] = resp.Token
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := Open(dbPath, "test-enroll", "test-admin-bootstrap", sig)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	for _, r := range roles {
		tok, ok := st2.AuthenticateToken(minted[r])
		if !ok || tok == nil {
			t.Fatalf("AuthenticateToken(%s) after reopen failed", r)
		}
		if tok.Role != r {
			t.Fatalf("reloaded role for %s = %q, want %q", r, tok.Role, r)
		}
	}
}

func TestSQLiteMigrateLegacyTokensTable(t *testing.T) {
	dir := t.TempDir()
	sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	dbPath := filepath.Join(dir, "legacy.db")

	// Simulate a pre-RBAC database without the `role` column on api_tokens.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	legacyRawToken := "tw_legacy0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	if _, err := rawDB.Exec(`
CREATE TABLE kv (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
);`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := rawDB.Exec(
		`INSERT INTO api_tokens(id, name, token_hash, created_at, expires_at, revoked) VALUES(?,?,?,?,NULL,0)`,
		"tok-legacy", "legacy-op", hashToken(legacyRawToken), time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatalf("insert legacy token: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	// Open with current Store — should migrate safely without losing legacy tokens.
	st, err := Open(dbPath, "test-enroll", "test-admin-bootstrap", sig)
	if err != nil {
		t.Fatalf("Open legacy db: %v", err)
	}
	defer st.Close()

	tok, ok := st.AuthenticateToken(legacyRawToken)
	if !ok || tok == nil {
		t.Fatalf("legacy token failed to authenticate after migration")
	}
	if tok.Role != "admin" {
		t.Fatalf("legacy token role = %q, want admin", tok.Role)
	}

	// Minting a new role-scoped token after migration works.
	viewer, err := st.CreateTokenWithRole("auditor", "viewer", nil)
	if err != nil {
		t.Fatalf("CreateTokenWithRole after migration: %v", err)
	}
	if vtok, ok := st.AuthenticateToken(viewer.Token); !ok || vtok.Role != "viewer" {
		t.Fatalf("viewer token auth failed: ok=%v tok=%+v", ok, vtok)
	}
}

func TestStoreSelfApproveSeparationOfDuties(t *testing.T) {
	st := testStore(t)
	art := st.CreateArtifactBy(types.Artifact{Name: "p1", Type: "bpf"}, "alice")
	b, err := st.CreateBindingBy(types.Binding{ArtifactDigest: art.Digest}, "alice")
	if err != nil {
		t.Fatalf("CreateBindingBy: %v", err)
	}
	if b.CreatedBy != "alice" {
		t.Fatalf("CreatedBy = %q, want alice", b.CreatedBy)
	}

	// Same principal (exact or case-variant) is rejected by default.
	if _, err := st.Approve(b.ID, "alice"); err != ErrSelfApproveForbidden {
		t.Fatalf("Approve by creator: err = %v, want ErrSelfApproveForbidden", err)
	}
	if _, err := st.Approve(b.ID, " Alice "); err != ErrSelfApproveForbidden {
		t.Fatalf("Approve by creator (case/space): err = %v, want ErrSelfApproveForbidden", err)
	}

	// Distinct principal succeeds.
	approved, err := st.Approve(b.ID, "bob")
	if err != nil {
		t.Fatalf("Approve by bob: %v", err)
	}
	if approved.ApprovedBy != "bob" {
		t.Fatalf("ApprovedBy = %q, want bob", approved.ApprovedBy)
	}

	// Opt-in AllowSelfApprove allows same-principal approval.
	st.AllowSelfApprove = true
	b2, err := st.CreateBindingBy(types.Binding{ArtifactDigest: art.Digest}, "alice")
	if err != nil {
		t.Fatalf("CreateBindingBy 2: %v", err)
	}
	if approved2, err := st.Approve(b2.ID, "alice"); err != nil || approved2.ApprovedBy != "alice" {
		t.Fatalf("Approve with AllowSelfApprove=true: err=%v binding=%+v", err, approved2)
	}
}
