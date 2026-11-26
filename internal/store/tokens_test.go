package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/signer"
)

func TestSQLiteTokenHashingAndPersistence(t *testing.T) {
	dir := t.TempDir()
	sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	dbPath := filepath.Join(dir, "treeward.db")
	st, err := Open(dbPath, "test-bootstrap", sig)
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
	st2, err := Open(dbPath, "test-bootstrap", sig)
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
	st := New("test-bootstrap", nil)
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
