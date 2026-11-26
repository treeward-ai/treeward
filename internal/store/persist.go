package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

type snapshot struct {
	Connectors map[string]*types.Connector      `json:"connectors"`
	Nodes      map[string]*types.Node           `json:"nodes"`
	Artifacts  map[string]*types.Artifact       `json:"artifacts"`
	Bindings   map[string]*types.Binding        `json:"bindings"`
	Tree       []types.TreeOp                   `json:"tree"`
	Audit      []types.AuditEvent               `json:"audit"`
	Campaigns  map[string]*types.AttestCampaign `json:"campaigns"`
}

// Open loads (or creates) a SQLite-backed store at dbPath.
func Open(dbPath, enrollToken, adminBootstrapToken string, sig signer.Signer) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// One writer; avoid busy locks under Kind.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
);`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := os.Stat(dbPath); err == nil {
		_ = os.Chmod(dbPath, 0o600)
	}

	s := &Store{
		EnrollToken:         enrollToken,
		AdminBootstrapToken: adminBootstrapToken,
		Signer:              sig,
		db:                  db,
		Connectors:          map[string]*types.Connector{},
		Nodes:               map[string]*types.Node{},
		Artifacts:           map[string]*types.Artifact{},
		Bindings:            map[string]*types.Binding{},
		Campaigns:           map[string]*types.AttestCampaign{},
		tokens:              map[string]*storedToken{},
	}
	if err := s.load(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) load() error {
	var raw []byte
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, "state").Scan(&raw)
	if err == sql.ErrNoRows {
		return s.loadTokens()
	}
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if snap.Connectors != nil {
		s.Connectors = snap.Connectors
	}
	if snap.Nodes != nil {
		s.Nodes = snap.Nodes
	}
	if snap.Artifacts != nil {
		s.Artifacts = snap.Artifacts
	}
	if snap.Bindings != nil {
		s.Bindings = snap.Bindings
	}
	if snap.Tree != nil {
		s.Tree = snap.Tree
	}
	if snap.Audit != nil {
		s.Audit = snap.Audit
	}
	if snap.Campaigns != nil {
		s.Campaigns = snap.Campaigns
	}
	return s.loadTokens()
}

// persistLocked writes the in-memory state. Caller must hold s.mu.
func (s *Store) persistLocked() {
	if s.db == nil {
		return
	}
	snap := snapshot{
		Connectors: s.Connectors,
		Nodes:      s.Nodes,
		Artifacts:  s.Artifacts,
		Bindings:   s.Bindings,
		Tree:       s.Tree,
		Audit:      s.Audit,
		Campaigns:  s.Campaigns,
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "treeward persist marshal: %v\n", err)
		return
	}
	_, err = s.db.Exec(
		`INSERT INTO kv(key, value, updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		"state", raw, time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		// Best-effort; API stays up. Logs would need a logger injected.
		fmt.Fprintf(os.Stderr, "treeward persist: %v\n", err)
	}
}
