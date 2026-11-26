package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

type storedToken struct {
	types.APIToken
	TokenHash string
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) loadTokens() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, name, token_hash, created_at, expires_at, revoked FROM api_tokens`)
	if err != nil {
		return fmt.Errorf("load api_tokens: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			tok        storedToken
			createdStr string
			expiresStr sql.NullString
			revokedInt int
		)
		if err := rows.Scan(&tok.ID, &tok.Name, &tok.TokenHash, &createdStr, &expiresStr, &revokedInt); err != nil {
			return fmt.Errorf("scan api_token: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, createdStr); err == nil {
			tok.CreatedAt = t
		}
		if expiresStr.Valid && expiresStr.String != "" {
			if t, err := time.Parse(time.RFC3339Nano, expiresStr.String); err == nil {
				tok.ExpiresAt = &t
			}
		}
		tok.Revoked = revokedInt != 0
		s.tokens[tok.ID] = &tok
	}
	return rows.Err()
}

// CreateToken mints a new operator API token, stores only its SHA-256 hash,
// and returns the raw token once.
func (s *Store) CreateToken(name string, expiresAt *time.Time) (*types.CreateTokenResponse, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("token name is required")
	}
	var rawBytes [32]byte
	if _, err := rand.Read(rawBytes[:]); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	rawToken := "tw_" + hex.EncodeToString(rawBytes[:])
	tokenHash := hashToken(rawToken)

	now := time.Now().UTC()
	var expCopy *time.Time
	if expiresAt != nil {
		t := expiresAt.UTC()
		expCopy = &t
	}

	st := &storedToken{
		APIToken: types.APIToken{
			ID:        id("tok"),
			Name:      name,
			CreatedAt: now,
			ExpiresAt: expCopy,
			Revoked:   false,
		},
		TokenHash: tokenHash,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		var expVal any
		if st.ExpiresAt != nil {
			expVal = st.ExpiresAt.Format(time.RFC3339Nano)
		}
		if _, err := s.db.Exec(
			`INSERT INTO api_tokens(id, name, token_hash, created_at, expires_at, revoked) VALUES(?,?,?,?,?,0)`,
			st.ID, st.Name, st.TokenHash, st.CreatedAt.Format(time.RFC3339Nano), expVal,
		); err != nil {
			return nil, fmt.Errorf("insert api_token: %w", err)
		}
	}
	s.tokens[st.ID] = st
	s.auditLocked("token.create", "admin-bootstrap", "", "", "id="+st.ID+" name="+st.Name)
	s.persistLocked()

	return &types.CreateTokenResponse{
		APIToken: st.APIToken,
		Token:    rawToken,
	}, nil
}

// ListTokens returns all API tokens (metadata only; hashes and raw values are never returned).
func (s *Store) ListTokens() []types.APIToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.APIToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t.APIToken)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// RevokeToken marks the token with the given ID as revoked.
func (s *Store) RevokeToken(tokenID, actor string) (*types.APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tokens[tokenID]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	if !st.Revoked {
		if s.db != nil {
			if _, err := s.db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE id = ?`, tokenID); err != nil {
				return nil, fmt.Errorf("revoke api_token: %w", err)
			}
		}
		st.Revoked = true
		if actor == "" {
			actor = "operator"
		}
		s.auditLocked("token.revoke", actor, "", "", "id="+st.ID+" name="+st.Name)
		s.persistLocked()
	}
	cp := st.APIToken
	return &cp, nil
}

// AuthenticateToken validates a raw bearer token using SHA-256 + crypto/subtle.
// Returns the token metadata and true if valid, not revoked, and not expired.
func (s *Store) AuthenticateToken(rawToken string) (*types.APIToken, bool) {
	if rawToken == "" {
		return nil, false
	}
	wantHash := []byte(hashToken(rawToken))
	now := time.Now().UTC()

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(st.TokenHash), wantHash) == 1 {
			if st.Revoked {
				return nil, false
			}
			if st.ExpiresAt != nil && !now.Before(*st.ExpiresAt) {
				return nil, false
			}
			cp := st.APIToken
			return &cp, true
		}
	}
	return nil, false
}
