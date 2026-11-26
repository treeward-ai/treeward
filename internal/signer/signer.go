package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Signer is the interface both local-dev and future GCP KMS backends satisfy.
type Signer interface {
	Sign(payload []byte) (signature string, err error)
	PublicKeyHex() string
}

type LocalSigner struct {
	mu   sync.Mutex
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewLocal(keyDir string) (*LocalSigner, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	privPath := filepath.Join(keyDir, "ed25519.priv")
	pubPath := filepath.Join(keyDir, "ed25519.pub")

	var priv ed25519.PrivateKey
	var pub ed25519.PublicKey

	if raw, err := os.ReadFile(privPath); err == nil && len(raw) == ed25519.PrivateKeySize {
		priv = ed25519.PrivateKey(raw)
		pub = priv.Public().(ed25519.PublicKey)
	} else {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(privPath, priv, 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
			return nil, err
		}
	}
	return &LocalSigner{priv: priv, pub: pub}, nil
}

func (s *LocalSigner) Sign(payload []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sig := ed25519.Sign(s.priv, payload)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *LocalSigner) PublicKeyHex() string {
	return hex.EncodeToString(s.pub)
}

// ArtifactDigest returns a real sha256 content-address for artifact metadata.
// Later this becomes the digest of the signed .upatch bytes.
func ArtifactDigest(name, typ string, fixes []string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "treeward-artifact-v1\nname=%s\ntype=%s\n", name, typ)
	sorted := append([]string(nil), fixes...)
	sort.Strings(sorted)
	for _, f := range sorted {
		_, _ = fmt.Fprintf(h, "fix=%s\n", f)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func SignTreePayload(digest, op string, selector map[string]string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%v", op, digest, selector))
}
