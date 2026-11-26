package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

const (
	treeOpDomain     = "treeward-tree-op-v1\n"
	treeOpHashDomain = "treeward-tree-op-hash-v1\n"
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

// SelectorKV represents a single key-value entry in a canonicalized selector.
type SelectorKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type canonicalTreeOp struct {
	Seq       int64        `json:"seq"`
	PrevHash  string       `json:"prev_hash"`
	Op        string       `json:"op"`
	Digest    string       `json:"digest"`
	Selector  []SelectorKV `json:"selector"`
	BindingID string       `json:"binding_id"`
	At        string       `json:"at"`
}

// CanonicalTreePayload builds a domain-separated, deterministic JSON encoding
// of a TreeOp's signed fields. Selector entries are sorted into a slice of
// key-value structs so special characters (|, :, spaces, quotes) cannot cause
// ambiguity.
func CanonicalTreePayload(op types.TreeOp) ([]byte, error) {
	sel := make([]SelectorKV, 0, len(op.Selector))
	for k, v := range op.Selector {
		sel = append(sel, SelectorKV{Key: k, Value: v})
	}
	sort.Slice(sel, func(i, j int) bool {
		if sel[i].Key != sel[j].Key {
			return sel[i].Key < sel[j].Key
		}
		return sel[i].Value < sel[j].Value
	})

	doc := canonicalTreeOp{
		Seq:       op.Seq,
		PrevHash:  op.PrevHash,
		Op:        op.Op,
		Digest:    op.Digest,
		Selector:  sel,
		BindingID: op.BindingID,
		At:        op.At.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical tree op: %w", err)
	}
	out := make([]byte, 0, len(treeOpDomain)+len(encoded))
	out = append(out, treeOpDomain...)
	out = append(out, encoded...)
	return out, nil
}

// TreeOpHash computes a domain-separated SHA-256 hash over a TreeOp's
// canonical payload and signature, cryptographically chaining each op to the
// previous op in the tree log.
func TreeOpHash(op types.TreeOp) (string, error) {
	payload, err := CanonicalTreePayload(op)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(treeOpHashDomain))
	_, _ = h.Write(payload)
	_, _ = h.Write([]byte("\nsig="))
	_, _ = h.Write([]byte(op.Signature))
	_, _ = h.Write([]byte("\n"))
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ParsePublicKeyHex decodes and validates a hex-encoded Ed25519 public key.
func ParsePublicKeyHex(pubKeyHex string) (ed25519.PublicKey, error) {
	pubKeyHex = strings.TrimSpace(pubKeyHex)
	if pubKeyHex == "" {
		return nil, fmt.Errorf("empty ed25519 public key")
	}
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyTreeOp verifies the Ed25519 signature over a single TreeOp's canonical payload.
func VerifyTreeOp(pubKeyHex string, op types.TreeOp) error {
	pub, err := ParsePublicKeyHex(pubKeyHex)
	if err != nil {
		return err
	}
	return verifyTreeOpWithKey(pub, op)
}

func verifyTreeOpWithKey(pub ed25519.PublicKey, op types.TreeOp) error {
	if op.Signature == "" {
		return fmt.Errorf("tree op seq=%d: missing signature", op.Seq)
	}
	sig, err := base64.StdEncoding.DecodeString(op.Signature)
	if err != nil {
		return fmt.Errorf("tree op seq=%d: decode signature: %w", op.Seq, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("tree op seq=%d: invalid signature length %d", op.Seq, len(sig))
	}
	payload, err := CanonicalTreePayload(op)
	if err != nil {
		return fmt.Errorf("tree op seq=%d: %w", op.Seq, err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("tree op seq=%d: invalid ed25519 signature", op.Seq)
	}
	return nil
}

// VerifyTreeChain verifies that ops form a valid, strictly sequential,
// hash-chained, Ed25519-signed tree log starting at seq 1 (or an empty tree).
func VerifyTreeChain(pubKeyHex string, ops []types.TreeOp) error {
	return VerifyTreeChainFrom(pubKeyHex, ops, 0)
}

// VerifyTreeChainFrom verifies the full tree chain and rejects rollback if the
// verified chain length is smaller than lastVerifiedSeq. An empty tree (seq=0)
// is accepted only when lastVerifiedSeq == 0.
func VerifyTreeChainFrom(pubKeyHex string, ops []types.TreeOp, lastVerifiedSeq int64) error {
	pub, err := ParsePublicKeyHex(pubKeyHex)
	if err != nil {
		return err
	}
	if lastVerifiedSeq < 0 {
		return fmt.Errorf("invalid lastVerifiedSeq %d", lastVerifiedSeq)
	}
	if int64(len(ops)) < lastVerifiedSeq {
		return fmt.Errorf("tree rollback detected: chain length %d < last verified seq %d", len(ops), lastVerifiedSeq)
	}
	var prevHash string
	for i, op := range ops {
		wantSeq := int64(i + 1)
		if op.Seq != wantSeq {
			return fmt.Errorf("tree op index %d: seq=%d, want %d", i, op.Seq, wantSeq)
		}
		if op.Op != "add" && op.Op != "delete" {
			return fmt.Errorf("tree op seq=%d: unsupported op %q", op.Seq, op.Op)
		}
		if i == 0 {
			if op.PrevHash != "" {
				return fmt.Errorf("tree op seq=1: prevHash must be empty, got %q", op.PrevHash)
			}
		} else if op.PrevHash != prevHash {
			return fmt.Errorf("tree op seq=%d: prevHash mismatch: got %q, want %q", op.Seq, op.PrevHash, prevHash)
		}
		if err := verifyTreeOpWithKey(pub, op); err != nil {
			return err
		}
		prevHash, err = TreeOpHash(op)
		if err != nil {
			return fmt.Errorf("tree op seq=%d: hash: %w", op.Seq, err)
		}
	}
	return nil
}

// MatchSelector returns true when labels satisfy all key-value pairs in sel.
// An empty selector matches all nodes.
func MatchSelector(labels, sel map[string]string) bool {
	if len(sel) == 0 {
		return true
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ReplayDesiredForNode replays verified TreeOps against a node's labels and
// returns the sorted list of digests that should be loaded on that node.
func ReplayDesiredForNode(ops []types.TreeOp, labels map[string]string) []string {
	active := map[string]struct{}{}
	for _, op := range ops {
		if !MatchSelector(labels, op.Selector) {
			continue
		}
		switch op.Op {
		case "add":
			active[op.Digest] = struct{}{}
		case "delete":
			delete(active, op.Digest)
		}
	}
	digests := make([]string, 0, len(active))
	for d := range active {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	return digests
}
