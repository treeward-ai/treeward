package signer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

func signOp(t *testing.T, s Signer, op types.TreeOp) types.TreeOp {
	t.Helper()
	payload, err := CanonicalTreePayload(op)
	if err != nil {
		t.Fatalf("CanonicalTreePayload: %v", err)
	}
	sig, err := s.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	op.Signature = sig
	return op
}

func buildValidChain(t *testing.T, s Signer) []types.TreeOp {
	t.Helper()
	base := time.Date(2026, 11, 26, 12, 0, 0, 123456789, time.UTC)

	op1 := signOp(t, s, types.TreeOp{
		Seq:       1,
		PrevHash:  "",
		Op:        "add",
		Digest:    "sha256:aaa111",
		Selector:  map[string]string{types.LabelRollout: types.RolloutCanary, "tier": "web"},
		BindingID: "bind-1",
		At:        base,
	})

	h1, err := TreeOpHash(op1)
	if err != nil {
		t.Fatalf("TreeOpHash(op1): %v", err)
	}
	op2 := signOp(t, s, types.TreeOp{
		Seq:       2,
		PrevHash:  h1,
		Op:        "add",
		Digest:    "sha256:aaa111",
		Selector:  map[string]string{"tier": "web"},
		BindingID: "bind-1",
		At:        base.Add(time.Minute),
	})

	h2, err := TreeOpHash(op2)
	if err != nil {
		t.Fatalf("TreeOpHash(op2): %v", err)
	}
	op3 := signOp(t, s, types.TreeOp{
		Seq:       3,
		PrevHash:  h2,
		Op:        "add",
		Digest:    "sha256:bbb222",
		Selector:  map[string]string{"env": "prod"},
		BindingID: "bind-2",
		At:        base.Add(2 * time.Minute),
	})

	h3, err := TreeOpHash(op3)
	if err != nil {
		t.Fatalf("TreeOpHash(op3): %v", err)
	}
	op4 := signOp(t, s, types.TreeOp{
		Seq:       4,
		PrevHash:  h3,
		Op:        "delete",
		Digest:    "sha256:aaa111",
		Selector:  map[string]string{},
		BindingID: "bind-1",
		At:        base.Add(3 * time.Minute),
	})

	return []types.TreeOp{op1, op2, op3, op4}
}

func TestCanonicalTreePayloadDeterminismAndSpecialChars(t *testing.T) {
	ts := time.Date(2026, 11, 26, 10, 20, 30, 987654321, time.UTC)

	// Selector map insertion order must not affect canonical payload.
	opA := types.TreeOp{
		Seq:       1,
		Op:        "add",
		Digest:    "sha256:deadbeef",
		Selector:  map[string]string{"z:key": "val|1", "a key": "val:2", "m\"q": "a b|c:d"},
		BindingID: "bind-special",
		At:        ts,
	}
	opB := types.TreeOp{
		Seq:       1,
		Op:        "add",
		Digest:    "sha256:deadbeef",
		Selector:  map[string]string{"m\"q": "a b|c:d", "a key": "val:2", "z:key": "val|1"},
		BindingID: "bind-special",
		At:        ts.In(time.FixedZone("UTC+2", 2*3600)), // non-UTC same instant
	}

	pA, err := CanonicalTreePayload(opA)
	if err != nil {
		t.Fatalf("CanonicalTreePayload(opA): %v", err)
	}
	pB, err := CanonicalTreePayload(opB)
	if err != nil {
		t.Fatalf("CanonicalTreePayload(opB): %v", err)
	}
	if !bytes.HasPrefix(pA, []byte("treeward-tree-op-v1\n")) {
		t.Fatalf("missing domain separation prefix: %q", string(pA))
	}
	if !bytes.Equal(pA, pB) {
		t.Fatalf("canonical payload not deterministic:\nA=%s\nB=%s", pA, pB)
	}

	// nil selector and empty selector must serialize identically.
	pNil, err := CanonicalTreePayload(types.TreeOp{Seq: 1, Op: "delete", Digest: "d", Selector: nil, At: ts})
	if err != nil {
		t.Fatal(err)
	}
	pEmpty, err := CanonicalTreePayload(types.TreeOp{Seq: 1, Op: "delete", Digest: "d", Selector: map[string]string{}, At: ts})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pNil, pEmpty) {
		t.Fatalf("nil vs empty selector payloads differ:\nnil=%s\nempty=%s", pNil, pEmpty)
	}

	// Ambiguous special characters (|, :, spaces) that could collide under fmt.Sprintf("%s|%s|%v")
	// MUST produce distinct canonical payloads.
	ambiguousPairs := [][2]types.TreeOp{
		{
			{Seq: 1, Op: "add", Digest: "d", Selector: map[string]string{"a": "b c:d"}, At: ts},
			{Seq: 1, Op: "add", Digest: "d", Selector: map[string]string{"a": "b", "c": "d"}, At: ts},
		},
		{
			{Seq: 1, Op: "add", Digest: "d", Selector: map[string]string{"k:1": "v|2"}, At: ts},
			{Seq: 1, Op: "add", Digest: "d", Selector: map[string]string{"k": "1:v|2"}, At: ts},
		},
		{
			{Seq: 1, Op: "add", Digest: "x|y", Selector: map[string]string{"k": "v"}, At: ts},
			{Seq: 1, Op: "add|x", Digest: "y", Selector: map[string]string{"k": "v"}, At: ts},
		},
	}
	for i, pair := range ambiguousPairs {
		p1, err := CanonicalTreePayload(pair[0])
		if err != nil {
			t.Fatalf("pair %d[0]: %v", i, err)
		}
		p2, err := CanonicalTreePayload(pair[1])
		if err != nil {
			t.Fatalf("pair %d[1]: %v", i, err)
		}
		if bytes.Equal(p1, p2) {
			t.Fatalf("pair %d produced colliding canonical payloads: %s", i, p1)
		}
	}

	// Verify signing + JSON round-trip with special characters in selectors.
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signed := signOp(t, s, opA)
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded types.TreeOp
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeOp(s.PublicKeyHex(), decoded); err != nil {
		t.Fatalf("VerifyTreeOp after JSON round-trip failed: %v", err)
	}
}

func TestVerifyTreeChainAndReplayLifecycle(t *testing.T) {
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := s.PublicKeyHex()
	ops := buildValidChain(t, s)

	// Verify prefix chains and full chain.
	for n := 0; n <= len(ops); n++ {
		if err := VerifyTreeChain(pub, ops[:n]); err != nil {
			t.Fatalf("VerifyTreeChain(ops[:%d]): %v", n, err)
		}
		if err := VerifyTreeChainFrom(pub, ops[:n], int64(n)); err != nil {
			t.Fatalf("VerifyTreeChainFrom(ops[:%d], %d): %v", n, n, err)
		}
	}

	// Verify TreeOpHash format.
	h1, err := TreeOpHash(ops[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, "sha256:") || len(h1) != len("sha256:")+64 {
		t.Fatalf("unexpected TreeOpHash format: %q", h1)
	}
	if ops[1].PrevHash != h1 {
		t.Fatalf("ops[1].PrevHash = %q, want %q", ops[1].PrevHash, h1)
	}

	canaryLabels := map[string]string{types.LabelRollout: types.RolloutCanary, "tier": "web", "env": "prod"}
	webProdLabels := map[string]string{"tier": "web", "env": "prod"}
	otherLabels := map[string]string{"tier": "db", "env": "staging"}

	// Step 1: canary only.
	if got := ReplayDesiredForNode(ops[:1], canaryLabels); !reflect.DeepEqual(got, []string{"sha256:aaa111"}) {
		t.Fatalf("canary step canaryLabels = %v, want [sha256:aaa111]", got)
	}
	if got := ReplayDesiredForNode(ops[:1], webProdLabels); len(got) != 0 {
		t.Fatalf("canary step webProdLabels = %v, want empty", got)
	}

	// Step 2: promote to tier=web.
	if got := ReplayDesiredForNode(ops[:2], webProdLabels); !reflect.DeepEqual(got, []string{"sha256:aaa111"}) {
		t.Fatalf("promote step webProdLabels = %v, want [sha256:aaa111]", got)
	}
	if got := ReplayDesiredForNode(ops[:2], otherLabels); len(got) != 0 {
		t.Fatalf("promote step otherLabels = %v, want empty", got)
	}

	// Step 3: add second digest for env=prod (sorted output).
	if got := ReplayDesiredForNode(ops[:3], webProdLabels); !reflect.DeepEqual(got, []string{"sha256:aaa111", "sha256:bbb222"}) {
		t.Fatalf("step 3 webProdLabels = %v, want [sha256:aaa111 sha256:bbb222]", got)
	}

	// Step 4: delete/revert sha256:aaa111 globally; sha256:bbb222 stays loaded.
	if got := ReplayDesiredForNode(ops[:4], canaryLabels); !reflect.DeepEqual(got, []string{"sha256:bbb222"}) {
		t.Fatalf("delete step canaryLabels = %v, want [sha256:bbb222]", got)
	}
	if got := ReplayDesiredForNode(ops[:4], webProdLabels); !reflect.DeepEqual(got, []string{"sha256:bbb222"}) {
		t.Fatalf("delete step webProdLabels = %v, want [sha256:bbb222]", got)
	}
	if got := ReplayDesiredForNode(ops[:4], otherLabels); len(got) != 0 {
		t.Fatalf("delete step otherLabels = %v, want empty", got)
	}
}

func TestVerifyTreeChainEmptyAndPubKeyValidation(t *testing.T) {
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := s.PublicKeyHex()

	if err := VerifyTreeChain(pub, nil); err != nil {
		t.Fatalf("empty tree (nil) should pass with lastSeq=0: %v", err)
	}
	if err := VerifyTreeChain(pub, []types.TreeOp{}); err != nil {
		t.Fatalf("empty tree (slice) should pass with lastSeq=0: %v", err)
	}
	if err := VerifyTreeChainFrom(pub, nil, 1); err == nil {
		t.Fatal("empty tree with lastSeq=1 must fail as rollback")
	}
	if err := VerifyTreeChainFrom(pub, nil, -1); err == nil {
		t.Fatal("negative lastSeq must fail")
	}
	if err := VerifyTreeChain("", nil); err == nil {
		t.Fatal("empty pubkey must fail even for empty tree")
	}
	if err := VerifyTreeChain("not-hex", nil); err == nil {
		t.Fatal("invalid hex pubkey must fail even for empty tree")
	}
	if err := VerifyTreeChain("deadbeef", nil); err == nil {
		t.Fatal("short pubkey must fail even for empty tree")
	}
}

func TestVerifyTreeChainTamperingRejected(t *testing.T) {
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := s.PublicKeyHex()

	cloneOps := func(in []types.TreeOp) []types.TreeOp {
		out := make([]types.TreeOp, len(in))
		for i, op := range in {
			sel := map[string]string{}
			for k, v := range op.Selector {
				sel[k] = v
			}
			op.Selector = sel
			out[i] = op
		}
		return out
	}

	valid := buildValidChain(t, s)

	tests := []struct {
		name    string
		pubKey  string
		lastSeq int64
		mutate  func([]types.TreeOp) []types.TreeOp
	}{
		{
			name:   "tampered digest",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[1].Digest = "sha256:evil"
				return ops
			},
		},
		{
			name:   "tampered selector value",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].Selector["tier"] = "all"
				return ops
			},
		},
		{
			name:   "tampered selector added key",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[1].Selector["extra"] = "1"
				return ops
			},
		},
		{
			name:   "tampered timestamp",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[2].At = ops[2].At.Add(time.Nanosecond)
				return ops
			},
		},
		{
			name:   "tampered binding id",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].BindingID = "bind-forged"
				return ops
			},
		},
		{
			name:   "tampered op verb",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[3].Op = "add"
				return ops
			},
		},
		{
			name:   "unsupported op verb",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].Op = "noop"
				return ops
			},
		},
		{
			name:   "non-empty prevHash on seq 1",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].PrevHash = "sha256:0000"
				return ops
			},
		},
		{
			name:   "broken prevHash link",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[2].PrevHash = "sha256:deadbeef"
				return ops
			},
		},
		{
			name:   "reordered ops",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[1], ops[2] = ops[2], ops[1]
				return ops
			},
		},
		{
			name:   "dropped first op",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				return ops[1:]
			},
		},
		{
			name:    "truncated chain rollback",
			pubKey:  pub,
			lastSeq: 4,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				return ops[:3]
			},
		},
		{
			name:   "wrong pubkey",
			pubKey: otherSigner.PublicKeyHex(),
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				return ops
			},
		},
		{
			name:   "missing signature",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].Signature = ""
				return ops
			},
		},
		{
			name:   "bad base64 signature",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].Signature = "!!!not-base64!!!"
				return ops
			},
		},
		{
			name:   "wrong signature length",
			pubKey: pub,
			mutate: func(ops []types.TreeOp) []types.TreeOp {
				ops[0].Signature = base64.StdEncoding.EncodeToString([]byte("short"))
				return ops
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := tc.mutate(cloneOps(valid))
			if err := VerifyTreeChainFrom(tc.pubKey, ops, tc.lastSeq); err == nil {
				t.Fatalf("expected VerifyTreeChainFrom to reject %q, got nil", tc.name)
			}
		})
	}
}
