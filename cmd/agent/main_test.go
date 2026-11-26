package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/store"
	"github.com/treeward-ai/treeward/internal/types"
)

func TestAgentSendsBearerAuthWhenLocalTokenSet(t *testing.T) {
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/v1/local/desired":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		case "/v1/local/attest":
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/v1/local/report":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	if _, err := getDesired(srv.URL, "local-secret"); err != nil {
		t.Fatalf("getDesired: %v", err)
	}
	if _, err := getPendingAttest(srv.URL, "local-secret"); err != nil {
		t.Fatalf("getPendingAttest: %v", err)
	}
	if err := postReport(srv.URL, "local-secret", []types.AgentReport{}); err != nil {
		t.Fatalf("postReport: %v", err)
	}
	if err := postAttest(srv.URL, "local-secret", []types.AttestResult{}); err != nil {
		t.Fatalf("postAttest: %v", err)
	}

	if len(gotAuth) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(gotAuth))
	}
	for i, h := range gotAuth {
		if h != "Bearer local-secret" {
			t.Fatalf("request %d auth = %q, want %q", i, h, "Bearer local-secret")
		}
	}

	// When token is empty, Authorization header should not be sent.
	gotAuth = nil
	if _, err := getDesired(srv.URL, ""); err != nil {
		t.Fatalf("getDesired empty token: %v", err)
	}
	if len(gotAuth) != 1 || gotAuth[0] != "" {
		t.Fatalf("expected empty Authorization header, got %v", gotAuth)
	}
}

type spyRuntime struct {
	nodes       []types.Node
	applyCalls  int
	lastApplied types.DesiredState
}

func (s *spyRuntime) Inventory() ([]types.Node, error) {
	return s.nodes, nil
}

func (s *spyRuntime) Apply(desired types.DesiredState) (map[string][]string, map[string][]string, error) {
	s.applyCalls++
	s.lastApplied = desired
	loaded := make(map[string][]string, len(s.nodes))
	for _, n := range s.nodes {
		loaded[n.ID] = append([]string(nil), desired.Nodes[n.ID]...)
	}
	return loaded, map[string][]string{}, nil
}

func (s *spyRuntime) Attest(nonce string, nodes []types.Node, loaded map[string][]string) ([]types.AttestResult, error) {
	return nil, nil
}

func TestResolveTreeVerifyConfig(t *testing.T) {
	sig, err := signer.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	validPub := sig.PublicKeyHex()

	tests := []struct {
		name        string
		runtimeKind string
		verifyEnv   string
		pubKeyHex   string
		wantPub     string
		wantWarn    bool
		wantErr     bool
	}{
		{
			name:        "shirudo default-on with pubkey",
			runtimeKind: "shirudo",
			verifyEnv:   "",
			pubKeyHex:   "  " + validPub + "  ",
			wantPub:     validPub,
		},
		{
			name:        "shirudo default-on without pubkey fails closed",
			runtimeKind: "shirudo",
			verifyEnv:   "",
			pubKeyHex:   "",
			wantErr:     true,
		},
		{
			name:        "stub default-off without pubkey",
			runtimeKind: "stub",
			verifyEnv:   "",
			pubKeyHex:   "",
			wantPub:     "",
		},
		{
			name:        "mock default-off without pubkey",
			runtimeKind: "mock",
			verifyEnv:   "",
			pubKeyHex:   "",
			wantPub:     "",
		},
		{
			name:        "explicit disable 0 on shirudo warns and returns disabled",
			runtimeKind: "shirudo",
			verifyEnv:   "0",
			pubKeyHex:   validPub,
			wantPub:     "",
			wantWarn:    true,
		},
		{
			name:        "explicit disable false on stub warns and returns disabled",
			runtimeKind: "stub",
			verifyEnv:   "false",
			pubKeyHex:   "",
			wantPub:     "",
			wantWarn:    true,
		},
		{
			name:        "explicit enable 1 on stub with pubkey",
			runtimeKind: "stub",
			verifyEnv:   "1",
			pubKeyHex:   validPub,
			wantPub:     validPub,
		},
		{
			name:        "explicit enable true on stub without pubkey fails closed",
			runtimeKind: "stub",
			verifyEnv:   "true",
			pubKeyHex:   "",
			wantErr:     true,
		},
		{
			name:        "malformed pubkey rejected",
			runtimeKind: "stub",
			verifyEnv:   "",
			pubKeyHex:   "not-valid-hex",
			wantErr:     true,
		},
		{
			name:        "invalid TREEWARD_VERIFY_TREE value rejected",
			runtimeKind: "shirudo",
			verifyEnv:   "maybe",
			pubKeyHex:   validPub,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPub, gotWarn, err := resolveTreeVerifyConfig(tc.runtimeKind, tc.verifyEnv, tc.pubKeyHex)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (pub=%q warn=%q)", gotPub, gotWarn)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPub != tc.wantPub {
				t.Fatalf("pub = %q, want %q", gotPub, tc.wantPub)
			}
			if tc.wantWarn && !strings.Contains(gotWarn, "WARNING") {
				t.Fatalf("expected WARNING in %q", gotWarn)
			}
			if !tc.wantWarn && gotWarn != "" {
				t.Fatalf("unexpected warning: %q", gotWarn)
			}
		})
	}
}

func TestVerifyAndResolveDesiredLifecycleAndIgnoresUnsignedNodes(t *testing.T) {
	sig, err := signer.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := sig.PublicKeyHex()
	st := store.New("enroll", "admin", sig)

	agentNodes := []types.Node{
		{
			ID:     "node-canary",
			Labels: map[string]string{types.LabelRollout: types.RolloutCanary, "tier": "web"},
		},
		{
			ID:     "node-prod",
			Labels: map[string]string{"tier": "web"},
		},
		{
			ID:     "node-other",
			Labels: map[string]string{"tier": "db"},
		},
	}
	st.UpsertInventory(agentNodes, "c1")

	// Empty tree (seq=0) succeeds when lastSeq=0 and ignores unsigned Nodes.
	emptyDesired := st.Desired()
	if emptyDesired.TreePubKey != pub {
		t.Fatalf("TreePubKey = %q, want %q", emptyDesired.TreePubKey, pub)
	}
	emptyDesired.Nodes = map[string][]string{"node-prod": {"sha256:evil-injected"}}
	resolved, seq, err := verifyAndResolveDesired(pub, 0, emptyDesired, agentNodes)
	if err != nil {
		t.Fatalf("empty tree verify failed: %v", err)
	}
	if seq != 0 {
		t.Fatalf("seq = %d, want 0", seq)
	}
	if len(resolved.Nodes["node-prod"]) != 0 {
		t.Fatalf("expected empty digests on empty tree, got %v", resolved.Nodes["node-prod"])
	}

	// Create artifact + binding -> approve -> canary (seq=1).
	art := st.CreateArtifact(types.Artifact{Name: "patch-1", Type: "bpf"})
	b, err := st.CreateBinding(types.Binding{
		ArtifactDigest: art.Digest,
		Selector:       types.Selector{Labels: map[string]string{"tier": "web"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Approve(b.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Canary(b.ID, "alice"); err != nil {
		t.Fatal(err)
	}

	// Round-trip through JSON to mirror connector HTTP transport, and poison desired.Nodes.
	desired := roundTripDesired(t, st.Desired())
	desired.Nodes = map[string][]string{
		"node-canary": {},
		"node-prod":   {"sha256:backdoor"},
		"node-other":  {"sha256:backdoor"},
	}

	rt := &spyRuntime{nodes: agentNodes}
	loaded, _, seq, err := applyDesiredState(rt, pub, seq, desired, agentNodes)
	if err != nil {
		t.Fatalf("canary applyDesiredState: %v", err)
	}
	if seq != 1 || rt.applyCalls != 1 {
		t.Fatalf("canary seq=%d applyCalls=%d, want 1, 1", seq, rt.applyCalls)
	}
	if !reflect.DeepEqual(loaded["node-canary"], []string{art.Digest}) {
		t.Fatalf("canary node-canary = %v, want [%s]", loaded["node-canary"], art.Digest)
	}
	if len(loaded["node-prod"]) != 0 || len(loaded["node-other"]) != 0 {
		t.Fatalf("canary should not apply to prod/other, got prod=%v other=%v", loaded["node-prod"], loaded["node-other"])
	}

	// Promote (seq=2): both canary and prod should get art.Digest, other stays empty.
	if _, err := st.Promote(b.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	desired = roundTripDesired(t, st.Desired())
	desired.Nodes = map[string][]string{"node-other": {"sha256:backdoor"}}
	loaded, _, seq, err = applyDesiredState(rt, pub, seq, desired, agentNodes)
	if err != nil {
		t.Fatalf("promote applyDesiredState: %v", err)
	}
	if seq != 2 || rt.applyCalls != 2 {
		t.Fatalf("promote seq=%d applyCalls=%d, want 2, 2", seq, rt.applyCalls)
	}
	if !reflect.DeepEqual(loaded["node-canary"], []string{art.Digest}) || !reflect.DeepEqual(loaded["node-prod"], []string{art.Digest}) {
		t.Fatalf("promote loaded = %v", loaded)
	}
	if len(loaded["node-other"]) != 0 {
		t.Fatalf("promote node-other = %v, want empty", loaded["node-other"])
	}

	// Revert (seq=3): all nodes unload art.Digest even if connector lies in desired.Nodes.
	if _, err := st.Revert(b.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	desired = roundTripDesired(t, st.Desired())
	desired.Nodes = map[string][]string{
		"node-canary": {art.Digest},
		"node-prod":   {art.Digest},
	}
	loaded, _, seq, err = applyDesiredState(rt, pub, seq, desired, agentNodes)
	if err != nil {
		t.Fatalf("revert applyDesiredState: %v", err)
	}
	if seq != 3 || rt.applyCalls != 3 {
		t.Fatalf("revert seq=%d applyCalls=%d, want 3, 3", seq, rt.applyCalls)
	}
	for _, n := range agentNodes {
		if len(loaded[n.ID]) != 0 {
			t.Fatalf("revert %s = %v, want empty", n.ID, loaded[n.ID])
		}
	}
}

func TestVerifyAndResolveDesiredRejectsTamperingAndSkipsApply(t *testing.T) {
	sig, err := signer.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	attackerSig, err := signer.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := sig.PublicKeyHex()

	st := store.New("enroll", "admin", sig)
	nodes := []types.Node{
		{ID: "n-canary", Labels: map[string]string{types.LabelRollout: types.RolloutCanary}},
		{ID: "n-prod", Labels: map[string]string{}},
	}
	st.UpsertInventory(nodes, "c1")

	art := st.CreateArtifact(types.Artifact{Name: "p1", Type: "bpf"})
	b, err := st.CreateBinding(types.Binding{ArtifactDigest: art.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Approve(b.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Canary(b.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Promote(b.ID, "op"); err != nil {
		t.Fatal(err)
	}

	validDesired := roundTripDesired(t, st.Desired())
	if validDesired.TreeSeq != 2 || len(validDesired.Ops) != 2 {
		t.Fatalf("unexpected fixture state: seq=%d len=%d", validDesired.TreeSeq, len(validDesired.Ops))
	}

	// Build a valid desired state signed by attackerSig to prove agent ignores desired.TreePubKey.
	attackerStore := store.New("enroll", "admin", attackerSig)
	attackerArt := attackerStore.CreateArtifact(types.Artifact{Name: "evil", Type: "bpf"})
	attackerBind, _ := attackerStore.CreateBinding(types.Binding{ArtifactDigest: attackerArt.Digest})
	_, _ = attackerStore.Approve(attackerBind.ID, "eve")
	_, _ = attackerStore.Canary(attackerBind.ID, "eve")
	attackerDesired := roundTripDesired(t, attackerStore.Desired())

	tests := []struct {
		name    string
		lastSeq int64
		build   func() types.DesiredState
	}{
		{
			name:    "tampered digest",
			lastSeq: 0,
			build: func() types.DesiredState {
				d := roundTripDesired(t, validDesired)
				d.Ops[1].Digest = "sha256:evil"
				return d
			},
		},
		{
			name:    "tampered selector",
			lastSeq: 0,
			build: func() types.DesiredState {
				d := roundTripDesired(t, validDesired)
				d.Ops[0].Selector = map[string]string{}
				return d
			},
		},
		{
			name:    "tampered timestamp",
			lastSeq: 0,
			build: func() types.DesiredState {
				d := roundTripDesired(t, validDesired)
				d.Ops[0].At = d.Ops[0].At.Add(time.Second)
				return d
			},
		},
		{
			name:    "reordered ops",
			lastSeq: 0,
			build: func() types.DesiredState {
				d := roundTripDesired(t, validDesired)
				d.Ops[0], d.Ops[1] = d.Ops[1], d.Ops[0]
				return d
			},
		},
		{
			name:    "truncated chain rollback",
			lastSeq: 2,
			build: func() types.DesiredState {
				d := roundTripDesired(t, validDesired)
				d.Ops = d.Ops[:1]
				d.TreeSeq = 1
				return d
			},
		},
		{
			name:    "rollback to empty tree",
			lastSeq: 2,
			build: func() types.DesiredState {
				return types.DesiredState{TreeSeq: 0, Ops: nil}
			},
		},
		{
			name:    "treeSeq mismatch with ops length",
			lastSeq: 0,
			build: func() types.DesiredState {
				d := roundTripDesired(t, validDesired)
				d.TreeSeq = 5
				return d
			},
		},
		{
			name:    "wrong pubkey even when server advertises attacker treePubKey",
			lastSeq: 0,
			build: func() types.DesiredState {
				return attackerDesired
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := &spyRuntime{nodes: nodes}
			d := tc.build()
			_, _, gotSeq, err := applyDesiredState(rt, pub, tc.lastSeq, d, nodes)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
			if rt.applyCalls != 0 {
				t.Fatalf("rt.Apply must NOT be called on failed verification (%q), got %d calls", tc.name, rt.applyCalls)
			}
			if gotSeq != tc.lastSeq {
				t.Fatalf("lastSeq mutated on failure: got %d, want %d", gotSeq, tc.lastSeq)
			}
		})
	}
}

func roundTripDesired(t *testing.T, d types.DesiredState) types.DesiredState {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal desired: %v", err)
	}
	var out types.DesiredState
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal desired: %v", err)
	}
	return out
}
