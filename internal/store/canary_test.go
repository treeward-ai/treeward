package store

import (
	"reflect"
	"testing"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

func TestCanarySelectionAndPromote(t *testing.T) {
	s := testStore(t)

	s.UpsertInventory([]types.Node{
		{
			ID:     "lab-canary",
			Labels: map[string]string{types.LabelRollout: types.RolloutCanary, "treeward.ai/runtime": "shirudo"},
		},
		{
			ID:     "lab-prod",
			Labels: map[string]string{"treeward.ai/runtime": "shirudo"},
		},
	}, "lab")

	art := s.CreateArtifact(types.Artifact{
		Name:   "vuln-app-shield",
		Digest: "vuln-app-shield",
		Type:   "bpf",
	})
	if art.Digest != "vuln-app-shield" {
		t.Fatalf("artifact digest = %q, want vuln-app-shield", art.Digest)
	}

	b, err := s.CreateBinding(types.Binding{ArtifactDigest: art.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b.ID, "damian"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Canary(b.ID, "damian"); err != nil {
		t.Fatal(err)
	}

	desired := s.Desired()
	if !reflect.DeepEqual(desired.Nodes["lab-canary"], []string{"vuln-app-shield"}) {
		t.Fatalf("canary desired for lab-canary = %v, want [vuln-app-shield]", desired.Nodes["lab-canary"])
	}
	if len(desired.Nodes["lab-prod"]) != 0 {
		t.Fatalf("canary desired for lab-prod = %v, want empty", desired.Nodes["lab-prod"])
	}

	if _, err := s.Promote(b.ID, "damian"); err != nil {
		t.Fatal(err)
	}
	desired = s.Desired()
	if !reflect.DeepEqual(desired.Nodes["lab-canary"], []string{"vuln-app-shield"}) {
		t.Fatalf("promoted desired for lab-canary = %v, want [vuln-app-shield]", desired.Nodes["lab-canary"])
	}
	if !reflect.DeepEqual(desired.Nodes["lab-prod"], []string{"vuln-app-shield"}) {
		t.Fatalf("promoted desired for lab-prod = %v, want [vuln-app-shield]", desired.Nodes["lab-prod"])
	}
	if desired.TreePubKey != s.Signer.PublicKeyHex() {
		t.Fatalf("desired.TreePubKey = %q, want %q", desired.TreePubKey, s.Signer.PublicKeyHex())
	}
	if err := signer.VerifyTreeChain(s.Signer.PublicKeyHex(), desired.Ops); err != nil {
		t.Fatalf("VerifyTreeChain failed on store ops: %v", err)
	}
	if desired.Ops[0].PrevHash != "" || desired.Ops[1].PrevHash == "" {
		t.Fatalf("unexpected PrevHash chaining: op0=%q op1=%q", desired.Ops[0].PrevHash, desired.Ops[1].PrevHash)
	}
}
