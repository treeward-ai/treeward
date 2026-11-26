package store

import (
	"testing"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	sig, err := signer.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New("test-enroll", "test-admin-bootstrap", sig)
}

func TestPauseOnLoadError(t *testing.T) {
	s := testStore(t)
	art := s.CreateArtifact(types.Artifact{Name: "x", Type: "java"})
	b, err := s.CreateBinding(types.Binding{ArtifactDigest: art.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b.ID, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Canary(b.ID, "t"); err != nil {
		t.Fatal(err)
	}

	canary := types.Node{
		ID:     "n-canary",
		Labels: map[string]string{types.LabelRollout: types.RolloutCanary},
	}
	s.ProcessAgentReports([]types.AgentReport{{
		Node:   canary,
		Loaded: nil,
		Errors: []string{"load error: " + art.Digest},
	}}, "c1")

	got, ok := s.GetBinding(b.ID)
	if !ok || got.Status != "paused" {
		t.Fatalf("want paused, got %#v ok=%v", got, ok)
	}
	if _, err := s.Promote(b.ID, "t"); err == nil {
		t.Fatal("promote should fail while paused")
	}
	found := false
	for _, e := range s.ListAudit() {
		if e.Action == "pause" && e.BindingID == b.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("missing pause audit event")
	}
}

func TestPauseOnCanaryAttestFail(t *testing.T) {
	s := testStore(t)
	art := s.CreateArtifact(types.Artifact{Name: "y", Type: "java"})
	b, err := s.CreateBinding(types.Binding{ArtifactDigest: art.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b.ID, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Canary(b.ID, "t"); err != nil {
		t.Fatal(err)
	}
	s.UpsertInventory([]types.Node{{
		ID:     "n-canary",
		Labels: map[string]string{types.LabelRollout: types.RolloutCanary},
	}}, "c1")

	camp := s.StartAttestCampaign()
	_, err = s.SubmitAttest(camp.ID, []types.AttestResult{{
		NodeID: "n-canary",
		Quote:  "stub:" + camp.Nonce + ":FAIL",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetBinding(b.ID)
	if got.Status != "paused" {
		t.Fatalf("want paused after canary attest fail, got %s", got.Status)
	}
}

func TestAttestFailNonCanaryDoesNotPause(t *testing.T) {
	s := testStore(t)
	art := s.CreateArtifact(types.Artifact{Name: "z", Type: "java"})
	b, err := s.CreateBinding(types.Binding{ArtifactDigest: art.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b.ID, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Canary(b.ID, "t"); err != nil {
		t.Fatal(err)
	}
	s.UpsertInventory([]types.Node{{
		ID:     "n-stable",
		Labels: map[string]string{"tier": "stable"},
	}}, "c1")

	camp := s.StartAttestCampaign()
	_, err = s.SubmitAttest(camp.ID, []types.AttestResult{{
		NodeID: "n-stable",
		Quote:  "stub:" + camp.Nonce + ":FAIL",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetBinding(b.ID)
	if got.Status != "canary" {
		t.Fatalf("stable-node attest fail should not pause canary binding, got %s", got.Status)
	}
}
