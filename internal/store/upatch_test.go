package store

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

func TestUpatchBytesSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	dbPath := filepath.Join(dir, "treeward.db")
	up := []byte("upatch-payload")
	un := []byte("unload-payload")
	const upSHA = "1111111111111111111111111111111111111111111111111111111111111111"

	st, err := Open(dbPath, "test-enroll", "test-admin", sig)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	art, err := st.CreateUpatchArtifactBy(types.Artifact{
		Name:         "persist-shield",
		Digest:       "persist-shield@sha256:" + upSHA,
		UpatchSHA256: upSHA,
	}, up, un, "test")
	if err != nil {
		t.Fatalf("CreateUpatchArtifactBy: %v", err)
	}
	if art.Type != "bpf" || art.ID == "" {
		t.Fatalf("artifact = %+v", art)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := Open(dbPath, "test-enroll", "test-admin", sig)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if got, ok := st2.UpatchBytes(upSHA, false); !ok || !bytes.Equal(got, up) {
		t.Fatalf("upatch after reopen: ok=%v got=%q", ok, got)
	}
	if got, ok := st2.UpatchBytes(upSHA, true); !ok || !bytes.Equal(got, un) {
		t.Fatalf("unload after reopen: ok=%v got=%q", ok, got)
	}
}
