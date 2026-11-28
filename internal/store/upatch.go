package store

import (
	"errors"

	"github.com/treeward-ai/treeward/internal/types"
)

// upatchBlob holds the signed bytes for one registered bpf artifact. It is
// keyed by the sha256 of Upatch, which is what agents request from the connector
// (GET /v1/upatches/{sha}) and what the desired-state digest "<name>@sha256:<sha>" carries.
type upatchBlob struct {
	Upatch []byte `json:"upatch"`
	Unload []byte `json:"unload"`
}

// ErrDuplicateArtifact is returned when an artifact with the same digest or upatch bytes already exists.
var ErrDuplicateArtifact = errors.New("artifact already registered")

// CreateUpatchArtifactBy registers a bpf artifact together with the signed upatch
// and its unload directive. The caller computes a.Digest, a.UpatchSHA256 and
// a.UnloadSHA256 from the bytes; the store only checks uniqueness and records them.
func (s *Store) CreateUpatchArtifactBy(a types.Artifact, upatch, unload []byte, actor string) (types.Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Upatches[a.UpatchSHA256]; ok {
		return types.Artifact{}, ErrDuplicateArtifact
	}
	for _, existing := range s.Artifacts {
		if existing.Digest == a.Digest {
			return types.Artifact{}, ErrDuplicateArtifact
		}
	}
	if actor == "" {
		actor = "api"
	}
	a.ID = id("art")
	a.Type = "bpf"
	cp := a
	s.Artifacts[a.ID] = &cp
	s.Upatches[a.UpatchSHA256] = &upatchBlob{Upatch: upatch, Unload: unload}
	s.auditLocked("artifact.create", actor, "", a.Digest, a.Name)
	s.persistLocked()
	return a, nil
}

// UpatchBytes returns the signed upatch registered under the given file sha256,
// or its unload directive when unload is true.
func (s *Store) UpatchBytes(sha string, unload bool) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.Upatches[sha]
	if !ok {
		return nil, false
	}
	if unload {
		return blob.Unload, len(blob.Unload) > 0
	}
	return blob.Upatch, len(blob.Upatch) > 0
}
