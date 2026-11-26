package runtime

import (
	"log"

	"github.com/treeward-ai/treeward/internal/types"
)

// ShirudoRuntime is a skeleton for a real Linux lab VM backend.
//
// Intended future wiring (not implemented):
//   - Inventory: probe host / Shirudo node identity (hostname, arch, kernel, labels).
//   - Apply:     `bpm tree sync` (or equivalent) then `upatch load` / unload per digest
//                to match DesiredState.Nodes for this host.
//   - Attest:    invoke Shirudo `attest` CLI with the campaign nonce and currently
//                loaded digests; return hardware/TPM-backed quotes.
//
// Select with TREEWARD_RUNTIME=shirudo. Until wired, every method returns
// ErrNotImplemented so the agent loop can surface a clear failure.
type ShirudoRuntime struct{}

// NewShirudo returns an unimplemented Shirudo-backed Runtime.
func NewShirudo() *ShirudoRuntime {
	return &ShirudoRuntime{}
}

func (s *ShirudoRuntime) Inventory() ([]types.Node, error) {
	// Future: discover local node inventory via Shirudo / OS probes.
	log.Printf("shirudo runtime: Inventory not implemented (would probe host + Shirudo identity)")
	return nil, ErrNotImplemented
}

func (s *ShirudoRuntime) Apply(desired types.DesiredState) (map[string][]string, map[string][]string, error) {
	// Future: bpm tree sync → upatch load/unload to match desired digests.
	_ = desired
	log.Printf("shirudo runtime: Apply not implemented (would run bpm tree sync / upatch load)")
	return nil, nil, ErrNotImplemented
}

func (s *ShirudoRuntime) Attest(nonce string, nodes []types.Node, loaded map[string][]string) ([]types.AttestResult, error) {
	// Future: shirudo attest CLI with nonce + loaded digests → real quotes.
	_, _, _ = nonce, nodes, loaded
	log.Printf("shirudo runtime: Attest not implemented (would call attest CLI)")
	return nil, ErrNotImplemented
}
