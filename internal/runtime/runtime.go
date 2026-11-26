// Package runtime abstracts how the node agent discovers inventory, applies
// desired digests, and produces attestation quotes.
//
// Kind / MVP uses StubRuntime (in-memory fixtures). A Linux lab VM can later
// select ShirudoRuntime via TREEWARD_RUNTIME=shirudo without changing the
// agent poll/report loop.
package runtime

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/treeward-ai/treeward/internal/types"
)

// ErrNotImplemented is returned by skeleton runtimes that are not yet wired.
var ErrNotImplemented = errors.New("runtime: not implemented")

// Runtime is the pluggable backend for inventory, apply, and attest.
type Runtime interface {
	// Inventory returns the nodes this agent manages.
	Inventory() ([]types.Node, error)

	// Apply reconciles local load state toward desired.
	// loaded maps node ID → digests currently loaded;
	// errs maps node ID → human-readable apply errors (empty on success).
	Apply(desired types.DesiredState) (loaded map[string][]string, errs map[string][]string, err error)

	// Attest produces quotes for the given nonce over the supplied nodes/loaded digests.
	Attest(nonce string, nodes []types.Node, loaded map[string][]string) ([]types.AttestResult, error)
}

// NewFromEnv selects a Runtime from TREEWARD_RUNTIME (stub|shirudo; default stub).
func NewFromEnv() (Runtime, error) {
	switch strings.ToLower(strings.TrimSpace(env("TREEWARD_RUNTIME", "stub"))) {
	case "stub", "":
		return NewStubFromEnv(), nil
	case "shirudo":
		return NewShirudo(), nil
	default:
		return nil, fmt.Errorf("unknown TREEWARD_RUNTIME %q (want stub|shirudo)", os.Getenv("TREEWARD_RUNTIME"))
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
