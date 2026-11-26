package runtime

import (
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"

	"github.com/treeward-ai/treeward/internal/types"
)

// StubRuntime fakes three nodes derived from hostname, applies desired digests
// in memory, and emits fixture attestation quotes. Used by Kind / MVP.
type StubRuntime struct {
	nodes     []types.Node
	loaded    map[string]map[string]struct{}
	failNodes map[string]bool
	loadFail  bool // TREEWARD_LOAD_FAIL=1 → report load errors, skip loading
	mu        sync.Mutex
}

// NewStubFromEnv builds a StubRuntime from NODE_NAME/HOSTNAME,
// TREEWARD_ATTEST_FAIL, and TREEWARD_LOAD_FAIL.
func NewStubFromEnv() *StubRuntime {
	hostname := env("NODE_NAME", env("HOSTNAME", "stub-node"))
	failNodes := map[string]bool{}
	for _, id := range strings.Split(env("TREEWARD_ATTEST_FAIL", ""), ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			failNodes[id] = true
		}
	}
	s := NewStub(hostname, failNodes)
	s.loadFail = env("TREEWARD_LOAD_FAIL", "") == "1"
	return s
}

// NewStub constructs a StubRuntime with three fake nodes under hostname.
func NewStub(hostname string, failNodes map[string]bool) *StubRuntime {
	if failNodes == nil {
		failNodes = map[string]bool{}
	}
	nodes := buildStubNodes(hostname)
	loaded := map[string]map[string]struct{}{}
	for _, n := range nodes {
		loaded[n.ID] = map[string]struct{}{}
	}
	return &StubRuntime{
		nodes:     nodes,
		loaded:    loaded,
		failNodes: failNodes,
	}
}

func (s *StubRuntime) Inventory() ([]types.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.Node, len(s.nodes))
	for i, n := range s.nodes {
		out[i] = cloneNode(n)
		digests := make([]string, 0, len(s.loaded[n.ID]))
		for d := range s.loaded[n.ID] {
			digests = append(digests, d)
		}
		out[i].Loaded = digests
	}
	return out, nil
}

func (s *StubRuntime) Apply(desired types.DesiredState) (map[string][]string, map[string][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	loaded := map[string][]string{}
	errs := map[string][]string{}
	for _, n := range s.nodes {
		want := desired.Nodes[n.ID]
		set := map[string]struct{}{}
		var nodeErrs []string
		for _, d := range want {
			if s.loadFail {
				nodeErrs = append(nodeErrs, "load error: "+d)
				continue
			}
			set[d] = struct{}{}
		}
		s.loaded[n.ID] = set
		digests := make([]string, 0, len(set))
		for d := range set {
			digests = append(digests, d)
		}
		loaded[n.ID] = digests
		if len(nodeErrs) > 0 {
			errs[n.ID] = nodeErrs
		}
	}
	return loaded, errs, nil
}

func (s *StubRuntime) Attest(nonce string, nodes []types.Node, loaded map[string][]string) ([]types.AttestResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	quotes := make([]types.AttestResult, 0, len(nodes))
	for _, n := range nodes {
		digests := loaded[n.ID]
		if digests == nil {
			// Fall back to in-memory state if caller did not pass loaded.
			for d := range s.loaded[n.ID] {
				digests = append(digests, d)
			}
		}
		quote := fmt.Sprintf("stub-quote:nonce=%s:node=%s:loaded=%s", nonce, n.ID, strings.Join(digests, ","))
		if s.failNodes[n.ID] {
			quote += ":FAIL"
		}
		quotes = append(quotes, types.AttestResult{
			NodeID: n.ID,
			Nonce:  nonce,
			Quote:  quote,
		})
	}
	return quotes, nil
}

func buildStubNodes(hostname string) []types.Node {
	baseLabels := map[string]string{
		"kubernetes.io/hostname": hostname,
	}
	canary := copyMap(baseLabels)
	canary[types.LabelRollout] = types.RolloutCanary

	stable := copyMap(baseLabels)
	stable["tier"] = "stable"

	extra := copyMap(baseLabels)
	extra["tier"] = "stable"

	return []types.Node{
		{
			ID:       hostname + "-canary",
			Hostname: hostname + "-canary",
			Arch:     goruntime.GOARCH,
			Kernel:   "6.8.0-stub",
			Labels:   canary,
		},
		{
			ID:       hostname + "-n1",
			Hostname: hostname + "-n1",
			Arch:     goruntime.GOARCH,
			Kernel:   "6.8.0-stub",
			Labels:   stable,
		},
		{
			ID:       hostname + "-n2",
			Hostname: hostname + "-n2",
			Arch:     goruntime.GOARCH,
			Kernel:   "6.8.0-stub",
			Labels:   extra,
		},
	}
}

func cloneNode(n types.Node) types.Node {
	out := n
	out.Labels = copyMap(n.Labels)
	if n.Loaded != nil {
		out.Loaded = append([]string{}, n.Loaded...)
	}
	return out
}

func copyMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
