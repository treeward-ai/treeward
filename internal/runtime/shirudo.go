package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"

	"github.com/treeward-ai/treeward/internal/types"
)

// DefaultShirudoBin is the default path to the shirudo-runtime CLI.
const DefaultShirudoBin = "/usr/local/bin/shirudo-runtime"

// ShirudoStatus represents the JSON output of `shirudo-runtime status --json`.
type ShirudoStatus struct {
	Status         string   `json:"status"`
	UpatchesLoaded []string `json:"upatches_loaded"`
	TPM            any      `json:"tpm,omitempty"`
	Kernel         string   `json:"kernel,omitempty"`
	Arch           string   `json:"arch,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
}

func (s *ShirudoStatus) UnmarshalJSON(data []byte) error {
	type rawStatus struct {
		Status         string          `json:"status"`
		UpatchesLoaded json.RawMessage `json:"upatches_loaded"`
		TPM            any             `json:"tpm,omitempty"`
		Kernel         string          `json:"kernel,omitempty"`
		Arch           string          `json:"arch,omitempty"`
		Hostname       string          `json:"hostname,omitempty"`
	}
	var raw rawStatus
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.Status = raw.Status
	s.TPM = raw.TPM
	s.Kernel = raw.Kernel
	s.Arch = raw.Arch
	s.Hostname = raw.Hostname
	s.UpatchesLoaded = nil
	if len(raw.UpatchesLoaded) == 0 || string(raw.UpatchesLoaded) == "null" {
		return nil
	}
	var names []string
	if err := json.Unmarshal(raw.UpatchesLoaded, &names); err == nil {
		s.UpatchesLoaded = names
		return nil
	}
	var objs []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw.UpatchesLoaded, &objs); err != nil {
		return err
	}
	s.UpatchesLoaded = make([]string, 0, len(objs))
	for _, o := range objs {
		if o.Name != "" {
			s.UpatchesLoaded = append(s.UpatchesLoaded, o.Name)
		}
	}
	return nil
}

// ShirudoOption configures a ShirudoRuntime instance.
type ShirudoOption func(*ShirudoRuntime)

// WithShirudoBin overrides the path to the shirudo-runtime binary.
func WithShirudoBin(bin string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		if bin != "" {
			s.bin = bin
		}
	}
}

// WithNodeID overrides the node ID reported by Inventory and matched in Apply.
func WithNodeID(id string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		if id != "" {
			s.nodeID = id
		}
	}
}

// WithHostname overrides the hostname reported by Inventory.
func WithHostname(hostname string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		if hostname != "" {
			s.hostname = hostname
		}
	}
}

// WithUpatchDir sets a base directory prepended to relative upatch paths on load.
func WithUpatchDir(dir string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.upatchDir = dir
	}
}

// ShirudoRuntime implements Runtime by shelling out to the shirudo-runtime CLI.
type ShirudoRuntime struct {
	bin       string
	nodeID    string
	hostname  string
	upatchDir string
}

// NewShirudo constructs a ShirudoRuntime configured from environment variables
// (SHIRUDO_RUNTIME_BIN, NODE_NAME/HOSTNAME, SHIRUDO_UPATCH_DIR) and optional overrides.
func NewShirudo(opts ...ShirudoOption) *ShirudoRuntime {
	host, _ := os.Hostname()
	hostname := env("NODE_NAME", env("HOSTNAME", host))
	if hostname == "" {
		hostname = "shirudo-node"
	}

	s := &ShirudoRuntime{
		bin:       env("SHIRUDO_RUNTIME_BIN", DefaultShirudoBin),
		nodeID:    hostname,
		hostname:  hostname,
		upatchDir: env("SHIRUDO_UPATCH_DIR", ""),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Status invokes `shirudo-runtime status --json` and parses the response.
func (s *ShirudoRuntime) Status() (ShirudoStatus, error) {
	out, err := s.run("status", "--json")
	if err != nil {
		return ShirudoStatus{}, fmt.Errorf("shirudo status: %w", err)
	}
	var st ShirudoStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return ShirudoStatus{}, fmt.Errorf("shirudo status: decode json: %w", err)
	}
	return st, nil
}

// LoadUpatch invokes `shirudo-runtime upatch load <path>`.
func (s *ShirudoRuntime) LoadUpatch(path string) error {
	if _, err := s.run("upatch", "load", path); err != nil {
		return fmt.Errorf("shirudo upatch load %q: %w", path, err)
	}
	return nil
}

// UnloadUpatch invokes `shirudo-runtime upatch unload <name>`.
func (s *ShirudoRuntime) UnloadUpatch(name string) error {
	if _, err := s.run("upatch", "unload", name); err != nil {
		return fmt.Errorf("shirudo upatch unload %q: %w", name, err)
	}
	return nil
}

// AttestRaw invokes `shirudo-runtime attest --nonce <hex>` and returns the raw JSON document.
func (s *ShirudoRuntime) AttestRaw(nonce string) (string, error) {
	out, err := s.run("attest", "--nonce", nonce)
	if err != nil {
		return "", fmt.Errorf("shirudo attest: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *ShirudoRuntime) Inventory() ([]types.Node, error) {
	st, err := s.Status()
	if err != nil {
		return nil, err
	}

	hostname := s.hostname
	if st.Hostname != "" {
		hostname = st.Hostname
	}
	nodeID := s.nodeID
	if nodeID == "" {
		nodeID = hostname
	}
	arch := st.Arch
	if arch == "" {
		arch = goruntime.GOARCH
	}
	kernel := st.Kernel
	if kernel == "" {
		kernel = readKernelRelease()
	}

	labels := map[string]string{
		"kubernetes.io/hostname": hostname,
		"treeward.ai/runtime":    "shirudo",
	}
	if st.Status != "" {
		labels["shirudo.io/status"] = st.Status
	}

	loaded := make([]string, len(st.UpatchesLoaded))
	copy(loaded, st.UpatchesLoaded)

	return []types.Node{
		{
			ID:       nodeID,
			Hostname: hostname,
			Arch:     arch,
			Kernel:   kernel,
			Labels:   labels,
			Loaded:   loaded,
		},
	}, nil
}

func (s *ShirudoRuntime) Apply(desired types.DesiredState) (map[string][]string, map[string][]string, error) {
	st, err := s.Status()
	if err != nil {
		return nil, nil, err
	}

	currentSet := make(map[string]struct{}, len(st.UpatchesLoaded))
	for _, name := range st.UpatchesLoaded {
		currentSet[name] = struct{}{}
	}

	want := desired.Nodes[s.nodeID]
	wantSet := make(map[string]struct{}, len(want))
	for _, d := range want {
		wantSet[d] = struct{}{}
	}

	var nodeErrs []string

	// Load desired upatches that are not yet loaded.
	for _, d := range want {
		if _, ok := currentSet[d]; ok {
			continue
		}
		path := d
		if s.upatchDir != "" && !filepath.IsAbs(d) {
			path = filepath.Join(s.upatchDir, d)
		}
		if err := s.LoadUpatch(path); err != nil {
			nodeErrs = append(nodeErrs, err.Error())
			continue
		}
		currentSet[d] = struct{}{}
	}

	// Unload currently loaded upatches that are no longer desired.
	for _, cur := range st.UpatchesLoaded {
		if _, ok := wantSet[cur]; ok {
			continue
		}
		if err := s.UnloadUpatch(cur); err != nil {
			nodeErrs = append(nodeErrs, err.Error())
			continue
		}
		delete(currentSet, cur)
	}

	loadedSlice := make([]string, 0, len(currentSet))
	for d := range currentSet {
		loadedSlice = append(loadedSlice, d)
	}
	sort.Strings(loadedSlice)

	loaded := map[string][]string{
		s.nodeID: loadedSlice,
	}
	errs := map[string][]string{}
	if len(nodeErrs) > 0 {
		errs[s.nodeID] = nodeErrs
	}
	return loaded, errs, nil
}

func (s *ShirudoRuntime) Attest(nonce string, nodes []types.Node, loaded map[string][]string) ([]types.AttestResult, error) {
	_ = loaded
	raw, err := s.AttestRaw(nonce)
	if err != nil {
		return nil, err
	}

	targets := nodes
	if len(targets) == 0 {
		targets = []types.Node{{ID: s.nodeID}}
	}

	results := make([]types.AttestResult, 0, len(targets))
	for _, n := range targets {
		results = append(results, types.AttestResult{
			NodeID: n.ID,
			Nonce:  nonce,
			Quote:  raw,
		})
	}
	return results, nil
}

func (s *ShirudoRuntime) run(args ...string) ([]byte, error) {
	cmd := exec.Command(s.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func readKernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	if s := strings.TrimSpace(string(b)); s != "" {
		return s
	}
	return "unknown"
}
