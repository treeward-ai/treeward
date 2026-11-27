package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

var (
	upatchNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hexNonceRe   = regexp.MustCompile(`^[0-9a-fA-F]{16,128}$`)
	sha256HexRe  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// DefaultShirudoBin is the default path to the shirudo-runtime CLI.
const DefaultShirudoBin = "/usr/local/bin/shirudo-runtime"

// DefaultShirudoStateDir is the default directory for persisting Treeward-owned upatch state.
const DefaultShirudoStateDir = "/var/lib/treeward-agent"

const (
	ownedStateFilename     = "owned.json"
	upatchFileSuffix       = ".upatch"
	unloadDirectiveSuffix  = ".unload.upatch"
	defaultDownloadTimeout = 60 * time.Second
	maxUpatchDownloadBytes = 16 << 20 // 16 MiB
)

// UpatchSpec is a parsed desired upatch entry of the form "<name>@sha256:<64-hex>".
type UpatchSpec struct {
	Name   string
	SHA256 string // lowercase 64-hex
}

// ParseDesiredUpatch parses a desired upatch entry of the form "<name>@sha256:<64-hex>".
// Legacy plain digests (without '@') and malformed entries are rejected.
func ParseDesiredUpatch(entry string) (UpatchSpec, error) {
	idx := strings.IndexByte(entry, '@')
	if idx < 0 {
		return UpatchSpec{}, fmt.Errorf("invalid desired upatch %q: expected <name>@sha256:<64-hex>", entry)
	}
	name := entry[:idx]
	rest := entry[idx+1:]
	if err := validateUpatchName(name); err != nil {
		return UpatchSpec{}, fmt.Errorf("invalid desired upatch %q: %w", entry, err)
	}
	if !strings.HasPrefix(rest, "sha256:") {
		return UpatchSpec{}, fmt.Errorf("invalid desired upatch %q: missing sha256: prefix", entry)
	}
	digest := strings.TrimPrefix(rest, "sha256:")
	if !sha256HexRe.MatchString(digest) {
		return UpatchSpec{}, fmt.Errorf("invalid desired upatch %q: sha256 must be 64 hex chars", entry)
	}
	return UpatchSpec{
		Name:   name,
		SHA256: strings.ToLower(digest),
	}, nil
}

// ShirudoAssets represents the assets section of `shirudo-runtime status --json`.
type ShirudoAssets struct {
	Root     string `json:"root,omitempty"`
	Eventlog bool   `json:"eventlog,omitempty"`
}

// ShirudoStatus represents the JSON output of `shirudo-runtime status --json`.
type ShirudoStatus struct {
	Status         string         `json:"status"`
	UpatchesLoaded []string       `json:"upatches_loaded"`
	TPM            any            `json:"tpm,omitempty"`
	Assets         *ShirudoAssets `json:"assets,omitempty"`
	Kernel         string         `json:"kernel,omitempty"`
	Arch           string         `json:"arch,omitempty"`
	Hostname       string         `json:"hostname,omitempty"`
}

func (s *ShirudoStatus) UnmarshalJSON(data []byte) error {
	type rawStatus struct {
		Status         string          `json:"status"`
		UpatchesLoaded json.RawMessage `json:"upatches_loaded"`
		TPM            any             `json:"tpm,omitempty"`
		Assets         *ShirudoAssets  `json:"assets,omitempty"`
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
	s.Assets = raw.Assets
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

// WithUpatchDir sets a base directory prepended to relative upatch paths on load
// and used to resolve signed unload directives (<upatchDir>/<name>.unload.upatch).
func WithUpatchDir(dir string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.upatchDir = dir
	}
}

// WithStateDir sets the directory used to persist Treeward-owned upatch state (owned.json).
func WithStateDir(dir string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.stateDir = dir
	}
}

// WithRollout sets the treeward.ai/rollout label value (e.g. "canary") reported by Inventory.
func WithRollout(rollout string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.rollout = strings.TrimSpace(rollout)
	}
}

// WithConnectorURL sets the base URL used to download upatch payloads and unload directives.
func WithConnectorURL(url string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.connectorURL = strings.TrimRight(strings.TrimSpace(url), "/")
	}
}

// WithLocalToken sets the bearer token used when authenticating to the connector.
func WithLocalToken(token string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.localToken = token
	}
}

// WithHTTPClient overrides the HTTP client used for upatch downloads.
func WithHTTPClient(client *http.Client) ShirudoOption {
	return func(s *ShirudoRuntime) {
		if client != nil {
			s.httpClient = client
		}
	}
}

// WithEventlogPath overrides the path to the Shirudo TPM eventlog file used to
// detect the NV writer key size (RSA-3072 vs RSA-2048 fallback).
func WithEventlogPath(path string) ShirudoOption {
	return func(s *ShirudoRuntime) {
		s.eventlogPath = strings.TrimSpace(path)
	}
}

// ShirudoRuntime implements Runtime by shelling out to the shirudo-runtime CLI.
//
// Revert / unload convention: the operator builds a signed UNLOAD directive
// alongside each upatch artifact at <upatchDir>/<name>.unload.upatch. Treeward
// never holds the operator signing key; UnloadUpatch passes that directive path
// to `shirudo-runtime upatch unload <path>`.
//
// Ownership: Apply tracks upatches that appeared in a Treeward desired set in
// <stateDir>/owned.json (SHIRUDO_STATE_DIR, default /var/lib/treeward-agent)
// as a JSON object mapping upatch name -> payload sha256.
// Externally loaded upatches not present in owned.json are never unloaded.
type ShirudoRuntime struct {
	bin            string
	nodeID         string
	hostname       string
	upatchDir      string
	stateDir       string
	eventlogPath   string
	rollout        string
	connectorURL   string
	localToken     string
	httpClient     *http.Client
	ownedLoaded    bool
	owned          map[string]string
	loggedExternal map[string]bool
}

func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// NewShirudo constructs a ShirudoRuntime configured from environment variables
// (SHIRUDO_RUNTIME_BIN, NODE_NAME/HOSTNAME, SHIRUDO_UPATCH_DIR, SHIRUDO_STATE_DIR,
// SHIRUDO_EVENTLOG_PATH, TREEWARD_ROLLOUT, TREEWARD_CONNECTOR_URL, TREEWARD_LOCAL_TOKEN)
// and optional overrides.
func NewShirudo(opts ...ShirudoOption) *ShirudoRuntime {
	host, _ := os.Hostname()
	hostname := env("NODE_NAME", env("HOSTNAME", host))
	if hostname == "" {
		hostname = "shirudo-node"
	}

	s := &ShirudoRuntime{
		bin:            env("SHIRUDO_RUNTIME_BIN", DefaultShirudoBin),
		nodeID:         hostname,
		hostname:       hostname,
		upatchDir:      env("SHIRUDO_UPATCH_DIR", ""),
		stateDir:       env("SHIRUDO_STATE_DIR", DefaultShirudoStateDir),
		eventlogPath:   strings.TrimSpace(os.Getenv("SHIRUDO_EVENTLOG_PATH")),
		rollout:        strings.TrimSpace(os.Getenv("TREEWARD_ROLLOUT")),
		connectorURL:   strings.TrimRight(strings.TrimSpace(os.Getenv("TREEWARD_CONNECTOR_URL")), "/"),
		localToken:     os.Getenv("TREEWARD_LOCAL_TOKEN"),
		httpClient:     &http.Client{Timeout: defaultDownloadTimeout, CheckRedirect: noRedirect},
		owned:          map[string]string{},
		loggedExternal: map[string]bool{},
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

func validateUpatchName(name string) error {
	if name == "" {
		return fmt.Errorf("invalid upatch name: empty")
	}
	if strings.HasPrefix(name, "-") || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) || !upatchNameRe.MatchString(name) {
		return fmt.Errorf("invalid upatch name %q", name)
	}
	return nil
}

func validateUpatchPath(path string) error {
	if path == "" {
		return fmt.Errorf("invalid upatch path: empty")
	}
	if strings.HasPrefix(path, "-") {
		return fmt.Errorf("invalid upatch path %q: leading dash not allowed", path)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("invalid upatch path %q: null byte not allowed", path)
	}
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return fmt.Errorf("invalid upatch path %q: parent traversal not allowed", path)
		}
	}
	return nil
}

func resolvePathWithinBase(baseDir, filename string) (string, error) {
	cleanBase := filepath.Clean(baseDir)
	joined := filepath.Join(cleanBase, filename)
	rel, err := filepath.Rel(cleanBase, joined)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("resolved path %q escapes upatch dir %q", joined, cleanBase)
	}
	return joined, nil
}

func (s *ShirudoRuntime) resolveUpatchPath(name string) (string, error) {
	if err := validateUpatchName(name); err != nil {
		return "", err
	}
	filename := name + upatchFileSuffix
	if s.upatchDir == "" {
		return filename, nil
	}
	return resolvePathWithinBase(s.upatchDir, filename)
}

func (s *ShirudoRuntime) resolveUnloadDirectivePath(name string) (string, error) {
	if err := validateUpatchName(name); err != nil {
		return "", err
	}
	filename := name + unloadDirectiveSuffix
	if s.upatchDir == "" {
		return filename, nil
	}
	return resolvePathWithinBase(s.upatchDir, filename)
}

// LoadUpatch invokes `shirudo-runtime upatch load <path>`.
func (s *ShirudoRuntime) LoadUpatch(path string) error {
	if err := validateUpatchPath(path); err != nil {
		return fmt.Errorf("shirudo upatch load %q: %w", path, err)
	}
	if _, err := s.run("upatch", "load", path); err != nil {
		return fmt.Errorf("shirudo upatch load %q: %w", path, err)
	}
	return nil
}

// UnloadDirectivePath returns the convention path for a signed UNLOAD directive:
// <upatchDir>/<name>.unload.upatch.
func (s *ShirudoRuntime) UnloadDirectivePath(name string) string {
	return filepath.Join(s.upatchDir, name+unloadDirectiveSuffix)
}

// UnloadUpatch invokes `shirudo-runtime upatch unload <path>` using the signed
// unload directive at <upatchDir>/<name>.unload.upatch. If the directive file
// is absent, it logs a clear error and does not invoke shirudo-runtime.
func (s *ShirudoRuntime) UnloadUpatch(name string) error {
	directivePath, err := s.resolveUnloadDirectivePath(name)
	if err != nil {
		return fmt.Errorf("shirudo upatch unload %q: %w", name, err)
	}
	if _, err := os.Stat(directivePath); err != nil {
		log.Printf("shirudo: cannot unload %q: unload directive %q unavailable: %v", name, directivePath, err)
		return fmt.Errorf("shirudo upatch unload %q: missing unload directive %q: %w", name, directivePath, err)
	}
	if _, err := s.run("upatch", "unload", directivePath); err != nil {
		return fmt.Errorf("shirudo upatch unload %q (%q): %w", name, directivePath, err)
	}
	return nil
}

// AttestRaw invokes `shirudo-runtime attest --nonce <hex>` and returns the raw JSON document.
func (s *ShirudoRuntime) AttestRaw(nonce string) (string, error) {
	if !hexNonceRe.MatchString(nonce) {
		return "", fmt.Errorf("shirudo attest: invalid hex nonce %q", nonce)
	}
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
	if s.rollout != "" {
		labels[types.LabelRollout] = s.rollout
	}
	if nvWriter := s.detectTPMNvWriter(st); nvWriter != "" {
		labels[types.LabelTPMNvWriter] = nvWriter
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

	s.loadOwned()
	ownedDirty := false

	currentSet := make(map[string]struct{}, len(st.UpatchesLoaded))
	for _, name := range st.UpatchesLoaded {
		currentSet[name] = struct{}{}
	}

	want := desired.Nodes[s.nodeID]
	wantSet := make(map[string]struct{}, len(want))
	specs := make([]UpatchSpec, 0, len(want))
	var nodeErrs []string

	for _, d := range want {
		spec, err := ParseDesiredUpatch(d)
		if err != nil {
			nodeErrs = append(nodeErrs, fmt.Sprintf("shirudo upatch load %q: %v", d, err))
			continue
		}
		wantSet[spec.Name] = struct{}{}
		specs = append(specs, spec)
		if prevSHA, ok := s.owned[spec.Name]; !ok || prevSHA != spec.SHA256 {
			s.owned[spec.Name] = spec.SHA256
			ownedDirty = true
		}
	}

	// Load desired upatches that are not yet loaded.
	for _, spec := range specs {
		if _, ok := currentSet[spec.Name]; ok {
			continue
		}
		path, err := s.resolveUpatchPath(spec.Name)
		if err != nil {
			nodeErrs = append(nodeErrs, fmt.Sprintf("shirudo upatch load %q: %v", spec.Name, err))
			continue
		}
		if err := s.ensureUpatchFile(path, spec.SHA256); err != nil {
			nodeErrs = append(nodeErrs, fmt.Sprintf("shirudo upatch load %q: %v", spec.Name, err))
			continue
		}
		if err := s.LoadUpatch(path); err != nil {
			nodeErrs = append(nodeErrs, err.Error())
			continue
		}
		currentSet[spec.Name] = struct{}{}
	}

	// Unload currently loaded upatches that are owned by Treeward and no longer desired.
	for _, cur := range st.UpatchesLoaded {
		if _, ok := wantSet[cur]; ok {
			continue
		}
		recordedSHA, isOwned := s.owned[cur]
		if !isOwned {
			if !s.loggedExternal[cur] {
				log.Printf("shirudo: skipping externally loaded upatch %q (not managed by treeward)", cur)
				s.loggedExternal[cur] = true
			}
			continue
		}
		directivePath, err := s.resolveUnloadDirectivePath(cur)
		if err != nil {
			nodeErrs = append(nodeErrs, fmt.Sprintf("shirudo upatch unload %q: %v", cur, err))
			continue
		}
		if err := s.ensureUnloadDirectiveFile(directivePath, cur, recordedSHA); err != nil {
			nodeErrs = append(nodeErrs, err.Error())
			continue
		}
		if err := s.UnloadUpatch(cur); err != nil {
			nodeErrs = append(nodeErrs, err.Error())
			continue
		}
		delete(currentSet, cur)
		delete(s.owned, cur)
		ownedDirty = true
	}

	if ownedDirty {
		s.saveOwned()
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *ShirudoRuntime) ensureUpatchFile(destPath, expectedSHA string) error {
	if got, err := fileSHA256(destPath); err == nil && got == expectedSHA {
		return nil
	}
	if s.connectorURL == "" {
		return fmt.Errorf("upatch file %q missing or sha256 mismatch and connector URL is not configured", destPath)
	}
	url := fmt.Sprintf("%s/v1/upatches/%s", s.connectorURL, expectedSHA)
	return s.downloadAndVerify(url, destPath, expectedSHA, false)
}

func (s *ShirudoRuntime) ensureUnloadDirectiveFile(directivePath, name, recordedSHA string) error {
	if _, err := os.Stat(directivePath); err == nil {
		return nil
	}
	if recordedSHA == "" {
		return fmt.Errorf("shirudo upatch unload %q: missing unload directive %q and no recorded sha256 in owned state", name, directivePath)
	}
	if s.connectorURL == "" {
		return fmt.Errorf("shirudo upatch unload %q: missing unload directive %q and connector URL is not configured", name, directivePath)
	}
	url := fmt.Sprintf("%s/v1/upatches/%s/unload", s.connectorURL, recordedSHA)
	if err := s.downloadAndVerify(url, directivePath, recordedSHA, true); err != nil {
		return fmt.Errorf("shirudo upatch unload %q: %w", name, err)
	}
	return nil
}

// downloadAndVerify fetches url with bearer auth, enforces maxUpatchDownloadBytes,
// writes to a temp file in filepath.Dir(destPath), verifies sha256, chmods 0644,
// and renames into destPath. If preferHeaderSHA is true and the server returns a
// non-empty x-upatch-sha256 header, the response is verified against that header;
// otherwise it is verified against fallbackSHA.
func (s *ShirudoRuntime) downloadAndVerify(url, destPath, fallbackSHA string, preferHeaderSHA bool) error {
	client := s.httpClient
	if client == nil {
		client = &http.Client{Timeout: defaultDownloadTimeout, CheckRedirect: noRedirect}
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if s.localToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.localToken)
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return fmt.Errorf("download %s: HTTP %d: %s", url, res.StatusCode, strings.TrimSpace(string(body)))
	}

	expectedSHA := strings.ToLower(strings.TrimSpace(fallbackSHA))
	if preferHeaderSHA {
		if hdr := strings.TrimSpace(res.Header.Get("x-upatch-sha256")); hdr != "" {
			if !sha256HexRe.MatchString(hdr) {
				return fmt.Errorf("download %s: invalid x-upatch-sha256 header %q", url, hdr)
			}
			expectedSHA = strings.ToLower(hdr)
		}
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create upatch dir %q: %w", dir, err)
	}
	tmpFile, err := os.CreateTemp(dir, ".upatch-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmpFile, h), io.LimitReader(res.Body, maxUpatchDownloadBytes+1))
	if err != nil {
		cleanup()
		return fmt.Errorf("download %s: read body: %w", url, err)
	}
	if n > maxUpatchDownloadBytes {
		cleanup()
		return fmt.Errorf("download %s: response exceeds maximum size of %d bytes", url, maxUpatchDownloadBytes)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file %q: %w", tmpPath, err)
	}

	actualSHA := hex.EncodeToString(h.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download %s: sha256 mismatch: got %s, want %s", url, actualSHA, expectedSHA)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %q -> %q: %w", tmpPath, destPath, err)
	}
	return nil
}

func (s *ShirudoRuntime) ownedStatePath() string {
	return filepath.Join(s.stateDir, ownedStateFilename)
}

func (s *ShirudoRuntime) loadOwned() {
	if s.ownedLoaded {
		return
	}
	s.ownedLoaded = true
	if s.owned == nil {
		s.owned = map[string]string{}
	}
	if s.loggedExternal == nil {
		s.loggedExternal = map[string]bool{}
	}
	if s.stateDir == "" {
		return
	}
	data, err := os.ReadFile(s.ownedStatePath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("shirudo: read owned state %q: %v", s.ownedStatePath(), err)
		}
		return
	}
	var obj map[string]string
	if err := json.Unmarshal(data, &obj); err == nil && obj != nil {
		for name, sha := range obj {
			if name != "" {
				s.owned[name] = sha
			}
		}
		return
	}
	// Transparent migration from legacy JSON string-list format.
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		log.Printf("shirudo: decode owned state %q: %v", s.ownedStatePath(), err)
		return
	}
	for _, name := range names {
		if name != "" {
			s.owned[name] = ""
		}
	}
}

func (s *ShirudoRuntime) saveOwned() {
	if s.stateDir == "" {
		return
	}
	if err := os.MkdirAll(s.stateDir, 0o700); err != nil {
		log.Printf("shirudo: create state dir %q: %v", s.stateDir, err)
		return
	}
	out := make(map[string]string, len(s.owned))
	for name, sha := range s.owned {
		if name != "" {
			out[name] = sha
		}
	}
	data, err := json.Marshal(out)
	if err != nil {
		log.Printf("shirudo: encode owned state: %v", err)
		return
	}
	path := s.ownedStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("shirudo: write owned state %q: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("shirudo: rename owned state %q -> %q: %v", tmp, path, err)
	}
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

func readBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// classifyNVWriterPublicHex classifies a hex-encoded RSA NV writer public modulus.
// 256 bytes (512 hex chars) -> rsa2048-fallback; 384 bytes (768 hex chars) -> rsa3072.
func classifyNVWriterPublicHex(hexStr string) string {
	s := strings.TrimSpace(hexStr)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return ""
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	return classifyNVWriterKeyLen(len(raw))
}

func classifyNVWriterKeyLen(n int) string {
	switch n {
	case 256:
		return types.TPMNvWriterRSA2048Fallback
	case 384:
		return types.TPMNvWriterRSA3072
	default:
		return ""
	}
}

func detectTPMNvWriterFromStatus(st ShirudoStatus) string {
	tpmMap, ok := st.TPM.(map[string]any)
	if !ok || tpmMap == nil {
		return ""
	}
	if pub, ok := tpmMap["nv_writer_public"].(string); ok && pub != "" {
		if v := classifyNVWriterPublicHex(pub); v != "" {
			return v
		}
	}
	if l, ok := tpmMap["nv_writer_public_len"].(float64); ok {
		if v := classifyNVWriterKeyLen(int(l)); v != "" {
			return v
		}
	}
	if bits, ok := tpmMap["nv_writer_bits"].(float64); ok {
		switch int(bits) {
		case 2048:
			return types.TPMNvWriterRSA2048Fallback
		case 3072:
			return types.TPMNvWriterRSA3072
		}
	}
	for _, key := range []string{"nv_writer_alg", "nv_writer"} {
		if raw, ok := tpmMap[key].(string); ok {
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "rsa2048-fallback", "rsa2048", "rsa-2048":
				return types.TPMNvWriterRSA2048Fallback
			case "rsa3072", "rsa-3072":
				return types.TPMNvWriterRSA3072
			}
		}
	}
	return ""
}

type shirudoEventlogEntry struct {
	Type           string `json:"type"`
	BootID         string `json:"boot_id"`
	NVName         string `json:"nv_name"`
	NVWriterPublic string `json:"nv_writer_public"`
}

func detectTPMNvWriterFromEventlog(path, wantNVName, wantBootID string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var exactMatch string
	var lastInit string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry shirudoEventlogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Type != "" && entry.Type != "init" {
			continue
		}
		if entry.NVWriterPublic == "" {
			continue
		}
		lastInit = entry.NVWriterPublic
		if (wantNVName != "" && entry.NVName == wantNVName) ||
			(wantBootID != "" && entry.BootID == wantBootID) {
			exactMatch = entry.NVWriterPublic
		}
	}
	if exactMatch != "" {
		return classifyNVWriterPublicHex(exactMatch)
	}
	if lastInit != "" {
		return classifyNVWriterPublicHex(lastInit)
	}
	return ""
}

func (s *ShirudoRuntime) detectTPMNvWriter(st ShirudoStatus) string {
	if v := detectTPMNvWriterFromStatus(st); v != "" {
		return v
	}
	eventlogPath := s.eventlogPath
	if eventlogPath == "" {
		if st.Assets != nil && st.Assets.Root != "" {
			eventlogPath = filepath.Join(st.Assets.Root, "eventlog")
		} else {
			eventlogPath = "/var/lib/shirudo/eventlog"
		}
	}
	var wantNVName string
	if tpmMap, ok := st.TPM.(map[string]any); ok && tpmMap != nil {
		if nvName, ok := tpmMap["nv_name"].(string); ok {
			wantNVName = strings.TrimSpace(nvName)
		}
	}
	return detectTPMNvWriterFromEventlog(eventlogPath, wantNVName, readBootID())
}
