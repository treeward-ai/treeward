package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/treeward-ai/treeward/internal/types"
)

func writeFakeShirudo(t *testing.T, script string) (binPath, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	binPath = filepath.Join(dir, "shirudo-runtime")

	full := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		script + "\n"

	if err := os.WriteFile(binPath, []byte(full), 0o755); err != nil {
		t.Fatalf("write fake shirudo-runtime: %v", err)
	}
	return binPath, logPath
}

func readCallLog(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestShirudoStatusAndInventory(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
if [ "$1" = "status" ] && [ "$2" = "--json" ]; then
  cat <<'JSON'
{"status":"ok","upatches_loaded":["patch-a","patch-b"],"tpm":{"present":true,"pcr":10},"kernel":"6.8.0-shirudo","arch":"amd64","hostname":"lab-vm-1"}
JSON
  exit 0
fi
echo "unexpected args: $@" >&2
exit 1
`)

	rt := NewShirudo(WithShirudoBin(bin), WithNodeID("lab-vm-1"))

	st, err := rt.Status()
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if st.Status != "ok" {
		t.Fatalf("Status.Status = %q, want %q", st.Status, "ok")
	}
	if !reflect.DeepEqual(st.UpatchesLoaded, []string{"patch-a", "patch-b"}) {
		t.Fatalf("Status.UpatchesLoaded = %v, want [patch-a patch-b]", st.UpatchesLoaded)
	}
	if st.TPM == nil {
		t.Fatalf("Status.TPM = nil, want non-nil")
	}

	nodes, err := rt.Inventory()
	if err != nil {
		t.Fatalf("Inventory() error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}
	n := nodes[0]
	if n.ID != "lab-vm-1" || n.Hostname != "lab-vm-1" || n.Kernel != "6.8.0-shirudo" || n.Arch != "amd64" {
		t.Fatalf("unexpected node: %+v", n)
	}
	if !reflect.DeepEqual(n.Loaded, []string{"patch-a", "patch-b"}) {
		t.Fatalf("node.Loaded = %v, want [patch-a patch-b]", n.Loaded)
	}
	if n.Labels["treeward.ai/runtime"] != "shirudo" {
		t.Fatalf("missing runtime label: %+v", n.Labels)
	}

	calls := readCallLog(t, logPath)
	if len(calls) != 2 || calls[0] != "status --json" || calls[1] != "status --json" {
		t.Fatalf("unexpected calls: %v", calls)
	}
}

func TestShirudoApplyLoadAndUnload(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
case "$1" in
  status)
    echo '{"status":"ok","upatches_loaded":["old-patch","keep-patch"]}'
    exit 0
    ;;
  upatch)
    if [ "$2" = "load" ] && [ -n "$3" ]; then
      exit 0
    fi
    if [ "$2" = "unload" ] && [ -n "$3" ]; then
      exit 0
    fi
    ;;
esac
echo "unexpected args: $@" >&2
exit 1
`)

	upatchDir := t.TempDir()
	stateDir := t.TempDir()

	// Seed owned state and signed unload directive for old-patch.
	if err := os.WriteFile(filepath.Join(stateDir, "owned.json"), []byte(`["old-patch","keep-patch"]`), 0o644); err != nil {
		t.Fatalf("write owned.json: %v", err)
	}
	directivePath := filepath.Join(upatchDir, "old-patch.unload.upatch")
	if err := os.WriteFile(directivePath, []byte("signed-unload-directive"), 0o644); err != nil {
		t.Fatalf("write unload directive: %v", err)
	}

	rt := NewShirudo(
		WithShirudoBin(bin),
		WithNodeID("node-1"),
		WithUpatchDir(upatchDir),
		WithStateDir(stateDir),
	)

	desired := types.DesiredState{
		Nodes: map[string][]string{
			"node-1": {"keep-patch", "new-patch"},
		},
	}

	loaded, errs, err := rt.Apply(desired)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("Apply() errs = %v, want empty", errs)
	}
	wantLoaded := []string{"keep-patch", "new-patch"}
	if !reflect.DeepEqual(loaded["node-1"], wantLoaded) {
		t.Fatalf("loaded[node-1] = %v, want %v", loaded["node-1"], wantLoaded)
	}

	calls := readCallLog(t, logPath)
	wantCalls := []string{
		"status --json",
		"upatch load " + filepath.Join(upatchDir, "new-patch"),
		"upatch unload " + directivePath,
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
}

func TestShirudoApplyUnloadMissingDirective(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
case "$1" in
  status)
    echo '{"status":"ok","upatches_loaded":["old-patch"]}'
    exit 0
    ;;
  upatch)
    echo "should not be called" >&2
    exit 1
    ;;
esac
exit 1
`)

	upatchDir := t.TempDir()
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "owned.json"), []byte(`["old-patch"]`), 0o644); err != nil {
		t.Fatalf("write owned.json: %v", err)
	}

	rt := NewShirudo(
		WithShirudoBin(bin),
		WithNodeID("node-1"),
		WithUpatchDir(upatchDir),
		WithStateDir(stateDir),
	)

	loaded, errs, err := rt.Apply(types.DesiredState{
		Nodes: map[string][]string{"node-1": {}},
	})
	if err != nil {
		t.Fatalf("Apply() top-level error: %v", err)
	}
	if !reflect.DeepEqual(loaded["node-1"], []string{"old-patch"}) {
		t.Fatalf("loaded[node-1] = %v, want [old-patch]", loaded["node-1"])
	}
	if len(errs["node-1"]) != 1 || !strings.Contains(errs["node-1"][0], "missing unload directive") {
		t.Fatalf("errs[node-1] = %v, want missing unload directive error", errs["node-1"])
	}

	calls := readCallLog(t, logPath)
	wantCalls := []string{"status --json"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %v, want %v (no unload call should be made)", calls, wantCalls)
	}
}

func TestShirudoApplySkipsExternalUpatch(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
case "$1" in
  status)
    echo '{"status":"ok","upatches_loaded":["app-sandbox"]}'
    exit 0
    ;;
  upatch)
    echo "should not unload external upatch" >&2
    exit 1
    ;;
esac
exit 1
`)

	upatchDir := t.TempDir()
	stateDir := t.TempDir()
	// Even if a directive file happened to exist, an external upatch not in owned.json must never be unloaded.
	if err := os.WriteFile(filepath.Join(upatchDir, "app-sandbox.unload.upatch"), []byte("directive"), 0o644); err != nil {
		t.Fatalf("write directive: %v", err)
	}

	rt := NewShirudo(
		WithShirudoBin(bin),
		WithNodeID("node-1"),
		WithUpatchDir(upatchDir),
		WithStateDir(stateDir),
	)

	loaded, errs, err := rt.Apply(types.DesiredState{
		Nodes: map[string][]string{"node-1": {}},
	})
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("Apply() errs = %v, want empty", errs)
	}
	if !reflect.DeepEqual(loaded["node-1"], []string{"app-sandbox"}) {
		t.Fatalf("loaded[node-1] = %v, want [app-sandbox]", loaded["node-1"])
	}

	calls := readCallLog(t, logPath)
	if !reflect.DeepEqual(calls, []string{"status --json"}) {
		t.Fatalf("calls = %v, want [status --json]", calls)
	}
}

func TestShirudoApplyOwnedUpatchDroppedFromDesiredIsUnloaded(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "loaded.txt")
	bin, logPath := writeFakeShirudo(t, `
STATE_FILE="`+stateFile+`"
case "$1" in
  status)
    if [ -f "$STATE_FILE" ]; then
      echo '{"status":"ok","upatches_loaded":["app-sandbox","managed-patch"]}'
    else
      echo '{"status":"ok","upatches_loaded":["app-sandbox"]}'
    fi
    exit 0
    ;;
  upatch)
    if [ "$2" = "load" ] && [ -n "$3" ]; then
      touch "$STATE_FILE"
      exit 0
    fi
    if [ "$2" = "unload" ] && [ -n "$3" ]; then
      rm -f "$STATE_FILE"
      exit 0
    fi
    ;;
esac
echo "unexpected args: $@" >&2
exit 1
`)

	upatchDir := t.TempDir()
	stateDir := t.TempDir()
	directivePath := filepath.Join(upatchDir, "managed-patch.unload.upatch")
	if err := os.WriteFile(directivePath, []byte("signed-unload-directive"), 0o644); err != nil {
		t.Fatalf("write directive: %v", err)
	}

	// Cycle 1: managed-patch is desired -> loaded and recorded in owned.json.
	rt1 := NewShirudo(
		WithShirudoBin(bin),
		WithNodeID("node-1"),
		WithUpatchDir(upatchDir),
		WithStateDir(stateDir),
	)
	loaded, errs, err := rt1.Apply(types.DesiredState{
		Nodes: map[string][]string{"node-1": {"managed-patch"}},
	})
	if err != nil {
		t.Fatalf("cycle 1 Apply() error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("cycle 1 errs = %v, want empty", errs)
	}
	if !reflect.DeepEqual(loaded["node-1"], []string{"app-sandbox", "managed-patch"}) {
		t.Fatalf("cycle 1 loaded = %v, want [app-sandbox managed-patch]", loaded["node-1"])
	}

	// Cycle 2 (fresh runtime instance reading persisted owned.json): managed-patch dropped from desired.
	rt2 := NewShirudo(
		WithShirudoBin(bin),
		WithNodeID("node-1"),
		WithUpatchDir(upatchDir),
		WithStateDir(stateDir),
	)
	loaded, errs, err = rt2.Apply(types.DesiredState{
		Nodes: map[string][]string{"node-1": {}},
	})
	if err != nil {
		t.Fatalf("cycle 2 Apply() error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("cycle 2 errs = %v, want empty", errs)
	}
	if !reflect.DeepEqual(loaded["node-1"], []string{"app-sandbox"}) {
		t.Fatalf("cycle 2 loaded = %v, want [app-sandbox]", loaded["node-1"])
	}

	calls := readCallLog(t, logPath)
	wantCalls := []string{
		"status --json",
		"upatch load " + filepath.Join(upatchDir, "managed-patch"),
		"status --json",
		"upatch unload " + directivePath,
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
}

func TestShirudoApplyRecordsLoadError(t *testing.T) {
	bin, _ := writeFakeShirudo(t, `
case "$1" in
  status)
    echo '{"status":"ok","upatches_loaded":[]}'
    exit 0
    ;;
  upatch)
    if [ "$2" = "load" ]; then
      echo "signature verification failed" >&2
      exit 1
    fi
    ;;
esac
exit 1
`)

	rt := NewShirudo(WithShirudoBin(bin), WithNodeID("node-1"), WithStateDir(t.TempDir()))
	loaded, errs, err := rt.Apply(types.DesiredState{
		Nodes: map[string][]string{"node-1": {"bad-patch"}},
	})
	if err != nil {
		t.Fatalf("Apply() returned top-level error: %v", err)
	}
	if len(loaded["node-1"]) != 0 {
		t.Fatalf("loaded[node-1] = %v, want empty", loaded["node-1"])
	}
	if len(errs["node-1"]) != 1 || !strings.Contains(errs["node-1"][0], "signature verification failed") {
		t.Fatalf("errs[node-1] = %v, want signature verification failed", errs["node-1"])
	}
}

func TestShirudoAttest(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
if [ "$1" = "attest" ] && [ "$2" = "--nonce" ] && [ -n "$3" ]; then
  printf '{"nonce":"%s","tpm_quote":"deadbeef","pcrs":{"10":"abc"}}\n' "$3"
  exit 0
fi
echo "unexpected args: $@" >&2
exit 1
`)

	nonce := "a1b2c3d4e5f60718"
	rt := NewShirudo(WithShirudoBin(bin), WithNodeID("node-1"), WithStateDir(t.TempDir()))
	nodes := []types.Node{{ID: "node-1"}}
	results, err := rt.Attest(nonce, nodes, nil)
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].NodeID != "node-1" || results[0].Nonce != nonce {
		t.Fatalf("unexpected attest result metadata: %+v", results[0])
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(results[0].Quote), &doc); err != nil {
		t.Fatalf("Quote is not valid JSON: %v (%q)", err, results[0].Quote)
	}
	if doc["nonce"] != nonce {
		t.Fatalf("doc[nonce] = %v, want %s", doc["nonce"], nonce)
	}

	calls := readCallLog(t, logPath)
	if !reflect.DeepEqual(calls, []string{"attest --nonce " + nonce}) {
		t.Fatalf("calls = %v, want [attest --nonce %s]", calls, nonce)
	}
}

func TestShirudoRejectsPathTraversalAndFlagInjection(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
case "$1" in
  status)
    echo '{"status":"ok","upatches_loaded":[]}'
    exit 0
    ;;
  upatch|attest)
    echo "should not be invoked with untrusted args: $@" >&2
    exit 1
    ;;
esac
exit 1
`)

	upatchDir := t.TempDir()
	stateDir := t.TempDir()
	rt := NewShirudo(
		WithShirudoBin(bin),
		WithNodeID("node-1"),
		WithUpatchDir(upatchDir),
		WithStateDir(stateDir),
	)

	badNames := []string{
		"../evil",
		"foo/../bar",
		"/etc/passwd",
		`..\evil`,
		"--help",
		"-v",
		"",
		"bad name",
	}

	// Apply must reject all bad upatch names without calling shirudo-runtime upatch load.
	loaded, errs, err := rt.Apply(types.DesiredState{
		Nodes: map[string][]string{"node-1": badNames},
	})
	if err != nil {
		t.Fatalf("Apply() top-level error: %v", err)
	}
	if len(loaded["node-1"]) != 0 {
		t.Fatalf("loaded[node-1] = %v, want empty", loaded["node-1"])
	}
	if len(errs["node-1"]) != len(badNames) {
		t.Fatalf("len(errs[node-1]) = %d, want %d (errs=%v)", len(errs["node-1"]), len(badNames), errs["node-1"])
	}

	// UnloadUpatch must reject all bad upatch names.
	for _, name := range badNames {
		if err := rt.UnloadUpatch(name); err == nil {
			t.Fatalf("UnloadUpatch(%q) expected error, got nil", name)
		}
	}

	// LoadUpatch must reject leading dashes and parent traversal segments.
	for _, p := range []string{"--help", "-x", "../evil.upatch", "/var/lib/../etc/passwd", ""} {
		if err := rt.LoadUpatch(p); err == nil {
			t.Fatalf("LoadUpatch(%q) expected error, got nil", p)
		}
	}

	// AttestRaw must reject flag injection and malformed nonces.
	for _, nonce := range []string{"--help", "-n", "a1b2c3d4", "zzzzzzzzzzzzzzzz", "0123456789abcdef --extra", ""} {
		if _, err := rt.AttestRaw(nonce); err == nil {
			t.Fatalf("AttestRaw(%q) expected error, got nil", nonce)
		}
	}

	// Only the single status --json call from Apply should have executed.
	calls := readCallLog(t, logPath)
	if !reflect.DeepEqual(calls, []string{"status --json"}) {
		t.Fatalf("calls = %v, want [status --json]", calls)
	}
}

func TestShirudoLoadUpatchAllowsLegitimateAbsolutePath(t *testing.T) {
	bin, logPath := writeFakeShirudo(t, `
if [ "$1" = "upatch" ] && [ "$2" = "load" ] && [ -n "$3" ]; then
  exit 0
fi
exit 1
`)
	rt := NewShirudo(WithShirudoBin(bin), WithNodeID("node-1"))
	absPath := filepath.Join(t.TempDir(), "patch-1.upatch")
	if err := rt.LoadUpatch(absPath); err != nil {
		t.Fatalf("LoadUpatch(%q) unexpected error: %v", absPath, err)
	}
	calls := readCallLog(t, logPath)
	if !reflect.DeepEqual(calls, []string{"upatch load " + absPath}) {
		t.Fatalf("calls = %v, want [upatch load %s]", calls, absPath)
	}
}

func TestShirudoOwnedStatePermissions(t *testing.T) {
	bin, _ := writeFakeShirudo(t, `
case "$1" in
  status)
    echo '{"status":"ok","upatches_loaded":[]}'
    exit 0
    ;;
  upatch)
    exit 0
    ;;
esac
exit 1
`)
	stateDir := filepath.Join(t.TempDir(), "state")
	rt := NewShirudo(WithShirudoBin(bin), WithNodeID("node-1"), WithStateDir(stateDir))
	if _, _, err := rt.Apply(types.DesiredState{Nodes: map[string][]string{"node-1": {"patch-a"}}}); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	dirInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("stat stateDir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("stateDir perm = %o, want 700", perm)
	}

	fileInfo, err := os.Stat(filepath.Join(stateDir, "owned.json"))
	if err != nil {
		t.Fatalf("stat owned.json: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("owned.json perm = %o, want 600", perm)
	}
}

func TestNewRuntimeSelection(t *testing.T) {
	t.Setenv("SHIRUDO_RUNTIME_BIN", "/custom/shirudo-runtime")

	for _, kind := range []string{"", "stub", "mock"} {
		rt, err := New(kind)
		if err != nil {
			t.Fatalf("New(%q) error: %v", kind, err)
		}
		if _, ok := rt.(*StubRuntime); !ok {
			t.Fatalf("New(%q) returned %T, want *StubRuntime", kind, rt)
		}
	}

	rt, err := New("shirudo")
	if err != nil {
		t.Fatalf("New(shirudo) error: %v", err)
	}
	sr, ok := rt.(*ShirudoRuntime)
	if !ok {
		t.Fatalf("New(shirudo) returned %T, want *ShirudoRuntime", rt)
	}
	if sr.bin != "/custom/shirudo-runtime" {
		t.Fatalf("ShirudoRuntime.bin = %q, want /custom/shirudo-runtime", sr.bin)
	}

	if _, err := New("invalid"); err == nil {
		t.Fatalf("New(invalid) expected error, got nil")
	}
}

func TestShirudoInventoryRolloutLabel(t *testing.T) {
	bin, _ := writeFakeShirudo(t, `
if [ "$1" = "status" ] && [ "$2" = "--json" ]; then
  echo '{"status":"ok","upatches_loaded":[],"hostname":"lab-vm-1"}'
  exit 0
fi
exit 1
`)

	t.Run("omitted when TREEWARD_ROLLOUT unset", func(t *testing.T) {
		t.Setenv("TREEWARD_ROLLOUT", "")
		rt := NewShirudo(WithShirudoBin(bin), WithNodeID("lab-vm-1"))
		nodes, err := rt.Inventory()
		if err != nil {
			t.Fatalf("Inventory() error: %v", err)
		}
		if _, ok := nodes[0].Labels[types.LabelRollout]; ok {
			t.Fatalf("expected %s label to be omitted, got %+v", types.LabelRollout, nodes[0].Labels)
		}
	})

	t.Run("set from TREEWARD_ROLLOUT env", func(t *testing.T) {
		t.Setenv("TREEWARD_ROLLOUT", "canary")
		rt := NewShirudo(WithShirudoBin(bin), WithNodeID("lab-vm-1"))
		nodes, err := rt.Inventory()
		if err != nil {
			t.Fatalf("Inventory() error: %v", err)
		}
		if got := nodes[0].Labels[types.LabelRollout]; got != types.RolloutCanary {
			t.Fatalf("label %s = %q, want %q", types.LabelRollout, got, types.RolloutCanary)
		}
	})

	t.Run("overridden via WithRollout option", func(t *testing.T) {
		t.Setenv("TREEWARD_ROLLOUT", "")
		rt := NewShirudo(WithShirudoBin(bin), WithNodeID("lab-vm-1"), WithRollout("canary"))
		nodes, err := rt.Inventory()
		if err != nil {
			t.Fatalf("Inventory() error: %v", err)
		}
		if got := nodes[0].Labels[types.LabelRollout]; got != types.RolloutCanary {
			t.Fatalf("label %s = %q, want %q", types.LabelRollout, got, types.RolloutCanary)
		}
	})
}
