package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/store"
	"github.com/treeward-ai/treeward/internal/types"
)

func writeFakeShirudo(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-shirudo")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake shirudo: %v", err)
	}
	return bin
}

func TestShirudoVerifier_ValidVerdictAndTempFileCleanup(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	modeFile := filepath.Join(t.TempDir(), "mode.txt")
	evidencePathFile := filepath.Join(t.TempDir(), "evidence_path.txt")
	evidenceCopyFile := filepath.Join(t.TempDir(), "evidence_copy.json")

	script := `#!/bin/sh
set -eu
printf '%s\n' "$@" > "` + argsFile + `"
ev=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--evidence" ]; then
    ev="$a"
    break
  fi
  prev="$a"
done
printf '%s' "$ev" > "` + evidencePathFile + `"
stat -c '%a' "$ev" > "` + modeFile + `"
cp "$ev" "` + evidenceCopyFile + `"
echo '{"verdict":"ok","checks":[{"name":"quote","status":"ok"},{"name":"nonce","status":"ok"}]}'
`
	bin := writeFakeShirudo(t, script)

	v := NewShirudoVerifier(ShirudoVerifierConfig{
		Bin:              bin,
		AKName:           "aabbccdd",
		ExpectConfigRoot: "deadbeef",
		ExpectConfigPCR:  "11223344",
	})

	evidence := []byte(`{"quote":"base64data","ak_name":"ignored_when_cfg_set"}`)
	verdict, err := v.Verify(context.Background(), ShirudoVerifyRequest{
		Evidence: evidence,
		Nonce:    "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if verdict.Verdict != "ok" {
		t.Fatalf("verdict = %q, want %q", verdict.Verdict, "ok")
	}
	if len(verdict.Checks) != 2 {
		t.Fatalf("len(checks) = %d, want 2", len(verdict.Checks))
	}

	// Verify CLI arguments.
	rawArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read args file: %v", err)
	}
	gotArgs := strings.Split(strings.TrimSpace(string(rawArgs)), "\n")
	evPathBytes, err := os.ReadFile(evidencePathFile)
	if err != nil {
		t.Fatalf("read evidence path: %v", err)
	}
	evPath := strings.TrimSpace(string(evPathBytes))

	wantArgs := []string{
		"attest", "verify",
		"--evidence", evPath,
		"--nonce", "0123456789abcdef",
		"--ak-name", "aabbccdd",
		"--allow-runtime-events",
		"--json",
		"--expect-config-root", "deadbeef",
		"--expect-config-pcr", "11223344",
	}
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
	for i := range wantArgs {
		if gotArgs[i] != wantArgs[i] {
			t.Fatalf("arg[%d] = %q, want %q (all=%v)", i, gotArgs[i], wantArgs[i], gotArgs)
		}
	}

	// Verify 0600 permissions on temp file.
	modeBytes, err := os.ReadFile(modeFile)
	if err != nil {
		t.Fatalf("read mode file: %v", err)
	}
	if got := strings.TrimSpace(string(modeBytes)); got != "600" {
		t.Fatalf("temp file mode = %q, want %q", got, "600")
	}

	// Verify evidence content was written accurately.
	gotEvidence, err := os.ReadFile(evidenceCopyFile)
	if err != nil {
		t.Fatalf("read copied evidence: %v", err)
	}
	if !bytes.Equal(gotEvidence, evidence) {
		t.Fatalf("evidence content = %q, want %q", gotEvidence, evidence)
	}

	// Verify temp file was cleaned up via defer os.Remove.
	if _, err := os.Stat(evPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file %s to be removed, stat err = %v", evPath, err)
	}
}

func TestShirudoVerifier_FailVerdictAndInvalidJSON(t *testing.T) {
	t.Run("fail verdict with non-zero exit", func(t *testing.T) {
		bin := writeFakeShirudo(t, `#!/bin/sh
echo '{"verdict":"fail","checks":[{"name":"nonce","status":"fail","detail":"mismatch"}]}'
exit 1
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{Bin: bin, AKName: "aabb"})
		res := v.VerifyResult(context.Background(), "deadbeef", types.AttestResult{
			NodeID: "node-1",
			Quote:  `{"quote":"bad"}`,
		})
		if res.Pass {
			t.Fatalf("expected Pass=false for fail verdict, got %+v", res)
		}
		if !strings.Contains(strings.ToUpper(res.Quote), "FAIL") {
			t.Fatalf("expected Quote to contain FAIL for Store.SubmitAttest compatibility, got %q", res.Quote)
		}
	})

	t.Run("invalid JSON output", func(t *testing.T) {
		bin := writeFakeShirudo(t, `#!/bin/sh
echo 'not-valid-json'
exit 2
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{Bin: bin, AKName: "aabb"})
		if _, err := v.Verify(context.Background(), ShirudoVerifyRequest{
			Evidence: []byte(`{}`),
			Nonce:    "deadbeef",
		}); err == nil {
			t.Fatalf("expected error for invalid JSON output")
		}
		res := v.VerifyResult(context.Background(), "deadbeef", types.AttestResult{
			NodeID: "node-1",
			Quote:  `{}`,
		})
		if res.Pass {
			t.Fatalf("expected Pass=false for invalid JSON, got %+v", res)
		}
	})
}

func TestServer_AttestResults_ShirudoAndMockFallback(t *testing.T) {
	newTestServer := func(t *testing.T, shirudoBin string) (*Server, string, string) {
		t.Helper()
		t.Setenv("SHIRUDO_BIN", shirudoBin)
		dir := t.TempDir()
		sig, err := signer.NewLocal(filepath.Join(dir, "keys"))
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		st, err := store.Open(filepath.Join(dir, "treeward.db"), "enroll-tok", "admin-boot-tok", sig)
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		enrolled, err := st.Enroll(types.EnrollRequest{BootstrapToken: "enroll-tok", ClusterName: "c1"})
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		st.UpsertInventory([]types.Node{{ID: "node-1", Hostname: "n1"}}, enrolled.ClusterID)
		camp := st.StartAttestCampaign()

		return New(st), enrolled.Token, camp.ID
	}

	t.Run("SHIRUDO_BIN unset preserves mock behavior", func(t *testing.T) {
		srv, tok, campID := newTestServer(t, "")
		if srv.Verifier != nil {
			t.Fatalf("expected Verifier=nil when SHIRUDO_BIN is unset")
		}
		camp, _ := srv.Store.GetCampaign(campID)
		body, _ := json.Marshal([]types.AttestResult{{
			NodeID: "node-1",
			Quote:  "mock-quote-" + camp.Nonce,
		}})
		req := httptest.NewRequest(http.MethodPost, "/v1/attest/campaigns/"+campID+"/results", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out types.AttestCampaign
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(out.Results) != 1 || !out.Results[0].Pass {
			t.Fatalf("expected mock pass, got %+v", out.Results)
		}
	})

	t.Run("SHIRUDO_BIN set uses Shirudo verifier", func(t *testing.T) {
		bin := writeFakeShirudo(t, `#!/bin/sh
echo '{"verdict":"ok","checks":[{"name":"quote","status":"ok"}]}'
`)
		srv, tok, campID := newTestServer(t, bin)
		if srv.Verifier == nil {
			t.Fatalf("expected Verifier to be configured when SHIRUDO_BIN is set")
		}
		// Quote does not contain the nonce literally; only passes because Shirudo returned ok.
		body, _ := json.Marshal([]types.AttestResult{{
			NodeID: "node-1",
			Quote:  `{"ak_name":"aabb","quote":"opaque-tpm-evidence"}`,
		}})
		req := httptest.NewRequest(http.MethodPost, "/v1/attest/campaigns/"+campID+"/results", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out types.AttestCampaign
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(out.Results) != 1 || !out.Results[0].Pass {
			t.Fatalf("expected shirudo pass, got %+v", out.Results)
		}
	})
}
