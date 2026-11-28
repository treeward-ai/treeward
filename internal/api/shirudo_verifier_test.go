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
		Bin:                bin,
		AKName:             "aabbccdd",
		AllowRuntimeEvents: true,
		ExpectConfigRoot:   "deadbeef",
		ExpectConfigPCR:    "11223344",
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
	const validNonce = "0123456789abcdef"

	t.Run("fail verdict with non-zero exit", func(t *testing.T) {
		bin := writeFakeShirudo(t, `#!/bin/sh
echo '{"verdict":"fail","checks":[{"name":"nonce","status":"fail","detail":"mismatch"}]}'
exit 1
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{Bin: bin, AKName: "aabbccdd"})
		res := v.VerifyResult(context.Background(), validNonce, types.AttestResult{
			NodeID: "node-1",
			Quote:  `{"quote":"bad"}`,
		})
		if res.Pass {
			t.Fatalf("expected Pass=false for fail verdict, got %+v", res)
		}
		if !res.Verified {
			t.Fatalf("expected Verified=true from ShirudoVerifier, got %+v", res)
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
		v := NewShirudoVerifier(ShirudoVerifierConfig{Bin: bin, AKName: "aabbccdd"})
		if _, err := v.Verify(context.Background(), ShirudoVerifyRequest{
			Evidence: []byte(`{}`),
			Nonce:    validNonce,
		}); err == nil {
			t.Fatalf("expected error for invalid JSON output")
		}
		res := v.VerifyResult(context.Background(), validNonce, types.AttestResult{
			NodeID: "node-1",
			Quote:  `{}`,
		})
		if res.Pass {
			t.Fatalf("expected Pass=false for invalid JSON, got %+v", res)
		}
		if !res.Verified {
			t.Fatalf("expected Verified=true from ShirudoVerifier, got %+v", res)
		}
	})
}

func TestShirudoVerifier_AKPinningAndValidation(t *testing.T) {
	const validNonce = "0123456789abcdef"

	t.Run("unpinned AK fails closed by default", func(t *testing.T) {
		invokedFile := filepath.Join(t.TempDir(), "invoked")
		bin := writeFakeShirudo(t, `#!/bin/sh
touch "`+invokedFile+`"
echo '{"verdict":"ok","checks":[]}'
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{Bin: bin})
		_, err := v.Verify(context.Background(), ShirudoVerifyRequest{
			NodeID:   "node-1",
			Evidence: []byte(`{"ak_name":"aabbccdd11223344","quote":"self-asserted"}`),
			Nonce:    validNonce,
		})
		if err == nil || !strings.Contains(err.Error(), "no pinned AK configured") {
			t.Fatalf("expected fail-closed no pinned AK error, got %v", err)
		}
		if _, statErr := os.Stat(invokedFile); !os.IsNotExist(statErr) {
			t.Fatalf("expected shirudo binary not to be invoked when AK is unpinned")
		}
	})

	t.Run("per-node pinned AK is used over self-asserted evidence ak_name", func(t *testing.T) {
		argsFile := filepath.Join(t.TempDir(), "args.txt")
		bin := writeFakeShirudo(t, `#!/bin/sh
printf '%s\n' "$@" > "`+argsFile+`"
echo '{"verdict":"ok","checks":[{"name":"quote","status":"ok"}]}'
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin: bin,
			AKNames: map[string]string{
				"node-1": "1111222233334444",
				"node-2": "5555666677778888",
			},
			AKName: "99990000aaaabbbb",
		})

		verdict, err := v.Verify(context.Background(), ShirudoVerifyRequest{
			NodeID:   "node-2",
			Evidence: []byte(`{"ak_name":"deadbeefdeadbeef"}`),
			Nonce:    validNonce,
		})
		if err != nil {
			t.Fatalf("Verify() error: %v", err)
		}
		if verdict.Verdict != "ok" {
			t.Fatalf("verdict = %q, want ok", verdict.Verdict)
		}
		rawArgs, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatalf("read args: %v", err)
		}
		argsStr := string(rawArgs)
		if !strings.Contains(argsStr, "5555666677778888") {
			t.Fatalf("expected pinned AK for node-2 in args, got:\n%s", argsStr)
		}
		if strings.Contains(argsStr, "--allow-runtime-events") {
			t.Fatalf("expected --allow-runtime-events omitted when AllowRuntimeEvents=false, got:\n%s", argsStr)
		}
	})

	t.Run("AllowUnpinnedAK dev opt-in uses evidence ak_name", func(t *testing.T) {
		argsFile := filepath.Join(t.TempDir(), "args.txt")
		bin := writeFakeShirudo(t, `#!/bin/sh
printf '%s\n' "$@" > "`+argsFile+`"
echo '{"schema":1,"verdict":"ok","checks":[{"result":"ok","text":"attestation key: the pinned key"}]}'
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:             bin,
			AllowUnpinnedAK: true,
		})
		verdict, err := v.Verify(context.Background(), ShirudoVerifyRequest{
			NodeID:   "node-1",
			Evidence: []byte(`{"ak_name":"abcdef0123456789"}`),
			Nonce:    validNonce,
		})
		if err != nil {
			t.Fatalf("Verify() with AllowUnpinnedAK=true error: %v", err)
		}
		if len(verdict.Checks) != 1 || verdict.Checks[0].Result != "ok" || verdict.Checks[0].Text != "attestation key: the pinned key" {
			t.Fatalf("expected schema v1 result/text check fields to unmarshal, got %+v", verdict.Checks)
		}
		rawArgs, _ := os.ReadFile(argsFile)
		if !strings.Contains(string(rawArgs), "abcdef0123456789") {
			t.Fatalf("expected evidence ak_name in args, got:\n%s", string(rawArgs))
		}
	})

	t.Run("AllowUnpinnedAK dev opt-in extracts nested ak.name from shirudo schema v1", func(t *testing.T) {
		argsFile := filepath.Join(t.TempDir(), "args.txt")
		bin := writeFakeShirudo(t, `#!/bin/sh
printf '%s\n' "$@" > "`+argsFile+`"
echo '{"schema":1,"verdict":"ok","checks":[{"result":"ok","text":"nonce matches the request"}]}'
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:             bin,
			AllowUnpinnedAK: true,
		})
		if _, err := v.Verify(context.Background(), ShirudoVerifyRequest{
			NodeID:   "node-1",
			Evidence: []byte(`{"schema":1,"kind":"shirudo-attestation","ak":{"public":"0023","name":"000b7631cf876923"}}`),
			Nonce:    validNonce,
		}); err != nil {
			t.Fatalf("Verify() with nested ak.name error: %v", err)
		}
		rawArgs, _ := os.ReadFile(argsFile)
		if !strings.Contains(string(rawArgs), "000b7631cf876923") {
			t.Fatalf("expected nested ak.name in args, got:\n%s", string(rawArgs))
		}
	})

	t.Run("rejects malformed or flag-injection nonce and AK name", func(t *testing.T) {
		invokedFile := filepath.Join(t.TempDir(), "invoked")
		bin := writeFakeShirudo(t, `#!/bin/sh
touch "`+invokedFile+`"
echo '{"verdict":"ok","checks":[]}'
`)
		v := NewShirudoVerifier(ShirudoVerifierConfig{Bin: bin, AKName: "aabbccdd"})

		for _, badNonce := range []string{"--help", "-n", "deadbeef", "not-hex-at-all!!"} {
			if _, err := v.Verify(context.Background(), ShirudoVerifyRequest{
				NodeID:   "node-1",
				Evidence: []byte(`{}`),
				Nonce:    badNonce,
			}); err == nil {
				t.Fatalf("Verify(nonce=%q) expected error, got nil", badNonce)
			}
		}

		for _, badAK := range []string{"--help", "-k", "aabb", "not-hex!"} {
			if _, err := v.Verify(context.Background(), ShirudoVerifyRequest{
				NodeID:   "node-1",
				Evidence: []byte(`{}`),
				Nonce:    validNonce,
				AKName:   badAK,
			}); err == nil {
				t.Fatalf("Verify(akName=%q) expected error, got nil", badAK)
			}
		}

		if _, statErr := os.Stat(invokedFile); !os.IsNotExist(statErr) {
			t.Fatalf("expected shirudo binary not to be invoked on invalid nonce/AK")
		}
	})

	t.Run("env config parses SHIRUDO_AK_MAP_FILE, SHIRUDO_AK_NAMES, and SHIRUDO_ALLOW_RUNTIME_EVENTS", func(t *testing.T) {
		mapPath := filepath.Join(t.TempDir(), "aks.json")
		if err := os.WriteFile(mapPath, []byte(`{"node-1":"11111111","node-2":"22222222"}`), 0o600); err != nil {
			t.Fatalf("write ak map file: %v", err)
		}
		t.Setenv("SHIRUDO_BIN", "/usr/bin/shirudo")
		t.Setenv("SHIRUDO_AK_MAP_FILE", mapPath)
		t.Setenv("SHIRUDO_AK_NAMES", "node-2=33333333,node-3=44444444")
		t.Setenv("SHIRUDO_ALLOW_RUNTIME_EVENTS", "0")
		t.Setenv("SHIRUDO_ALLOW_UNPINNED_AK", "")

		cfg := ShirudoVerifierConfigFromEnv()
		if cfg.AllowRuntimeEvents {
			t.Fatalf("expected AllowRuntimeEvents=false when SHIRUDO_ALLOW_RUNTIME_EVENTS=0")
		}
		if cfg.AllowUnpinnedAK {
			t.Fatalf("expected AllowUnpinnedAK=false by default")
		}
		if cfg.AKNames["node-1"] != "11111111" || cfg.AKNames["node-2"] != "33333333" || cfg.AKNames["node-3"] != "44444444" {
			t.Fatalf("unexpected AKNames: %+v", cfg.AKNames)
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

	t.Run("SHIRUDO_BIN unset fails closed without TREEWARD_ALLOW_STUB_ATTEST", func(t *testing.T) {
		t.Setenv("TREEWARD_ALLOW_STUB_ATTEST", "")
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
		if len(out.Results) != 1 || out.Results[0].Pass || out.Results[0].Verified {
			t.Fatalf("expected fail-closed unverified failure, got %+v", out.Results)
		}
		nodes := srv.Store.ListNodes()
		if len(nodes) != 1 || nodes[0].AttestStatus != "fail" {
			t.Fatalf("expected node AttestStatus=fail, got %+v", nodes)
		}
	})

	t.Run("SHIRUDO_BIN unset allows stub verify with TREEWARD_ALLOW_STUB_ATTEST=true", func(t *testing.T) {
		t.Setenv("TREEWARD_ALLOW_STUB_ATTEST", "true")
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
		if len(out.Results) != 1 || !out.Results[0].Pass || out.Results[0].Verified {
			t.Fatalf("expected stub pass with Verified=false, got %+v", out.Results)
		}
		nodes := srv.Store.ListNodes()
		if len(nodes) != 1 || nodes[0].AttestStatus != "pass" {
			t.Fatalf("expected node AttestStatus=pass, got %+v", nodes)
		}
	})

	t.Run("SHIRUDO_BIN set uses Shirudo verifier with pinned AK", func(t *testing.T) {
		bin := writeFakeShirudo(t, `#!/bin/sh
echo '{"verdict":"ok","checks":[{"name":"quote","status":"ok"}]}'
`)
		t.Setenv("SHIRUDO_AK_NAMES", "node-1=aabbccdd")
		srv, tok, campID := newTestServer(t, bin)
		if srv.Verifier == nil {
			t.Fatalf("expected Verifier to be configured when SHIRUDO_BIN is set")
		}
		// Quote does not contain the nonce literally; only passes because Shirudo returned ok.
		body, _ := json.Marshal([]types.AttestResult{{
			NodeID: "node-1",
			Quote:  `{"quote":"opaque-tpm-evidence"}`,
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
		if len(out.Results) != 1 || !out.Results[0].Pass || !out.Results[0].Verified {
			t.Fatalf("expected shirudo verified pass, got %+v", out.Results)
		}
	})

	t.Run("connector cannot spoof Verified=true or Pass=true", func(t *testing.T) {
		// Stub mode (no Verifier): spoofed Verified=true/Pass=true with bad quote must fail.
		srv, tok, campID := newTestServer(t, "")
		spoofBody, _ := json.Marshal([]types.AttestResult{{
			NodeID:   "node-1",
			Quote:    "wrong-nonce-quote",
			Pass:     true,
			Verified: true,
		}})
		req := httptest.NewRequest(http.MethodPost, "/v1/attest/campaigns/"+campID+"/results", bytes.NewReader(spoofBody))
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
		if len(out.Results) != 1 || out.Results[0].Pass || out.Results[0].Verified {
			t.Fatalf("spoofed Verified/Pass must be cleared and fail stub verify, got %+v", out.Results)
		}
	})

	t.Run("rejects overwrites to already-completed campaigns", func(t *testing.T) {
		srv, tok, campID := newTestServer(t, "")
		camp, _ := srv.Store.GetCampaign(campID)

		// First submission completes the campaign (node-1 is the only known node).
		body1, _ := json.Marshal([]types.AttestResult{{
			NodeID: "node-1",
			Quote:  "mock-quote-" + camp.Nonce + "-FAIL",
		}})
		req1 := httptest.NewRequest(http.MethodPost, "/v1/attest/campaigns/"+campID+"/results", bytes.NewReader(body1))
		req1.Header.Set("Authorization", "Bearer "+tok)
		rec1 := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusOK {
			t.Fatalf("first submit status = %d, body = %s", rec1.Code, rec1.Body.String())
		}

		// Second submission attempting to overwrite the failed result with a passing one must be rejected.
		body2, _ := json.Marshal([]types.AttestResult{{
			NodeID: "node-1",
			Quote:  "mock-quote-" + camp.Nonce,
		}})
		req2 := httptest.NewRequest(http.MethodPost, "/v1/attest/campaigns/"+campID+"/results", bytes.NewReader(body2))
		req2.Header.Set("Authorization", "Bearer "+tok)
		rec2 := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("second submit status = %d, want 400 (body=%s)", rec2.Code, rec2.Body.String())
		}
		if !strings.Contains(rec2.Body.String(), "campaign already complete") {
			t.Fatalf("expected 'campaign already complete' error, got %q", rec2.Body.String())
		}

		// Verify original failed result was preserved.
		after, _ := srv.Store.GetCampaign(campID)
		if len(after.Results) != 1 || after.Results[0].Pass {
			t.Fatalf("expected original failed result to remain immutable, got %+v", after.Results)
		}
	})
}
