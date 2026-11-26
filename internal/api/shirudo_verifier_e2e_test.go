//go:build e2e

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/treeward-ai/treeward/internal/types"
)

func flipLastHexChar(s string) string {
	if len(s) == 0 {
		return s
	}
	last := s[len(s)-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	return s[:len(s)-1] + string(replacement)
}

func tamperQuotePayload(t *testing.T, raw []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal quote json: %v", err)
	}
	quoteObj, ok := doc["quote"].(map[string]any)
	if !ok {
		t.Fatalf("expected quote object in evidence JSON")
	}
	sig, ok := quoteObj["signature"].(string)
	if !ok || len(sig) < 4 {
		t.Fatalf("expected hex quote.signature in evidence JSON")
	}
	quoteObj["signature"] = flipLastHexChar(sig)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal tampered quote: %v", err)
	}
	return out
}

func failedCheckTexts(v *ShirudoVerdict) []string {
	if v == nil {
		return nil
	}
	var out []string
	for _, c := range v.Checks {
		if strings.EqualFold(c.Result, "fail") || strings.EqualFold(c.Status, "fail") {
			msg := c.Text
			if msg == "" {
				msg = c.Detail
			}
			out = append(out, msg)
		}
	}
	return out
}

func TestShirudoVerifier_E2E_RealTPMQuote(t *testing.T) {
	bin := strings.TrimSpace(os.Getenv("SHIRUDO_BIN"))
	akName := strings.TrimSpace(os.Getenv("SHIRUDO_AK_NAME"))
	cfgRoot := strings.TrimSpace(os.Getenv("SHIRUDO_EXPECT_CONFIG_ROOT"))
	cfgPCR := strings.TrimSpace(os.Getenv("SHIRUDO_EXPECT_CONFIG_PCR"))
	quoteFile := strings.TrimSpace(os.Getenv("E2E_QUOTE_FILE"))
	nonce := strings.TrimSpace(os.Getenv("E2E_NONCE"))

	if bin == "" || akName == "" || quoteFile == "" || nonce == "" {
		t.Skip("set SHIRUDO_BIN, SHIRUDO_AK_NAME, E2E_QUOTE_FILE, and E2E_NONCE to run E2E verifier tests")
	}

	evidence, err := os.ReadFile(quoteFile)
	if err != nil {
		t.Fatalf("read quote file %q: %v", quoteFile, err)
	}
	evidence = bytes.TrimSpace(evidence)
	ctx := context.Background()

	t.Run("Case1_GlobalPin_HappyPath", func(t *testing.T) {
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:                bin,
			AKName:             akName,
			AllowRuntimeEvents: true,
			ExpectConfigRoot:   cfgRoot,
			ExpectConfigPCR:    cfgPCR,
		})
		verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "lab",
			Evidence: evidence,
			Nonce:    nonce,
		})
		if err != nil {
			t.Fatalf("Verify() unexpected error: %v", err)
		}
		t.Logf("verdict=%q checks=%d", verdict.Verdict, len(verdict.Checks))
		if !strings.EqualFold(verdict.Verdict, "ok") {
			t.Fatalf("verdict = %q, want ok", verdict.Verdict)
		}
		res := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(evidence),
		})
		t.Logf("VerifyResult: pass=%v verified=%v quote=%q", res.Pass, res.Verified, res.Quote)
		if !res.Pass || !res.Verified {
			t.Fatalf("expected Pass=true Verified=true, got %+v", res)
		}
	})

	t.Run("Case2_PerNodePin_AKMapFile", func(t *testing.T) {
		mapPath := filepath.Join(t.TempDir(), "ak-map.json")
		mapData, _ := json.Marshal(map[string]string{"lab": akName})
		if err := os.WriteFile(mapPath, mapData, 0o600); err != nil {
			t.Fatalf("write ak map file: %v", err)
		}
		t.Setenv("SHIRUDO_BIN", bin)
		t.Setenv("SHIRUDO_AK_NAME", "")
		t.Setenv("SHIRUDO_AK_NAMES", "")
		t.Setenv("SHIRUDO_AK_MAP_FILE", mapPath)
		t.Setenv("SHIRUDO_ALLOW_UNPINNED_AK", "false")
		t.Setenv("SHIRUDO_ALLOW_RUNTIME_EVENTS", "true")
		t.Setenv("SHIRUDO_EXPECT_CONFIG_ROOT", cfgRoot)
		t.Setenv("SHIRUDO_EXPECT_CONFIG_PCR", cfgPCR)

		v := NewShirudoVerifierFromEnv()
		if v == nil {
			t.Fatalf("NewShirudoVerifierFromEnv returned nil")
		}

		// Must pass for nodeID="lab"
		resLab := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(evidence),
		})
		t.Logf("node=lab VerifyResult: pass=%v verified=%v quote=%q", resLab.Pass, resLab.Verified, resLab.Quote)
		if !resLab.Pass || !resLab.Verified {
			t.Fatalf("expected Pass=true for node=lab, got %+v", resLab)
		}

		// Must FAIL for nodeID="other-node"
		verdictOther, errOther := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "other-node",
			Evidence: evidence,
			Nonce:    nonce,
		})
		t.Logf("node=other-node Verify: verdict=%+v err=%v", verdictOther, errOther)
		if errOther == nil {
			t.Fatalf("expected error for unmapped node other-node, got verdict=%+v", verdictOther)
		}
		resOther := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "other-node",
			Quote:  string(evidence),
		})
		t.Logf("node=other-node VerifyResult: pass=%v verified=%v quote=%q", resOther.Pass, resOther.Verified, resOther.Quote)
		if resOther.Pass {
			t.Fatalf("expected Pass=false for node=other-node, got %+v", resOther)
		}
	})

	t.Run("Case3_WrongAKPin", func(t *testing.T) {
		wrongAK := flipLastHexChar(akName)
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:                bin,
			AKName:             wrongAK,
			AllowRuntimeEvents: true,
			ExpectConfigRoot:   cfgRoot,
			ExpectConfigPCR:    cfgPCR,
		})
		verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "lab",
			Evidence: evidence,
			Nonce:    nonce,
		})
		t.Logf("wrongAK=%s Verify: verdict=%q failedChecks=%q err=%v", wrongAK, verdict.Verdict, failedCheckTexts(verdict), err)
		res := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(evidence),
		})
		t.Logf("VerifyResult: pass=%v verified=%v quote=%q", res.Pass, res.Verified, res.Quote)
		if res.Pass {
			t.Fatalf("expected Pass=false for wrong AK pin, got %+v", res)
		}
	})

	t.Run("Case4_UnpinnedFailClosed", func(t *testing.T) {
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:                bin,
			AllowUnpinnedAK:    false,
			AllowRuntimeEvents: true,
			ExpectConfigRoot:   cfgRoot,
			ExpectConfigPCR:    cfgPCR,
		})
		verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "lab",
			Evidence: evidence,
			Nonce:    nonce,
		})
		t.Logf("Verify: verdict=%+v err=%v", verdict, err)
		if err == nil {
			t.Fatalf("expected fail-closed error, got verdict=%+v", verdict)
		}
		res := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(evidence),
		})
		t.Logf("VerifyResult: pass=%v verified=%v quote=%q", res.Pass, res.Verified, res.Quote)
		if res.Pass {
			t.Fatalf("expected Pass=false when unpinned, got %+v", res)
		}
	})

	t.Run("Case5_UnpinnedOptIn", func(t *testing.T) {
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:                bin,
			AllowUnpinnedAK:    true,
			AllowRuntimeEvents: true,
			ExpectConfigRoot:   cfgRoot,
			ExpectConfigPCR:    cfgPCR,
		})
		verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "lab",
			Evidence: evidence,
			Nonce:    nonce,
		})
		t.Logf("Verify: verdict=%+v err=%v", verdict, err)
		if err != nil {
			t.Fatalf("AllowUnpinnedAK=true failed against real evidence: %v", err)
		}
		if !strings.EqualFold(verdict.Verdict, "ok") {
			t.Fatalf("verdict = %q, want ok", verdict.Verdict)
		}
		res := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(evidence),
		})
		t.Logf("VerifyResult: pass=%v verified=%v quote=%q", res.Pass, res.Verified, res.Quote)
		if !res.Pass || !res.Verified {
			t.Fatalf("expected Pass=true Verified=true with AllowUnpinnedAK=true, got %+v", res)
		}
	})

	t.Run("Case6_NonceMismatch", func(t *testing.T) {
		wrongNonce := flipLastHexChar(nonce)
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:                bin,
			AKName:             akName,
			AllowRuntimeEvents: true,
			ExpectConfigRoot:   cfgRoot,
			ExpectConfigPCR:    cfgPCR,
		})
		verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "lab",
			Evidence: evidence,
			Nonce:    wrongNonce,
		})
		t.Logf("wrongNonce=%s Verify: verdict=%q failedChecks=%q err=%v", wrongNonce, verdict.Verdict, failedCheckTexts(verdict), err)
		res := v.VerifyResult(ctx, wrongNonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(evidence),
		})
		t.Logf("VerifyResult: pass=%v verified=%v quote=%q", res.Pass, res.Verified, res.Quote)
		if res.Pass {
			t.Fatalf("expected Pass=false for nonce mismatch, got %+v", res)
		}
	})

	t.Run("Case7_TamperedQuote", func(t *testing.T) {
		tampered := tamperQuotePayload(t, evidence)
		v := NewShirudoVerifier(ShirudoVerifierConfig{
			Bin:                bin,
			AKName:             akName,
			AllowRuntimeEvents: true,
			ExpectConfigRoot:   cfgRoot,
			ExpectConfigPCR:    cfgPCR,
		})
		verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
			NodeID:   "lab",
			Evidence: tampered,
			Nonce:    nonce,
		})
		t.Logf("Tampered Verify: verdict=%q failedChecks=%q err=%v", verdict.Verdict, failedCheckTexts(verdict), err)
		res := v.VerifyResult(ctx, nonce, types.AttestResult{
			NodeID: "lab",
			Quote:  string(tampered),
		})
		t.Logf("VerifyResult: pass=%v verified=%v quote=%q", res.Pass, res.Verified, res.Quote)
		if res.Pass {
			t.Fatalf("expected Pass=false for tampered quote, got %+v", res)
		}
	})
}
