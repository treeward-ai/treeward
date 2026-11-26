package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/treeward-ai/treeward/internal/types"
)

// AttestVerifier verifies a node's attestation evidence against a campaign nonce.
type AttestVerifier interface {
	VerifyResult(ctx context.Context, nonce string, res types.AttestResult) types.AttestResult
}

// ShirudoVerifierConfig configures the Shirudo CLI attestation verifier.
type ShirudoVerifierConfig struct {
	Bin              string
	AKName           string
	ExpectConfigRoot string
	ExpectConfigPCR  string
}

// ShirudoVerifier invokes `shirudo attest verify` to verify attestation evidence.
type ShirudoVerifier struct {
	cfg ShirudoVerifierConfig
}

// ShirudoVerifyRequest holds per-invocation verification parameters.
type ShirudoVerifyRequest struct {
	Evidence         []byte
	Nonce            string
	AKName           string
	ExpectConfigRoot string
	ExpectConfigPCR  string
}

// ShirudoCheck represents an individual check entry in shirudo's JSON output.
type ShirudoCheck struct {
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	OK     *bool  `json:"ok,omitempty"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ShirudoVerdict represents the JSON output of `shirudo attest verify --json`.
type ShirudoVerdict struct {
	Verdict string         `json:"verdict"`
	Checks  []ShirudoCheck `json:"checks"`
}

// NewShirudoVerifier constructs a ShirudoVerifier from the given configuration.
func NewShirudoVerifier(cfg ShirudoVerifierConfig) *ShirudoVerifier {
	return &ShirudoVerifier{cfg: cfg}
}

// NewShirudoVerifierFromEnv constructs a ShirudoVerifier when SHIRUDO_BIN is set.
// Returns nil when SHIRUDO_BIN is empty so callers preserve mock verification behavior.
func NewShirudoVerifierFromEnv() *ShirudoVerifier {
	bin := strings.TrimSpace(os.Getenv("SHIRUDO_BIN"))
	if bin == "" {
		return nil
	}
	return NewShirudoVerifier(ShirudoVerifierConfig{
		Bin:              bin,
		AKName:           strings.TrimSpace(os.Getenv("SHIRUDO_AK_NAME")),
		ExpectConfigRoot: strings.TrimSpace(os.Getenv("SHIRUDO_EXPECT_CONFIG_ROOT")),
		ExpectConfigPCR:  strings.TrimSpace(os.Getenv("SHIRUDO_EXPECT_CONFIG_PCR")),
	})
}

// Verify writes req.Evidence to a 0600 temp file, invokes `shirudo attest verify`,
// and parses the JSON verdict.
func (v *ShirudoVerifier) Verify(ctx context.Context, req ShirudoVerifyRequest) (*ShirudoVerdict, error) {
	if v == nil || strings.TrimSpace(v.cfg.Bin) == "" {
		return nil, fmt.Errorf("shirudo verifier binary not configured")
	}

	tmp, err := os.CreateTemp("", "treeward-evidence-*.json")
	if err != nil {
		return nil, fmt.Errorf("create evidence temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("chmod evidence temp file: %w", err)
	}
	if _, err := tmp.Write(req.Evidence); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write evidence temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close evidence temp file: %w", err)
	}

	akName := req.AKName
	if akName == "" {
		akName = v.cfg.AKName
	}
	if akName == "" {
		akName = extractAKName(req.Evidence)
	}

	expectConfigRoot := req.ExpectConfigRoot
	if expectConfigRoot == "" {
		expectConfigRoot = v.cfg.ExpectConfigRoot
	}
	expectConfigPCR := req.ExpectConfigPCR
	if expectConfigPCR == "" {
		expectConfigPCR = v.cfg.ExpectConfigPCR
	}

	args := []string{
		"attest", "verify",
		"--evidence", tmpPath,
		"--nonce", req.Nonce,
		"--ak-name", akName,
		"--allow-runtime-events",
		"--json",
	}
	if expectConfigRoot != "" {
		args = append(args, "--expect-config-root", expectConfigRoot)
	}
	if expectConfigPCR != "" {
		args = append(args, "--expect-config-pcr", expectConfigPCR)
	}

	cmd := exec.CommandContext(ctx, v.cfg.Bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	var verdict ShirudoVerdict
	parseErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &verdict)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("shirudo attest verify failed: %w (stderr=%q stdout=%q)", runErr, strings.TrimSpace(stderr.String()), strings.TrimSpace(stdout.String()))
		}
		return nil, fmt.Errorf("parse shirudo verdict json: %w (stdout=%q)", parseErr, strings.TrimSpace(stdout.String()))
	}

	if verdict.Verdict == "" {
		return nil, fmt.Errorf("shirudo verdict missing verdict field")
	}

	if runErr != nil && strings.EqualFold(verdict.Verdict, "ok") {
		return nil, fmt.Errorf("shirudo attest verify exited with error despite ok verdict: %w", runErr)
	}

	return &verdict, nil
}

// VerifyResult verifies a Treeward AttestResult's Quote (evidence JSON) and maps
// the Shirudo verdict back into an AttestResult compatible with Store.SubmitAttest.
func (v *ShirudoVerifier) VerifyResult(ctx context.Context, nonce string, res types.AttestResult) types.AttestResult {
	res.Nonce = nonce
	verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
		Evidence: []byte(res.Quote),
		Nonce:    nonce,
	})
	if err != nil {
		res.Pass = false
		res.Quote = fmt.Sprintf("shirudo:FAIL error=%s", err.Error())
		return res
	}

	if strings.EqualFold(verdict.Verdict, "ok") {
		res.Pass = true
		res.Quote = fmt.Sprintf("shirudo:ok nonce=%s checks=%d", nonce, len(verdict.Checks))
		return res
	}

	res.Pass = false
	res.Quote = fmt.Sprintf("shirudo:FAIL verdict=%s checks=%d", verdict.Verdict, len(verdict.Checks))
	return res
}

func extractAKName(evidence []byte) string {
	var envelope struct {
		AKNameSnake string `json:"ak_name"`
		AKNameCamel string `json:"akName"`
	}
	if err := json.Unmarshal(evidence, &envelope); err != nil {
		return ""
	}
	if envelope.AKNameSnake != "" {
		return envelope.AKNameSnake
	}
	return envelope.AKNameCamel
}
