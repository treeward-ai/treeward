package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/treeward-ai/treeward/internal/types"
)

var (
	verifierNonceHexRe  = regexp.MustCompile(`^[0-9a-fA-F]{16,128}$`)
	verifierAKNameHexRe = regexp.MustCompile(`^[0-9a-fA-F]{8,256}$`)
)

// AttestVerifier verifies a node's attestation evidence against a campaign nonce.
type AttestVerifier interface {
	VerifyResult(ctx context.Context, nonce string, res types.AttestResult) types.AttestResult
}

// ShirudoVerifierConfig configures the Shirudo CLI attestation verifier.
type ShirudoVerifierConfig struct {
	Bin                string
	AKName             string
	AKNames            map[string]string
	AllowUnpinnedAK    bool
	AllowRuntimeEvents bool
	ExpectConfigRoot   string
	ExpectConfigPCR    string
}

// ShirudoVerifier invokes `shirudo attest verify` to verify attestation evidence.
type ShirudoVerifier struct {
	cfg ShirudoVerifierConfig
}

// ShirudoVerifyRequest holds per-invocation verification parameters.
type ShirudoVerifyRequest struct {
	NodeID           string
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
	if len(cfg.AKNames) > 0 {
		copied := make(map[string]string, len(cfg.AKNames))
		for k, val := range cfg.AKNames {
			k = strings.TrimSpace(k)
			val = strings.TrimSpace(val)
			if k != "" && val != "" {
				copied[k] = val
			}
		}
		cfg.AKNames = copied
	}
	if cfg.ExpectConfigRoot == "" && cfg.ExpectConfigPCR == "" {
		log.Printf("WARNING: shirudo verifier configured without SHIRUDO_EXPECT_CONFIG_ROOT or SHIRUDO_EXPECT_CONFIG_PCR; config integrity is not pinned")
	}
	if cfg.AllowUnpinnedAK {
		log.Printf("WARNING: shirudo verifier AllowUnpinnedAK is enabled (dev-only); untrusted evidence ak_name will be used when no pinned AK is configured")
	}
	return &ShirudoVerifier{cfg: cfg}
}

// ShirudoVerifierConfigFromEnv parses Shirudo verifier settings from environment variables.
func ShirudoVerifierConfigFromEnv() ShirudoVerifierConfig {
	akNames := map[string]string{}
	if mapFile := strings.TrimSpace(os.Getenv("SHIRUDO_AK_MAP_FILE")); mapFile != "" {
		if data, err := os.ReadFile(mapFile); err != nil {
			log.Printf("shirudo verifier: failed to read SHIRUDO_AK_MAP_FILE %q: %v", mapFile, err)
		} else {
			var parsed map[string]string
			if err := json.Unmarshal(data, &parsed); err != nil {
				log.Printf("shirudo verifier: failed to parse SHIRUDO_AK_MAP_FILE %q: %v", mapFile, err)
			} else {
				for k, v := range parsed {
					k = strings.TrimSpace(k)
					v = strings.TrimSpace(v)
					if k != "" && v != "" {
						akNames[k] = v
					}
				}
			}
		}
	}
	if rawMap := strings.TrimSpace(os.Getenv("SHIRUDO_AK_NAMES")); rawMap != "" {
		for k, v := range parseAKNamesEnv(rawMap) {
			akNames[k] = v
		}
	}
	if len(akNames) == 0 {
		akNames = nil
	}

	return ShirudoVerifierConfig{
		Bin:                strings.TrimSpace(os.Getenv("SHIRUDO_BIN")),
		AKName:             strings.TrimSpace(os.Getenv("SHIRUDO_AK_NAME")),
		AKNames:            akNames,
		AllowUnpinnedAK:    parseEnvBool(os.Getenv("SHIRUDO_ALLOW_UNPINNED_AK"), false),
		AllowRuntimeEvents: parseEnvBool(os.Getenv("SHIRUDO_ALLOW_RUNTIME_EVENTS"), true),
		ExpectConfigRoot:   strings.TrimSpace(os.Getenv("SHIRUDO_EXPECT_CONFIG_ROOT")),
		ExpectConfigPCR:    strings.TrimSpace(os.Getenv("SHIRUDO_EXPECT_CONFIG_PCR")),
	}
}

// NewShirudoVerifierFromEnv constructs a ShirudoVerifier when SHIRUDO_BIN is set.
// Returns nil when SHIRUDO_BIN is empty so callers preserve mock verification behavior.
func NewShirudoVerifierFromEnv() *ShirudoVerifier {
	cfg := ShirudoVerifierConfigFromEnv()
	if cfg.Bin == "" {
		return nil
	}
	return NewShirudoVerifier(cfg)
}

func parseAKNamesEnv(raw string) map[string]string {
	out := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func parseEnvBool(val string, def bool) bool {
	s := strings.TrimSpace(val)
	if s == "" {
		return def
	}
	switch strings.ToLower(s) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	default:
		return def
	}
}

func (v *ShirudoVerifier) resolveAKName(req ShirudoVerifyRequest) (string, error) {
	if ak := strings.TrimSpace(req.AKName); ak != "" {
		return ak, nil
	}
	if req.NodeID != "" && len(v.cfg.AKNames) > 0 {
		if ak := strings.TrimSpace(v.cfg.AKNames[req.NodeID]); ak != "" {
			return ak, nil
		}
	}
	if ak := strings.TrimSpace(v.cfg.AKName); ak != "" {
		return ak, nil
	}
	if v.cfg.AllowUnpinnedAK {
		ak := strings.TrimSpace(extractAKName(req.Evidence))
		if ak == "" {
			return "", fmt.Errorf("no AK name found in evidence for node %q", req.NodeID)
		}
		return ak, nil
	}
	return "", fmt.Errorf("no pinned AK configured for node %q", req.NodeID)
}

// Verify writes req.Evidence to a 0600 temp file, invokes `shirudo attest verify`,
// and parses the JSON verdict.
func (v *ShirudoVerifier) Verify(ctx context.Context, req ShirudoVerifyRequest) (*ShirudoVerdict, error) {
	if v == nil || strings.TrimSpace(v.cfg.Bin) == "" {
		return nil, fmt.Errorf("shirudo verifier binary not configured")
	}

	if !verifierNonceHexRe.MatchString(req.Nonce) {
		return nil, fmt.Errorf("invalid hex nonce %q", req.Nonce)
	}

	akName, err := v.resolveAKName(req)
	if err != nil {
		return nil, err
	}
	if !verifierAKNameHexRe.MatchString(akName) {
		return nil, fmt.Errorf("invalid hex AK name %q", akName)
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
	}
	if v.cfg.AllowRuntimeEvents {
		args = append(args, "--allow-runtime-events")
	}
	args = append(args, "--json")
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
	res.Verified = true
	res.Pass = false
	verdict, err := v.Verify(ctx, ShirudoVerifyRequest{
		NodeID:   res.NodeID,
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
