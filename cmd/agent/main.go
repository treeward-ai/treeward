package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/treeward-ai/treeward/internal/runtime"
	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

const maxResponseBodyBytes = 4 << 20 // 4 MiB

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Node agent: poll connector desired state → verify signed tree (when pinned) →
// runtime.Apply → report → poll attest → runtime.Attest → submit.
// Backend selected via --runtime or TREEWARD_RUNTIME.
func main() {
	runtimeFlag := flag.String("runtime", env("TREEWARD_RUNTIME", "stub"), "runtime backend (stub|mock|shirudo)")
	flag.Parse()

	connector := env("TREEWARD_CONNECTOR_URL", "http://treeward-connector:8090")
	tokSrc := tokenSource{
		file:  strings.TrimSpace(os.Getenv("TREEWARD_AGENT_TOKEN_FILE")),
		fixed: os.Getenv("TREEWARD_LOCAL_TOKEN"),
	}
	kind := *runtimeFlag
	treePubKey, verifyWarning, err := resolveTreeVerifyConfig(kind, os.Getenv("TREEWARD_VERIFY_TREE"), os.Getenv("TREEWARD_TREE_PUBKEY"))
	if err != nil {
		log.Fatalf("tree verify config: %v", err)
	}
	if verifyWarning != "" {
		log.Printf("%s", verifyWarning)
	}

	var rt runtime.Runtime
	if strings.EqualFold(strings.TrimSpace(kind), "shirudo") {
		rt = runtime.NewShirudo(
			runtime.WithConnectorURL(connector),
			runtime.WithLocalToken(tokSrc.fixed),
			runtime.WithLocalTokenFile(tokSrc.file),
		)
	} else {
		rt, err = runtime.New(kind)
		if err != nil {
			log.Fatalf("runtime: %v", err)
		}
	}
	interval := 3 * time.Second

	nodes, err := rt.Inventory()
	if err != nil {
		log.Fatalf("inventory: %v", err)
	}
	log.Printf("agent starting runtime=%s nodes=%d verify_tree=%v token_file=%v → %s", kind, len(nodes), treePubKey != "", tokSrc.file != "", connector)

	var lastAttest string
	var lastVerifiedSeq int64
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		var loaded map[string][]string
		var applyErrs map[string][]string

		if tok, err := tokSrc.Token(); err != nil {
			log.Printf("desired token: %v", err)
		} else if desired, err := getDesired(connector, tok); err != nil {
			log.Printf("desired: %v", err)
		} else {
			loaded, applyErrs, lastVerifiedSeq, err = applyDesiredState(rt, treePubKey, lastVerifiedSeq, desired, nodes)
			if err != nil {
				log.Printf("%v", err)
			} else {
				for id, digests := range loaded {
					log.Printf("node=%s loaded=%v", id, digests)
				}
			}
		}

		nodes, err = rt.Inventory()
		if err != nil {
			log.Printf("inventory: %v", err)
			<-t.C
			continue
		}

		reports := make([]types.AgentReport, 0, len(nodes))
		for _, n := range nodes {
			digests := n.Loaded
			if loaded != nil {
				if d, ok := loaded[n.ID]; ok {
					digests = d
				}
			}
			n.Loaded = digests
			rep := types.AgentReport{Node: n, Loaded: digests}
			if applyErrs != nil {
				rep.Errors = applyErrs[n.ID]
			}
			reports = append(reports, rep)
		}

		if tok, err := tokSrc.Token(); err != nil {
			log.Printf("report token: %v", err)
		} else if err := postReport(connector, tok, reports); err != nil {
			log.Printf("report: %v", err)
		}

		if tok, err := tokSrc.Token(); err != nil {
			log.Printf("attest poll token: %v", err)
		} else if pending, err := getPendingAttest(connector, tok); err != nil {
			log.Printf("attest poll: %v", err)
		} else if pending != nil && pending.ID != lastAttest {
			loadedForAttest := map[string][]string{}
			for _, n := range nodes {
				loadedForAttest[n.ID] = append([]string{}, n.Loaded...)
			}
			quotes, err := rt.Attest(pending.Nonce, nodes, loadedForAttest)
			if err != nil {
				log.Printf("attest: %v", err)
			} else if tok, err := tokSrc.Token(); err != nil {
				log.Printf("attest submit token: %v", err)
			} else if err := postAttest(connector, tok, quotes); err != nil {
				log.Printf("attest submit: %v", err)
			} else {
				log.Printf("attest submitted campaign=%s nodes=%d", pending.ID, len(quotes))
				lastAttest = pending.ID
			}
		}

		<-t.C
	}
}

// tokenSource resolves the bearer token sent to the connector. When file is
// set (TREEWARD_AGENT_TOKEN_FILE), it is re-read on every call so rotated
// Kubernetes projected ServiceAccount tokens are picked up automatically.
type tokenSource struct {
	file  string
	fixed string
}

func (ts tokenSource) Token() (string, error) {
	if ts.file != "" {
		data, err := os.ReadFile(ts.file)
		if err != nil {
			return "", fmt.Errorf("read agent token file %q: %w", ts.file, err)
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", fmt.Errorf("agent token file %q is empty", ts.file)
		}
		return tok, nil
	}
	return ts.fixed, nil
}

func getDesired(connector, localToken string) (types.DesiredState, error) {
	var out types.DesiredState
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(connector, "/")+"/v1/local/desired", nil)
	if err != nil {
		return out, err
	}
	setBearerAuth(req, localToken)
	res, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	data, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return out, err
	}
	if res.StatusCode >= 300 {
		return out, &httpError{res.StatusCode, string(data)}
	}
	err = json.Unmarshal(data, &out)
	return out, err
}

func getPendingAttest(connector, localToken string) (*types.PendingAttest, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(connector, "/")+"/v1/local/attest", nil)
	if err != nil {
		return nil, err
	}
	setBearerAuth(req, localToken)
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, &httpError{res.StatusCode, string(data)}
	}
	var p types.PendingAttest
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func postReport(connector, localToken string, reports []types.AgentReport) error {
	return postJSON(strings.TrimRight(connector, "/")+"/v1/local/report", localToken, reports)
}

func postAttest(connector, localToken string, results []types.AttestResult) error {
	return postJSON(strings.TrimRight(connector, "/")+"/v1/local/attest", localToken, results)
}

func postJSON(url, localToken string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setBearerAuth(req, localToken)
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		data, err := readBodyBounded(res.Body, maxResponseBodyBytes)
		if err != nil {
			return &httpError{res.StatusCode, err.Error()}
		}
		return &httpError{res.StatusCode, string(data)}
	}
	return nil
}

func readBodyBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds %d byte limit", limit)
	}
	return data, nil
}

func setBearerAuth(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return e.body }

func resolveTreeVerifyConfig(runtimeKind, verifyEnv, pubKeyHex string) (string, string, error) {
	verifyEnv = strings.TrimSpace(verifyEnv)
	pubKeyHex = strings.TrimSpace(pubKeyHex)

	var verifyTree bool
	var explicitDisable bool
	switch {
	case verifyEnv == "":
		verifyTree = strings.EqualFold(strings.TrimSpace(runtimeKind), "shirudo")
	case verifyEnv == "1" || strings.EqualFold(verifyEnv, "true"):
		verifyTree = true
	case verifyEnv == "0" || strings.EqualFold(verifyEnv, "false"):
		verifyTree = false
		explicitDisable = true
	default:
		return "", "", fmt.Errorf("invalid TREEWARD_VERIFY_TREE value %q (expected 1, true, 0, or false)", verifyEnv)
	}

	if explicitDisable {
		warn := fmt.Sprintf("WARNING: TREEWARD_VERIFY_TREE=%s disables signed tree verification for runtime=%s; agent will trust unsigned desired.Nodes", verifyEnv, runtimeKind)
		return "", warn, nil
	}

	if verifyTree && pubKeyHex == "" {
		return "", "", fmt.Errorf("tree verification is enabled for runtime=%s but TREEWARD_TREE_PUBKEY is empty (obtain treePubKey from GET /v1/desired and pin it out-of-band, or set TREEWARD_VERIFY_TREE=0 to disable)", runtimeKind)
	}
	if pubKeyHex != "" {
		if _, err := signer.ParsePublicKey(pubKeyHex); err != nil {
			return "", "", fmt.Errorf("invalid TREEWARD_TREE_PUBKEY: %w", err)
		}
	}
	return pubKeyHex, "", nil
}

// verifyAndResolveDesired verifies the full Ed25519 hash-chained TreeOp log,
// enforces monotonic TreeSeq >= lastSeq to prevent rollback/truncation, and
// locally replays desired digests for each node owned by this agent—completely
// ignoring the server/connector's unsigned desired.Nodes map.
func verifyAndResolveDesired(pubKeyHex string, lastSeq int64, desired types.DesiredState, nodes []types.Node) (types.DesiredState, int64, error) {
	if desired.TreeSeq != int64(len(desired.Ops)) {
		return types.DesiredState{}, lastSeq, fmt.Errorf("desired treeSeq %d does not match ops length %d", desired.TreeSeq, len(desired.Ops))
	}
	if err := signer.VerifyTreeChainFrom(pubKeyHex, desired.Ops, lastSeq); err != nil {
		return types.DesiredState{}, lastSeq, err
	}
	verifiedNodes := make(map[string][]string, len(nodes))
	for _, n := range nodes {
		verifiedNodes[n.ID] = signer.ReplayDesiredForNode(desired.Ops, n.Labels)
	}
	resolved := types.DesiredState{
		TreeSeq:    desired.TreeSeq,
		TreePubKey: pubKeyHex,
		Ops:        desired.Ops,
		Nodes:      verifiedNodes,
	}
	return resolved, desired.TreeSeq, nil
}

func applyDesiredState(rt runtime.Runtime, pubKeyHex string, lastSeq int64, desired types.DesiredState, nodes []types.Node) (map[string][]string, map[string][]string, int64, error) {
	toApply := desired
	nextSeq := lastSeq
	if pubKeyHex != "" {
		var err error
		toApply, nextSeq, err = verifyAndResolveDesired(pubKeyHex, lastSeq, desired, nodes)
		if err != nil {
			return nil, nil, lastSeq, fmt.Errorf("tree verify failed (skipping apply): %w", err)
		}
	}
	loaded, applyErrs, err := rt.Apply(toApply)
	if err != nil {
		return nil, nil, nextSeq, fmt.Errorf("apply: %w", err)
	}
	return loaded, applyErrs, nextSeq, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
