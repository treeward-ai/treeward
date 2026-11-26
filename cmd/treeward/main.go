package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	api := env("TREEWARD_API_URL", "http://127.0.0.1:8080")
	switch os.Args[1] {
	case "nodes":
		getPrint(api + "/v1/nodes")
	case "artifacts":
		getPrint(api + "/v1/artifacts")
	case "bindings":
		getPrint(api + "/v1/bindings")
	case "tree":
		getPrint(api + "/v1/tree")
	case "audit":
		getPrint(api + "/v1/audit")
	case "create-artifact":
		body, err := parseCreateArtifactArgs(os.Args[2:])
		if err != nil {
			fatal(err)
		}
		postPrint(api+"/v1/artifacts", body)
	case "create-binding":
		digest := mustArg(2, "digest required")
		body := types.Binding{
			ArtifactDigest: digest,
			Selector:       types.Selector{Labels: map[string]string{}},
			TreeRef:        "default",
		}
		postPrint(api+"/v1/bindings", body)
	case "approve":
		postPrint(api+"/v1/bindings/"+mustArg(2, "binding id")+"/approve", types.ApproveRequest{Actor: arg(3, "damian")})
	case "canary":
		postPrint(api+"/v1/bindings/"+mustArg(2, "binding id")+"/canary", types.ApproveRequest{Actor: arg(3, "damian")})
	case "promote":
		postPrint(api+"/v1/bindings/"+mustArg(2, "binding id")+"/promote", types.ApproveRequest{Actor: arg(3, "damian")})
	case "revert":
		postPrint(api+"/v1/bindings/"+mustArg(2, "binding id")+"/revert", types.ApproveRequest{Actor: arg(3, "damian")})
	case "attest":
		runAttest(api)
	case "demo":
		runDemo(api)
	case "token":
		runToken(api)
	default:
		usage()
		os.Exit(2)
	}
}

func runToken(api string) {
	if len(os.Args) < 3 {
		fatal(fmt.Errorf("usage: treeward token create <name> | list | revoke <id>"))
	}
	switch os.Args[2] {
	case "create":
		name := mustArg(3, "token name required")
		bootstrap := env("TREEWARD_BOOTSTRAP_TOKEN", "dev-bootstrap")
		var raw json.RawMessage
		doRequest(http.MethodPost, api+"/v1/tokens", types.CreateTokenRequest{Name: name}, bootstrap, &raw)
		var buf bytes.Buffer
		_ = json.Indent(&buf, raw, "", "  ")
		fmt.Println(buf.String())
	case "list":
		getPrint(api + "/v1/tokens")
	case "revoke":
		id := mustArg(3, "token id required")
		var raw json.RawMessage
		doRequest(http.MethodDelete, api+"/v1/tokens/"+id, nil, os.Getenv("TREEWARD_TOKEN"), &raw)
		var buf bytes.Buffer
		_ = json.Indent(&buf, raw, "", "  ")
		fmt.Println(buf.String())
	default:
		fatal(fmt.Errorf("unknown token subcommand %q (expected create|list|revoke)", os.Args[2]))
	}
}

func runAttest(api string) {
	fmt.Println("== start attest campaign")
	var camp types.AttestCampaign
	mustPost(api+"/v1/attest/campaigns", map[string]any{}, &camp)
	fmt.Printf("campaign id=%s nonce=%s status=%s\n", camp.ID, camp.Nonce, camp.Status)
	waitAttest(api, camp.ID)
	getPrint(api + "/v1/attest/campaigns/" + camp.ID)
	printNodes(api)
}

func runDemo(api string) {
	fmt.Println("== create artifact")
	var art types.Artifact
	mustPost(api+"/v1/artifacts", types.Artifact{Name: "java4shell-demo", Type: "java", Fixes: []string{"CVE-2021-44228"}}, &art)
	fmt.Printf("artifact digest=%s\n", art.Digest)

	fmt.Println("== create binding")
	var bind types.Binding
	mustPost(api+"/v1/bindings", types.Binding{
		ArtifactDigest: art.Digest,
		Selector:       types.Selector{Labels: map[string]string{}},
		TreeRef:        "default",
	}, &bind)
	fmt.Printf("binding id=%s status=%s\n", bind.ID, bind.Status)

	fmt.Println("== approve")
	mustPost(api+"/v1/bindings/"+bind.ID+"/approve", types.ApproveRequest{Actor: "damian"}, &bind)
	fmt.Printf("status=%s by=%s\n", bind.Status, bind.ApprovedBy)

	fmt.Println("== canary (wait for agents)")
	mustPost(api+"/v1/bindings/"+bind.ID+"/canary", types.ApproveRequest{Actor: "damian"}, &bind)
	waitLoaded(api, art.Digest, true)
	printNodes(api)

	fmt.Println("== promote")
	mustPost(api+"/v1/bindings/"+bind.ID+"/promote", types.ApproveRequest{Actor: "damian"}, &bind)
	waitLoaded(api, art.Digest, false)
	printNodes(api)

	fmt.Println("== attest (stub TPM quotes)")
	var camp types.AttestCampaign
	mustPost(api+"/v1/attest/campaigns", map[string]any{}, &camp)
	fmt.Printf("campaign id=%s nonce=%s\n", camp.ID, camp.Nonce)
	waitAttest(api, camp.ID)
	getPrint(api + "/v1/attest/campaigns/" + camp.ID)
	printNodes(api)

	fmt.Println("== revert")
	mustPost(api+"/v1/bindings/"+bind.ID+"/revert", types.ApproveRequest{Actor: "damian"}, &bind)
	time.Sleep(6 * time.Second)
	printNodes(api)

	fmt.Println("== audit")
	getPrint(api + "/v1/audit")
}

func waitLoaded(api, digest string, canaryOnly bool) {
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var nodes []types.Node
		mustGet(api+"/v1/nodes", &nodes)
		if len(nodes) == 0 {
			time.Sleep(2 * time.Second)
			continue
		}
		canaryOK, othersEmpty, allOK := true, true, true
		for _, n := range nodes {
			has := contains(n.Loaded, digest)
			isCanary := n.Labels[types.LabelRollout] == types.RolloutCanary
			if isCanary && !has {
				canaryOK = false
			}
			if !isCanary && has {
				othersEmpty = false
			}
			if !has {
				allOK = false
			}
		}
		if canaryOnly && canaryOK && othersEmpty {
			fmt.Println("canary loaded on canary nodes only")
			return
		}
		if !canaryOnly && allOK {
			fmt.Println("all nodes loaded")
			return
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Println("warning: timed out waiting for desired load state")
}

func waitAttest(api, campaignID string) {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var camp types.AttestCampaign
		mustGet(api+"/v1/attest/campaigns/"+campaignID, &camp)
		if camp.Status == "complete" {
			pass, fail := 0, 0
			for _, r := range camp.Results {
				if r.Pass {
					pass++
				} else {
					fail++
				}
			}
			fmt.Printf("attest complete results=%d pass=%d fail=%d\n", len(camp.Results), pass, fail)
			return
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Println("warning: timed out waiting for attest campaign")
}

func printNodes(api string) {
	getPrint(api + "/v1/nodes")
}

func usage() {
	fmt.Fprintf(os.Stderr, `treeward — local MVP CLI

Usage:
  treeward nodes|artifacts|bindings|tree|audit
  treeward create-artifact [name] [--digest <value>] [--type <bpf|java|...>]
  treeward create-binding <digest>
  treeward approve|canary|promote|revert <binding-id> [actor]
  treeward attest
  treeward demo
  treeward token create <name>
  treeward token list
  treeward token revoke <id>

Env:
  TREEWARD_API_URL         (default http://127.0.0.1:8080)
  TREEWARD_TOKEN           (operator bearer token for admin routes)
  TREEWARD_BOOTSTRAP_TOKEN (bootstrap token for 'token create', default dev-bootstrap)

Pause-on-hard-fail (binding → paused; no auto-revert; promote rejected):
  Attest: set agent TREEWARD_ATTEST_FAIL=<canary-node-id> (e.g. kind-worker-canary),
          canary a binding, then treeward attest — audit action=pause.
  Load:   set agent TREEWARD_LOAD_FAIL=1, canary a binding — agent reports load errors
          for the digest; control plane pauses the canary binding.
`)
}

func getPrint(url string) {
	var raw json.RawMessage
	mustGet(url, &raw)
	var buf bytes.Buffer
	_ = json.Indent(&buf, raw, "", "  ")
	fmt.Println(buf.String())
}

func postPrint(url string, body any) {
	var raw json.RawMessage
	mustPost(url, body, &raw)
	var buf bytes.Buffer
	_ = json.Indent(&buf, raw, "", "  ")
	fmt.Println(buf.String())
}

func mustGet(url string, out any) {
	doRequest(http.MethodGet, url, nil, os.Getenv("TREEWARD_TOKEN"), out)
}

func mustPost(url string, body any, out any) {
	doRequest(http.MethodPost, url, body, os.Getenv("TREEWARD_TOKEN"), out)
}

func doRequest(method, url string, body any, bearer string, out any) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			fatal(err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		fatal(fmt.Errorf("%s: %s", res.Status, data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			fatal(err)
		}
	}
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

func arg(i int, def string) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return def
}

func mustArg(i int, msg string) string {
	if len(os.Args) <= i || strings.TrimSpace(os.Args[i]) == "" {
		fatal(fmt.Errorf("%s", msg))
	}
	return os.Args[i]
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func parseCreateArtifactArgs(args []string) (types.Artifact, error) {
	art := types.Artifact{
		Name:  "java4shell-demo",
		Type:  "java",
		Fixes: []string{"CVE-2021-44228"},
	}
	nameSet := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--digest" || a == "-digest":
			if i+1 >= len(args) {
				return types.Artifact{}, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			art.Digest = args[i]
		case strings.HasPrefix(a, "--digest="):
			art.Digest = strings.TrimPrefix(a, "--digest=")
		case strings.HasPrefix(a, "-digest="):
			art.Digest = strings.TrimPrefix(a, "-digest=")
		case a == "--type" || a == "-type":
			if i+1 >= len(args) {
				return types.Artifact{}, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			art.Type = args[i]
		case strings.HasPrefix(a, "--type="):
			art.Type = strings.TrimPrefix(a, "--type=")
		case strings.HasPrefix(a, "-type="):
			art.Type = strings.TrimPrefix(a, "-type=")
		case strings.HasPrefix(a, "-"):
			return types.Artifact{}, fmt.Errorf("unknown flag: %s", a)
		default:
			if !nameSet {
				art.Name = a
				nameSet = true
			} else {
				return types.Artifact{}, fmt.Errorf("unexpected argument: %s", a)
			}
		}
	}
	return art, nil
}
