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
		name := arg(2, "java4shell-demo")
		body := types.Artifact{Name: name, Type: "java", Fixes: []string{"CVE-2021-44228"}}
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
	default:
		usage()
		os.Exit(2)
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
  treeward create-artifact [name]
  treeward create-binding <digest>
  treeward approve|canary|promote|revert <binding-id> [actor]
  treeward attest
  treeward demo

Env: TREEWARD_API_URL (default http://127.0.0.1:8080)

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
	res, err := http.Get(url)
	if err != nil {
		fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		fatal(fmt.Errorf("%s: %s", res.Status, data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			fatal(err)
		}
	}
}

func mustPost(url string, body any, out any) {
	b, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", bytes.NewReader(b))
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
