package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/treeward-ai/treeward/internal/runtime"
	"github.com/treeward-ai/treeward/internal/types"
)

// Node agent: poll connector desired state → runtime.Apply → report →
// poll attest → runtime.Attest → submit. Backend selected via TREEWARD_RUNTIME.
func main() {
	connector := env("TREEWARD_CONNECTOR_URL", "http://treeward-connector:8090")
	rt, err := runtime.NewFromEnv()
	if err != nil {
		log.Fatalf("runtime: %v", err)
	}
	kind := env("TREEWARD_RUNTIME", "stub")
	interval := 3 * time.Second

	nodes, err := rt.Inventory()
	if err != nil {
		log.Fatalf("inventory: %v", err)
	}
	log.Printf("agent starting runtime=%s nodes=%d → %s", kind, len(nodes), connector)

	var lastAttest string
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		var loaded map[string][]string
		var applyErrs map[string][]string

		desired, err := getDesired(connector)
		if err != nil {
			log.Printf("desired: %v", err)
		} else {
			loaded, applyErrs, err = rt.Apply(desired)
			if err != nil {
				log.Printf("apply: %v", err)
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

		if err := postReport(connector, reports); err != nil {
			log.Printf("report: %v", err)
		}

		if pending, err := getPendingAttest(connector); err != nil {
			log.Printf("attest poll: %v", err)
		} else if pending != nil && pending.ID != lastAttest {
			loadedForAttest := map[string][]string{}
			for _, n := range nodes {
				loadedForAttest[n.ID] = append([]string{}, n.Loaded...)
			}
			quotes, err := rt.Attest(pending.Nonce, nodes, loadedForAttest)
			if err != nil {
				log.Printf("attest: %v", err)
			} else if err := postAttest(connector, quotes); err != nil {
				log.Printf("attest submit: %v", err)
			} else {
				log.Printf("attest submitted campaign=%s nodes=%d", pending.ID, len(quotes))
				lastAttest = pending.ID
			}
		}

		<-t.C
	}
}

func getDesired(connector string) (types.DesiredState, error) {
	var out types.DesiredState
	res, err := http.Get(strings.TrimRight(connector, "/") + "/v1/local/desired")
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return out, &httpError{res.StatusCode, string(data)}
	}
	err = json.Unmarshal(data, &out)
	return out, err
}

func getPendingAttest(connector string) (*types.PendingAttest, error) {
	res, err := http.Get(strings.TrimRight(connector, "/") + "/v1/local/attest")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, &httpError{res.StatusCode, string(data)}
	}
	var p types.PendingAttest
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func postReport(connector string, reports []types.AgentReport) error {
	return postJSON(strings.TrimRight(connector, "/")+"/v1/local/report", reports)
}

func postAttest(connector string, results []types.AttestResult) error {
	return postJSON(strings.TrimRight(connector, "/")+"/v1/local/attest", results)
}

func postJSON(url string, body any) error {
	b, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		data, _ := io.ReadAll(res.Body)
		return &httpError{res.StatusCode, string(data)}
	}
	return nil
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return e.body }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
