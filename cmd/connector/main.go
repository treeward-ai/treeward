package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

// Connector sits between node agents and the Treeward API.
// Agents POST inventory/status here; connector enrolls and phones home.

type agentState struct {
	Node   types.Node
	Loaded []string
	Errors []string
}

func main() {
	apiURL := env("TREEWARD_API_URL", "http://treeward-api:8080")
	bootstrap := env("TREEWARD_BOOTSTRAP_TOKEN", "dev-bootstrap")
	cluster := env("TREEWARD_CLUSTER", "kind-treeward")
	listen := env("TREEWARD_CONNECTOR_ADDR", ":8090")
	interval := 5 * time.Second

	var credMu sync.Mutex
	token, clusterID := enrollWithRetry(apiURL, bootstrap, cluster)
	log.Printf("enrolled connector cluster=%s", clusterID)

	reenrol := func() {
		credMu.Lock()
		defer credMu.Unlock()
		tok, cid := enrollWithRetry(apiURL, bootstrap, cluster)
		token, clusterID = tok, cid
		log.Printf("re-enrolled connector cluster=%s", clusterID)
	}
	tokenSnapshot := func() (string, string) {
		credMu.Lock()
		defer credMu.Unlock()
		return token, clusterID
	}

	var mu sync.Mutex
	agents := map[string]*agentState{}
	var pending *types.PendingAttest
	quotes := map[string]types.AttestResult{} // nodeID -> quote for current campaign
	submitted := map[string]bool{}           // campaignID already pushed upstream

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /v1/local/report", func(w http.ResponseWriter, r *http.Request) {
		var reports []types.AgentReport
		if err := json.NewDecoder(r.Body).Decode(&reports); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, cid := tokenSnapshot()
		mu.Lock()
		for _, rep := range reports {
			rep.Node.ClusterID = cid
			agents[rep.Node.ID] = &agentState{Node: rep.Node, Loaded: rep.Loaded, Errors: append([]string{}, rep.Errors...)}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /v1/local/desired", func(w http.ResponseWriter, _ *http.Request) {
		tok, _ := tokenSnapshot()
		desired, err := getDesired(apiURL, tok)
		if err != nil {
			if isUnauthorized(err) {
				reenrol()
				tok, _ = tokenSnapshot()
				desired, err = getDesired(apiURL, tok)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		writeJSON(w, desired)
	})

	mux.HandleFunc("GET /v1/local/attest", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		p := pending
		mu.Unlock()
		if p == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, p)
	})

	mux.HandleFunc("POST /v1/local/attest", func(w http.ResponseWriter, r *http.Request) {
		var results []types.AttestResult
		if err := json.NewDecoder(r.Body).Decode(&results); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		if pending == nil {
			mu.Unlock()
			http.Error(w, "no active campaign", http.StatusConflict)
			return
		}
		campID := pending.ID
		for _, res := range results {
			res.Nonce = pending.Nonce
			quotes[res.NodeID] = res
		}
		ready := len(agents) > 0
		for id := range agents {
			if _, ok := quotes[id]; !ok {
				ready = false
				break
			}
		}
		batch := make([]types.AttestResult, 0, len(quotes))
		if ready {
			for _, q := range quotes {
				batch = append(batch, q)
			}
		}
		already := submitted[campID]
		mu.Unlock()

		if ready && !already {
			tok, _ := tokenSnapshot()
			if err := postJSON(apiURL+"/v1/attest/campaigns/"+campID+"/results", tok, batch, nil); err != nil {
				if isUnauthorized(err) {
					reenrol()
					tok, _ = tokenSnapshot()
					err = postJSON(apiURL+"/v1/attest/campaigns/"+campID+"/results", tok, batch, nil)
				}
				if err != nil {
					log.Printf("attest submit: %v", err)
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
			}
			mu.Lock()
			submitted[campID] = true
			pending = nil
			quotes = map[string]types.AttestResult{}
			mu.Unlock()
			log.Printf("attest campaign %s submitted (%d quotes)", campID, len(batch))
		}
		w.WriteHeader(http.StatusOK)
	})

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			tok, cid := tokenSnapshot()
			mu.Lock()
			nodes := make([]types.Node, 0, len(agents))
			reports := make([]types.AgentReport, 0, len(agents))
			for _, a := range agents {
				n := a.Node
				n.Loaded = a.Loaded
				n.ClusterID = cid
				nodes = append(nodes, n)
				reports = append(reports, types.AgentReport{
					Node:   n,
					Loaded: a.Loaded,
					Errors: append([]string{}, a.Errors...),
				})
			}
			mu.Unlock()
			if len(nodes) > 0 {
				if err := upsertInventory(apiURL, tok, cid, nodes); err != nil {
					if isUnauthorized(err) {
						reenrol()
						tok, cid = tokenSnapshot()
						err = upsertInventory(apiURL, tok, cid, nodes)
					}
					if err != nil {
						log.Printf("inventory upsert: %v", err)
					}
				}
				if err := postJSON(apiURL+"/v1/agents/report", tok, reports, nil); err != nil {
					if isUnauthorized(err) {
						reenrol()
						tok, _ = tokenSnapshot()
						err = postJSON(apiURL+"/v1/agents/report", tok, reports, nil)
					}
					if err != nil {
						log.Printf("agent report: %v", err)
					}
				}
			}

			p, err := getActiveAttest(apiURL, tok)
			if err != nil {
				if isUnauthorized(err) {
					reenrol()
					tok, _ = tokenSnapshot()
					p, err = getActiveAttest(apiURL, tok)
				}
				if err != nil {
					log.Printf("attest poll: %v", err)
					continue
				}
			}
			mu.Lock()
			if p == nil {
				pending = nil
			} else if submitted[p.ID] {
				pending = nil
			} else if pending == nil || pending.ID != p.ID {
				pending = p
				quotes = map[string]types.AttestResult{}
				log.Printf("attest campaign pending id=%s", p.ID)
			}
			mu.Unlock()
		}
	}()

	log.Printf("connector listening on %s → %s", listen, apiURL)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func enrollWithRetry(apiURL, bootstrap, cluster string) (token, clusterID string) {
	for i := 0; i < 30; i++ {
		tok, cid, err := enroll(apiURL, bootstrap, cluster)
		if err == nil {
			return tok, cid
		}
		log.Printf("enroll retry: %v", err)
		time.Sleep(2 * time.Second)
	}
	log.Fatal("enroll failed after retries")
	return "", ""
}

func enroll(apiURL, bootstrap, cluster string) (token, clusterID string, err error) {
	var resp types.EnrollResponse
	err = postJSON(apiURL+"/v1/connectors/enroll", "", types.EnrollRequest{
		BootstrapToken: bootstrap,
		ClusterName:    cluster,
	}, &resp)
	return resp.Token, resp.ClusterID, err
}

func getDesired(apiURL, token string) (types.DesiredState, error) {
	var out types.DesiredState
	err := getJSON(apiURL+"/v1/desired", token, &out)
	return out, err
}

func getActiveAttest(apiURL, token string) (*types.PendingAttest, error) {
	req, err := http.NewRequest(http.MethodGet, apiURL+"/v1/attest/active", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, &httpError{code: res.StatusCode, body: string(data)}
	}
	var p types.PendingAttest
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func upsertInventory(apiURL, token, cluster string, nodes []types.Node) error {
	return postJSON(apiURL+"/v1/inventory", token, types.InventoryUpsert{
		ClusterID: cluster,
		Nodes:     nodes,
	}, nil)
}

func postJSON(url, token string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return &httpError{code: res.StatusCode, body: string(data)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func getJSON(url, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return &httpError{code: res.StatusCode, body: string(data)}
	}
	return json.Unmarshal(data, out)
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return e.body }

func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	if he, ok := err.(*httpError); ok {
		return he.code == http.StatusUnauthorized || strings.Contains(he.body, "unauthorized")
	}
	return strings.Contains(err.Error(), "unauthorized")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
