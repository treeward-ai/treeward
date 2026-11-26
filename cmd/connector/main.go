package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

const maxLocalBodyBytes = 4 << 20 // 4 MiB

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Connector sits between node agents and the Treeward API.
// Agents POST inventory/status here; connector enrolls and phones home.

type agentState struct {
	Node   types.Node
	Loaded []string
	Errors []string
}

func main() {
	apiURL := env("TREEWARD_API_URL", "http://treeward-api:8080")
	enrollToken := os.Getenv("TREEWARD_ENROLL_TOKEN")
	if enrollToken == "" {
		log.Fatal("TREEWARD_ENROLL_TOKEN is required")
	}
	cluster := env("TREEWARD_CLUSTER", "kind-treeward")
	listen := connectorListenAddr()
	localToken := os.Getenv("TREEWARD_LOCAL_TOKEN")
	localAuthDisabled := strings.EqualFold(os.Getenv("TREEWARD_LOCAL_AUTH"), "off")
	if localToken == "" {
		if !localAuthDisabled {
			log.Fatal("TREEWARD_LOCAL_TOKEN is required (set TREEWARD_LOCAL_AUTH=off for local dev only)")
		}
		log.Printf("WARNING: TREEWARD_LOCAL_AUTH=off and TREEWARD_LOCAL_TOKEN is empty; local connector endpoints are unauthenticated (local dev only)")
	}
	interval := 5 * time.Second

	creds := newCredManager(apiURL, enrollToken, cluster, enroll)
	if err := creds.enrollWithRetry(30); err != nil {
		log.Fatalf("enroll failed: %v", err)
	}
	_, clusterID := creds.snapshot()
	log.Printf("enrolled connector cluster=%s", clusterID)

	var mu sync.Mutex
	agents := map[string]*agentState{}
	var pending *types.PendingAttest
	quotes := map[string]types.AttestResult{} // nodeID -> quote for current campaign
	submitted := map[string]bool{}            // campaignID already pushed upstream

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /v1/local/report", requireLocalAuth(localToken, localAuthDisabled, func(w http.ResponseWriter, r *http.Request) {
		var reports []types.AgentReport
		if !decodeLocalJSON(w, r, &reports) {
			return
		}
		_, cid := creds.snapshot()
		mu.Lock()
		for _, rep := range reports {
			rep.Node.ClusterID = cid
			agents[rep.Node.ID] = &agentState{Node: rep.Node, Loaded: rep.Loaded, Errors: append([]string{}, rep.Errors...)}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	mux.HandleFunc("GET /v1/local/desired", requireLocalAuth(localToken, localAuthDisabled, func(w http.ResponseWriter, _ *http.Request) {
		tok, _ := creds.snapshot()
		desired, err := getDesired(apiURL, tok)
		if err != nil {
			if isUnauthorized(err) {
				if rerr := creds.reenroll(tok); rerr != nil {
					log.Printf("re-enroll: %v", rerr)
				} else {
					tok, _ = creds.snapshot()
					desired, err = getDesired(apiURL, tok)
				}
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		writeJSON(w, desired)
	}))

	mux.HandleFunc("GET /v1/local/attest", requireLocalAuth(localToken, localAuthDisabled, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		p := pending
		mu.Unlock()
		if p == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, p)
	}))

	mux.HandleFunc("POST /v1/local/attest", requireLocalAuth(localToken, localAuthDisabled, func(w http.ResponseWriter, r *http.Request) {
		var results []types.AttestResult
		if !decodeLocalJSON(w, r, &results) {
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
			tok, _ := creds.snapshot()
			if err := postJSON(apiURL+"/v1/attest/campaigns/"+campID+"/results", tok, batch, nil); err != nil {
				if isUnauthorized(err) {
					if rerr := creds.reenroll(tok); rerr != nil {
						log.Printf("re-enroll: %v", rerr)
					} else {
						tok, _ = creds.snapshot()
						err = postJSON(apiURL+"/v1/attest/campaigns/"+campID+"/results", tok, batch, nil)
					}
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
	}))

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			tok, cid := creds.snapshot()
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
						if rerr := creds.reenroll(tok); rerr != nil {
							log.Printf("re-enroll: %v", rerr)
						} else {
							tok, cid = creds.snapshot()
							err = upsertInventory(apiURL, tok, cid, nodes)
						}
					}
					if err != nil {
						log.Printf("inventory upsert: %v", err)
					}
				}
				if err := postJSON(apiURL+"/v1/agents/report", tok, reports, nil); err != nil {
					if isUnauthorized(err) {
						if rerr := creds.reenroll(tok); rerr != nil {
							log.Printf("re-enroll: %v", rerr)
						} else {
							tok, _ = creds.snapshot()
							err = postJSON(apiURL+"/v1/agents/report", tok, reports, nil)
						}
					}
					if err != nil {
						log.Printf("agent report: %v", err)
					}
				}
			}

			p, err := getActiveAttest(apiURL, tok)
			if err != nil {
				if isUnauthorized(err) {
					if rerr := creds.reenroll(tok); rerr != nil {
						log.Printf("re-enroll: %v", rerr)
					} else {
						tok, _ = creds.snapshot()
						p, err = getActiveAttest(apiURL, tok)
					}
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

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	tlsCert := os.Getenv("TREEWARD_TLS_CERT")
	tlsKey := os.Getenv("TREEWARD_TLS_KEY")
	if (tlsCert == "") != (tlsKey == "") {
		log.Fatal("TREEWARD_TLS_CERT and TREEWARD_TLS_KEY must both be set to enable TLS")
	}
	if tlsCert != "" {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		log.Printf("connector listening on %s (TLS 1.3) → %s", listen, apiURL)
		log.Fatal(httpSrv.ListenAndServeTLS(tlsCert, tlsKey))
	}

	log.Printf("connector listening on %s → %s", listen, apiURL)
	log.Fatal(httpSrv.ListenAndServe())
}

type credManager struct {
	mu             sync.Mutex
	apiURL         string
	enrollToken    string
	cluster        string
	token          string
	clusterID      string
	lastAttempt    time.Time
	backoff        time.Duration
	enrollRejected bool
	enrollFn       func(apiURL, enrollToken, cluster string) (string, string, error)
	nowFn          func() time.Time
	sleepFn        func(time.Duration)
}

func newCredManager(apiURL, enrollToken, cluster string, enrollFn func(string, string, string) (string, string, error)) *credManager {
	return &credManager{
		apiURL:      apiURL,
		enrollToken: enrollToken,
		cluster:     cluster,
		enrollFn:    enrollFn,
		nowFn:       time.Now,
		sleepFn:     time.Sleep,
	}
}

func (c *credManager) snapshot() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token, c.clusterID
}

func (c *credManager) enrollWithRetry(maxAttempts int) error {
	delay := time.Second
	for i := 0; i < maxAttempts; i++ {
		tok, cid, err := c.enrollFn(c.apiURL, c.enrollToken, c.cluster)
		if err == nil {
			c.mu.Lock()
			c.token = tok
			c.clusterID = cid
			c.backoff = 0
			c.enrollRejected = false
			c.mu.Unlock()
			return nil
		}
		if isAuthRejected(err) {
			c.mu.Lock()
			c.enrollRejected = true
			c.mu.Unlock()
			return fmt.Errorf("enroll token rejected: %w", err)
		}
		log.Printf("enroll retry %d/%d: %v", i+1, maxAttempts, err)
		c.sleepFn(delay)
		if delay < 10*time.Second {
			delay *= 2
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
		}
	}
	return errors.New("enroll failed after retries")
}

func (c *credManager) reenroll(failedToken string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if failedToken != "" && c.token != "" && c.token != failedToken {
		return nil
	}
	// Clear stale token so subsequent calls don't keep reusing it.
	c.token = ""

	if c.enrollRejected {
		return errors.New("re-enroll halted: enroll token rejected")
	}

	now := c.nowFn()
	if !c.lastAttempt.IsZero() && c.backoff > 0 && now.Sub(c.lastAttempt) < c.backoff {
		return fmt.Errorf("re-enroll backed off (%s remaining)", (c.backoff - now.Sub(c.lastAttempt)).Round(time.Millisecond))
	}

	c.lastAttempt = now
	tok, cid, err := c.enrollFn(c.apiURL, c.enrollToken, c.cluster)
	if err != nil {
		if isAuthRejected(err) {
			c.enrollRejected = true
			return fmt.Errorf("re-enroll halted: enroll token rejected: %w", err)
		}
		if c.backoff == 0 {
			c.backoff = time.Second
		} else {
			c.backoff *= 2
			if c.backoff > 30*time.Second {
				c.backoff = 30 * time.Second
			}
		}
		return err
	}

	c.token = tok
	c.clusterID = cid
	c.backoff = 0
	c.enrollRejected = false
	log.Printf("re-enrolled connector cluster=%s", cid)
	return nil
}

func requireLocalAuth(expectedToken string, authDisabled bool, next http.HandlerFunc) http.HandlerFunc {
	if authDisabled && expectedToken == "" {
		return next
	}
	expected := []byte(expectedToken)
	return func(w http.ResponseWriter, r *http.Request) {
		if len(expected) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got := []byte(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare(got, expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func enroll(apiURL, enrollToken, cluster string) (token, clusterID string, err error) {
	var resp types.EnrollResponse
	err = postJSON(apiURL+"/v1/connectors/enroll", "", types.EnrollRequest{
		BootstrapToken: enrollToken,
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
	res, err := httpClient.Do(req)
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
	res, err := httpClient.Do(req)
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
	res, err := httpClient.Do(req)
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
	var he *httpError
	if errors.As(err, &he) {
		return he.code == http.StatusUnauthorized || strings.Contains(he.body, "unauthorized")
	}
	return strings.Contains(err.Error(), "unauthorized")
}

func isAuthRejected(err error) bool {
	if err == nil {
		return false
	}
	var he *httpError
	if errors.As(err, &he) {
		return he.code == http.StatusUnauthorized || he.code == http.StatusForbidden
	}
	return false
}

func decodeLocalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxLocalBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func connectorListenAddr() string {
	return env("TREEWARD_CONNECTOR_ADDR", "127.0.0.1:8090")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
