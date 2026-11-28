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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/treeward-ai/treeward/internal/types"
)

const (
	maxLocalBodyBytes    = 4 << 20 // 4 MiB
	maxResponseBodyBytes = 4 << 20 // 4 MiB
	agentStaleTTL        = 5 * time.Minute
	maxTrackedAgents     = 4096
	maxSubmittedIDs      = 256
	submittedIDTTL       = 24 * time.Hour
)

const connectorUserAgent = "treeward-connector/0.1"

type userAgentTransport struct {
	base http.RoundTripper
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", connectorUserAgent)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

var httpClient = &http.Client{
	Timeout:       15 * time.Second,
	Transport:     userAgentTransport{},
	CheckRedirect: noRedirect,
}

// Connector sits between node agents and the Treeward API.
// Agents POST inventory/status here; connector enrolls and phones home.

type agentState struct {
	Node     types.Node
	Loaded   []string
	Errors   []string
	LastSeen time.Time
}

type connectorState struct {
	mu           sync.Mutex
	agents       map[string]*agentState
	pending      *types.PendingAttest
	quotes       map[string]types.AttestResult // nodeID -> quote for current campaign
	submitted    map[string]time.Time          // campaignID -> submittedAt
	inFlight     map[string]bool               // campaignID currently being submitted
	nowFn        func() time.Time
	staleTTL     time.Duration
	maxAgents    int
	maxSubmitted int
	submittedTTL time.Duration
}

func newConnectorState() *connectorState {
	return &connectorState{
		agents:       map[string]*agentState{},
		quotes:       map[string]types.AttestResult{},
		submitted:    map[string]time.Time{},
		inFlight:     map[string]bool{},
		nowFn:        time.Now,
		staleTTL:     agentStaleTTL,
		maxAgents:    maxTrackedAgents,
		maxSubmitted: maxSubmittedIDs,
		submittedTTL: submittedIDTTL,
	}
}

func (s *connectorState) evictStaleAgentsLocked(now time.Time) {
	if s.staleTTL <= 0 {
		return
	}
	for id, a := range s.agents {
		if now.Sub(a.LastSeen) > s.staleTTL {
			delete(s.agents, id)
		}
	}
}

func (s *connectorState) pruneSubmittedLocked(now time.Time) {
	if s.submittedTTL > 0 {
		for id, ts := range s.submitted {
			if now.Sub(ts) > s.submittedTTL {
				delete(s.submitted, id)
			}
		}
	}
	for s.maxSubmitted > 0 && len(s.submitted) > s.maxSubmitted {
		var oldestID string
		var oldestTS time.Time
		first := true
		for id, ts := range s.submitted {
			if first || ts.Before(oldestTS) {
				oldestID = id
				oldestTS = ts
				first = false
			}
		}
		delete(s.submitted, oldestID)
	}
}

func (s *connectorState) recordReports(cid string, reports []types.AgentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	s.evictStaleAgentsLocked(now)
	for _, rep := range reports {
		if _, exists := s.agents[rep.Node.ID]; !exists && s.maxAgents > 0 && len(s.agents) >= s.maxAgents {
			log.Printf("connector: tracked agents limit (%d) reached; ignoring report for node=%s", s.maxAgents, rep.Node.ID)
			continue
		}
		rep.Node.ClusterID = cid
		s.agents[rep.Node.ID] = &agentState{
			Node:     rep.Node,
			Loaded:   rep.Loaded,
			Errors:   append([]string{}, rep.Errors...),
			LastSeen: now,
		}
	}
}

func (s *connectorState) snapshotForSync(cid string) ([]types.Node, []types.AgentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	s.evictStaleAgentsLocked(now)
	s.pruneSubmittedLocked(now)
	nodes := make([]types.Node, 0, len(s.agents))
	reports := make([]types.AgentReport, 0, len(s.agents))
	for _, a := range s.agents {
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
	return nodes, reports
}

func (s *connectorState) getPending() *types.PendingAttest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

func (s *connectorState) setPending(p *types.PendingAttest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		s.pending = nil
		return
	}
	if _, already := s.submitted[p.ID]; already {
		s.pending = nil
		return
	}
	if s.pending == nil || s.pending.ID != p.ID {
		s.pending = p
		s.quotes = map[string]types.AttestResult{}
		log.Printf("attest campaign pending id=%s", p.ID)
	}
}

func (s *connectorState) recordAttestResults(results []types.AttestResult) (campID string, batch []types.AttestResult, shouldSubmit bool, hasPending bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return "", nil, false, false
	}
	now := s.nowFn()
	s.evictStaleAgentsLocked(now)
	campID = s.pending.ID
	for _, res := range results {
		res.Nonce = s.pending.Nonce
		s.quotes[res.NodeID] = res
	}
	ready := len(s.agents) > 0
	for id := range s.agents {
		if _, ok := s.quotes[id]; !ok {
			ready = false
			break
		}
	}
	_, already := s.submitted[campID]
	if ready && !already && !s.inFlight[campID] {
		s.inFlight[campID] = true
		batch = make([]types.AttestResult, 0, len(s.quotes))
		for _, q := range s.quotes {
			batch = append(batch, q)
		}
		return campID, batch, true, true
	}
	return campID, nil, false, true
}

func (s *connectorState) finishAttestSubmit(campID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, campID)
	if ok {
		now := s.nowFn()
		s.submitted[campID] = now
		s.pruneSubmittedLocked(now)
		if s.pending != nil && s.pending.ID == campID {
			s.pending = nil
			s.quotes = map[string]types.AttestResult{}
		}
	}
}

func main() {
	apiURL := strings.TrimRight(env("TREEWARD_API_URL", "http://treeward-api:8080"), "/")
	enrollToken := os.Getenv("TREEWARD_ENROLL_TOKEN")
	if enrollToken == "" {
		log.Fatal("TREEWARD_ENROLL_TOKEN is required")
	}
	cluster := env("TREEWARD_CLUSTER", "kind-treeward")
	listen := connectorListenAddr()
	localToken := os.Getenv("TREEWARD_LOCAL_TOKEN")
	localAuthMode := strings.ToLower(strings.TrimSpace(os.Getenv("TREEWARD_LOCAL_AUTH")))
	var wrapAuth func(http.HandlerFunc) http.HandlerFunc
	allowStubNodes := false

	switch localAuthMode {
	case "", "token":
		if localToken == "" {
			log.Fatal("TREEWARD_LOCAL_TOKEN is required (or set TREEWARD_LOCAL_AUTH=k8s in Kubernetes, or TREEWARD_LOCAL_AUTH=off on loopback for local dev only)")
		}
		wrapAuth = func(next http.HandlerFunc) http.HandlerFunc {
			return requireLocalAuth(localToken, false, next)
		}
	case "off":
		if localToken != "" {
			wrapAuth = func(next http.HandlerFunc) http.HandlerFunc {
				return requireLocalAuth(localToken, false, next)
			}
		} else {
			if !isLoopbackListenAddr(listen) {
				log.Fatalf("refusing to start with TREEWARD_LOCAL_AUTH=off on non-loopback address %q (bind to 127.0.0.1, ::1, or localhost, or set TREEWARD_LOCAL_TOKEN / TREEWARD_LOCAL_AUTH=k8s)", listen)
			}
			log.Printf("WARNING: TREEWARD_LOCAL_AUTH=off and TREEWARD_LOCAL_TOKEN is empty; local connector endpoints are unauthenticated (local dev only)")
			wrapAuth = func(next http.HandlerFunc) http.HandlerFunc {
				return requireLocalAuth("", true, next)
			}
		}
	case "k8s":
		k8sAuth, err := newK8sAuthenticatorFromEnv()
		if err != nil {
			log.Fatalf("TREEWARD_LOCAL_AUTH=k8s init failed: %v", err)
		}
		wrapAuth = k8sAuth.Middleware
		if envTrue(os.Getenv("TREEWARD_K8S_ALLOW_STUB_NODES")) {
			allowStubNodes = true
			log.Printf("WARNING: TREEWARD_K8S_ALLOW_STUB_NODES=true — allowing stub node suffixes (-canary, -n1, -n2) under bound nodeName (dev/quickstart demo only)")
		}
		log.Printf("local auth enabled: Kubernetes TokenReview (audience=%s)", k8sAuth.audience)
	default:
		log.Fatalf("invalid TREEWARD_LOCAL_AUTH %q (expected token, k8s, or off)", localAuthMode)
	}
	interval := 5 * time.Second

	creds := newCredManager(apiURL, enrollToken, cluster, enroll)
	if err := creds.enrollWithRetry(30); err != nil {
		log.Fatalf("enroll failed: %v", err)
	}
	_, clusterID := creds.snapshot()
	log.Printf("enrolled connector cluster=%s", clusterID)

	state := newConnectorState()
	mux := newConnectorMux(apiURL, creds, state, wrapAuth, allowStubNodes)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			tok, cid := creds.snapshot()
			nodes, reports := state.snapshotForSync(cid)
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
			state.setPending(p)
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

type reenrollFlight struct {
	done chan struct{}
	err  error
}

type credManager struct {
	mu             sync.Mutex
	apiURL         string
	enrollToken    string
	cluster        string
	token          string
	clusterID      string
	tokenGen       uint64
	lastAttempt    time.Time
	backoff        time.Duration
	enrollRejected bool
	flight         *reenrollFlight
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
			c.tokenGen++
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

	// If another caller already rotated the token since our failed request,
	// skip redundant re-enrollment.
	if failedToken != "" && c.token != "" && c.token != failedToken {
		c.mu.Unlock()
		return nil
	}

	// Coalesce concurrent 401s onto a single in-flight enrollFn call without
	// holding c.mu across network I/O.
	if c.flight != nil {
		flight := c.flight
		c.mu.Unlock()
		<-flight.done
		return flight.err
	}

	if c.enrollRejected {
		c.mu.Unlock()
		return errors.New("re-enroll halted: enroll token rejected")
	}

	now := c.nowFn()
	if !c.lastAttempt.IsZero() && c.backoff > 0 && now.Sub(c.lastAttempt) < c.backoff {
		rem := (c.backoff - now.Sub(c.lastAttempt)).Round(time.Millisecond)
		c.mu.Unlock()
		return fmt.Errorf("re-enroll backed off (%s remaining)", rem)
	}

	c.lastAttempt = now
	flight := &reenrollFlight{done: make(chan struct{})}
	c.flight = flight
	apiURL := c.apiURL
	enrollToken := c.enrollToken
	cluster := c.cluster
	enrollFn := c.enrollFn
	c.mu.Unlock()

	tok, cid, err := enrollFn(apiURL, enrollToken, cluster)

	c.mu.Lock()
	var retErr error
	if err != nil {
		if isAuthRejected(err) {
			c.enrollRejected = true
			retErr = fmt.Errorf("re-enroll halted: enroll token rejected: %w", err)
		} else {
			if c.backoff == 0 {
				c.backoff = time.Second
			} else {
				c.backoff *= 2
				if c.backoff > 30*time.Second {
					c.backoff = 30 * time.Second
				}
			}
			retErr = err
		}
	} else {
		c.token = tok
		c.clusterID = cid
		c.tokenGen++
		c.backoff = 0
		c.enrollRejected = false
		log.Printf("re-enrolled connector cluster=%s", cid)
	}
	flight.err = retErr
	c.flight = nil
	close(flight.done)
	c.mu.Unlock()
	return retErr
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
	data, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return nil, err
	}
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
	data, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return err
	}
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
	data, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return &httpError{code: res.StatusCode, body: string(data)}
	}
	return json.Unmarshal(data, out)
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
		return he.code == http.StatusUnauthorized
	}
	return false
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

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

func envTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func newConnectorMux(apiURL string, creds *credManager, state *connectorState, wrapAuth func(http.HandlerFunc) http.HandlerFunc, allowStubNodes bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /v1/local/report", wrapAuth(func(w http.ResponseWriter, r *http.Request) {
		var reports []types.AgentReport
		if !decodeLocalJSON(w, r, &reports) {
			return
		}
		if boundNode, ok := k8sNodeFromContext(r.Context()); ok {
			for _, rep := range reports {
				if !matchesBoundNode(rep.Node.ID, boundNode, allowStubNodes) {
					http.Error(w, "forbidden: node identity mismatch", http.StatusForbidden)
					return
				}
			}
		}
		_, cid := creds.snapshot()
		state.recordReports(cid, reports)
		w.WriteHeader(http.StatusOK)
	}))

	mux.HandleFunc("GET /v1/local/desired", wrapAuth(func(w http.ResponseWriter, _ *http.Request) {
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

	mux.HandleFunc("GET /v1/local/attest", wrapAuth(func(w http.ResponseWriter, _ *http.Request) {
		p := state.getPending()
		if p == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, p)
	}))

	registerUpatchRoutesWithAuth(mux, apiURL, creds, wrapAuth)

	mux.HandleFunc("POST /v1/local/attest", wrapAuth(func(w http.ResponseWriter, r *http.Request) {
		var results []types.AttestResult
		if !decodeLocalJSON(w, r, &results) {
			return
		}
		if boundNode, ok := k8sNodeFromContext(r.Context()); ok {
			for _, res := range results {
				if !matchesBoundNode(res.NodeID, boundNode, allowStubNodes) {
					http.Error(w, "forbidden: node identity mismatch", http.StatusForbidden)
					return
				}
			}
		}
		campID, batch, shouldSubmit, hasPending := state.recordAttestResults(results)
		if !hasPending {
			http.Error(w, "no active campaign", http.StatusConflict)
			return
		}

		if shouldSubmit {
			resultsURL := fmt.Sprintf("%s/v1/attest/campaigns/%s/results", apiURL, url.PathEscape(campID))
			tok, _ := creds.snapshot()
			if err := postJSON(resultsURL, tok, batch, nil); err != nil {
				if isUnauthorized(err) {
					if rerr := creds.reenroll(tok); rerr != nil {
						log.Printf("re-enroll: %v", rerr)
					} else {
						tok, _ = creds.snapshot()
						err = postJSON(resultsURL, tok, batch, nil)
					}
				}
				if err != nil {
					state.finishAttestSubmit(campID, false)
					log.Printf("attest submit: %v", err)
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
			}
			state.finishAttestSubmit(campID, true)
			log.Printf("attest campaign %s submitted (%d quotes)", campID, len(batch))
		}
		w.WriteHeader(http.StatusOK)
	}))

	return mux
}
