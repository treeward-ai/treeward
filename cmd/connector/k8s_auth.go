package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultK8sAudience  = "treeward-connector"
	defaultK8sTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultK8sCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultK8sCacheTTL  = 60 * time.Second
	maxK8sAuthCache     = 4096
)

type ctxKeyK8sNodeName struct{}

func k8sNodeFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyK8sNodeName{}).(string)
	return v, ok && v != ""
}

type k8sAuthCacheEntry struct {
	nodeName  string
	expiresAt time.Time
}

// k8sAuthenticator validates Kubernetes projected ServiceAccount tokens via
// TokenReview and resolves the bound pod's spec.nodeName via the Kubernetes API.
type k8sAuthenticator struct {
	apiURL    string
	audience  string
	tokenFile string
	client    *http.Client
	cacheTTL  time.Duration
	maxCache  int
	nowFn     func() time.Time

	mu    sync.Mutex
	cache map[string]k8sAuthCacheEntry
}

func newK8sAuthenticatorFromEnv() (*k8sAuthenticator, error) {
	apiURL := strings.TrimRight(strings.TrimSpace(os.Getenv("TREEWARD_K8S_API_URL")), "/")
	if apiURL == "" {
		host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
		port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
		if host == "" || port == "" {
			return nil, errors.New("in-cluster Kubernetes config missing (set KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT or TREEWARD_K8S_API_URL)")
		}
		apiURL = "https://" + net.JoinHostPort(host, port)
	}

	audience := strings.TrimSpace(os.Getenv("TREEWARD_K8S_AUDIENCE"))
	if audience == "" {
		audience = defaultK8sAudience
	}

	tokenFile := strings.TrimSpace(os.Getenv("TREEWARD_K8S_TOKEN_FILE"))
	if tokenFile == "" {
		tokenFile = defaultK8sTokenFile
	}
	if b, err := os.ReadFile(tokenFile); err != nil {
		return nil, fmt.Errorf("read connector Kubernetes serviceaccount token %q: %w", tokenFile, err)
	} else if strings.TrimSpace(string(b)) == "" {
		return nil, fmt.Errorf("connector Kubernetes serviceaccount token %q is empty", tokenFile)
	}

	caFile := strings.TrimSpace(os.Getenv("TREEWARD_K8S_CA_FILE"))
	if caFile == "" {
		caFile = defaultK8sCAFile
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes CA bundle %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse Kubernetes CA bundle %q: no valid certificates", caFile)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: noRedirect,
	}

	return newK8sAuthenticator(apiURL, audience, tokenFile, client), nil
}

func newK8sAuthenticator(apiURL, audience, tokenFile string, client *http.Client) *k8sAuthenticator {
	if audience == "" {
		audience = defaultK8sAudience
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	}
	return &k8sAuthenticator{
		apiURL:    strings.TrimRight(apiURL, "/"),
		audience:  audience,
		tokenFile: tokenFile,
		client:    client,
		cacheTTL:  defaultK8sCacheTTL,
		maxCache:  maxK8sAuthCache,
		nowFn:     time.Now,
		cache:     map[string]k8sAuthCacheEntry{},
	}
}

func (a *k8sAuthenticator) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if tok == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		nodeName, err := a.Authenticate(r.Context(), tok)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyK8sNodeName{}, nodeName)
		next(w, r.WithContext(ctx))
	}
}

func (a *k8sAuthenticator) Authenticate(ctx context.Context, rawToken string) (string, error) {
	if rawToken == "" {
		return "", errors.New("empty bearer token")
	}

	sum := sha256.Sum256([]byte(rawToken))
	key := hex.EncodeToString(sum[:])

	now := a.nowFn()
	a.mu.Lock()
	if entry, ok := a.cache[key]; ok {
		if now.Before(entry.expiresAt) {
			a.mu.Unlock()
			return entry.nodeName, nil
		}
		delete(a.cache, key)
	}
	a.mu.Unlock()

	ns, podName, podUID, err := a.reviewToken(ctx, rawToken)
	if err != nil {
		return "", err
	}
	nodeName, err := a.lookupPodNode(ctx, ns, podName, podUID)
	if err != nil {
		return "", err
	}

	if a.cacheTTL > 0 {
		now = a.nowFn()
		a.mu.Lock()
		if a.maxCache > 0 && len(a.cache) >= a.maxCache {
			for k, v := range a.cache {
				if !now.Before(v.expiresAt) {
					delete(a.cache, k)
				}
			}
		}
		if a.maxCache <= 0 || len(a.cache) < a.maxCache {
			a.cache[key] = k8sAuthCacheEntry{
				nodeName:  nodeName,
				expiresAt: now.Add(a.cacheTTL),
			}
		}
		a.mu.Unlock()
	}

	return nodeName, nil
}

func (a *k8sAuthenticator) connectorToken() (string, error) {
	if a.tokenFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(a.tokenFile)
	if err != nil {
		return "", fmt.Errorf("read connector k8s token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("connector k8s token file is empty")
	}
	return tok, nil
}

type k8sTokenReviewRequest struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Spec       k8sTokenReviewReqSpec `json:"spec"`
}

type k8sTokenReviewReqSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type k8sTokenReviewResponse struct {
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Audiences     []string `json:"audiences"`
		Error         string   `json:"error"`
		User          struct {
			Username string              `json:"username"`
			UID      string              `json:"uid"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

func (a *k8sAuthenticator) reviewToken(ctx context.Context, rawToken string) (namespace, podName, podUID string, err error) {
	connTok, err := a.connectorToken()
	if err != nil {
		return "", "", "", err
	}
	payload, err := json.Marshal(k8sTokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: k8sTokenReviewReqSpec{
			Token:     rawToken,
			Audiences: []string{a.audience},
		},
	})
	if err != nil {
		return "", "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(payload))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if connTok != "" {
		req.Header.Set("Authorization", "Bearer "+connTok)
	}

	res, err := a.client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("tokenreview request: %w", err)
	}
	defer res.Body.Close()

	body, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("tokenreview read: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("tokenreview HTTP %d", res.StatusCode)
	}

	var tr k8sTokenReviewResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", "", "", fmt.Errorf("tokenreview decode: %w", err)
	}
	if !tr.Status.Authenticated {
		return "", "", "", errors.New("token not authenticated")
	}

	audMatch := false
	for _, aud := range tr.Status.Audiences {
		if aud == a.audience {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return "", "", "", fmt.Errorf("token audience does not include %q", a.audience)
	}

	namespace = parseServiceAccountNamespace(tr.Status.User.Username)
	if namespace == "" {
		return "", "", "", fmt.Errorf("token subject %q is not a serviceaccount", tr.Status.User.Username)
	}
	podName = firstExtra(tr.Status.User.Extra, "authentication.kubernetes.io/pod-name")
	if podName == "" {
		return "", "", "", errors.New("token is not bound to a pod")
	}
	podUID = firstExtra(tr.Status.User.Extra, "authentication.kubernetes.io/pod-uid")
	return namespace, podName, podUID, nil
}

type k8sPodResponse struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
}

func (a *k8sAuthenticator) lookupPodNode(ctx context.Context, namespace, podName, expectedUID string) (string, error) {
	connTok, err := a.connectorToken()
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s",
		a.apiURL, url.PathEscape(namespace), url.PathEscape(podName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if connTok != "" {
		req.Header.Set("Authorization", "Bearer "+connTok)
	}

	res, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pod lookup request: %w", err)
	}
	defer res.Body.Close()

	body, err := readBodyBounded(res.Body, maxResponseBodyBytes)
	if err != nil {
		return "", fmt.Errorf("pod lookup read: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pod lookup HTTP %d", res.StatusCode)
	}

	var pod k8sPodResponse
	if err := json.Unmarshal(body, &pod); err != nil {
		return "", fmt.Errorf("pod lookup decode: %w", err)
	}
	if expectedUID != "" && pod.Metadata.UID != "" && pod.Metadata.UID != expectedUID {
		return "", errors.New("bound pod UID mismatch")
	}
	nodeName := strings.TrimSpace(pod.Spec.NodeName)
	if nodeName == "" {
		return "", errors.New("bound pod has empty spec.nodeName")
	}
	return nodeName, nil
}

func parseServiceAccountNamespace(username string) string {
	// Format: system:serviceaccount:<namespace>:<serviceaccount-name>
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(username, prefix)
	ns, sa, ok := strings.Cut(rest, ":")
	if !ok || ns == "" || sa == "" || strings.Contains(sa, ":") {
		return ""
	}
	return ns
}

func firstExtra(extra map[string][]string, key string) string {
	if extra == nil {
		return ""
	}
	for _, v := range extra[key] {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// matchesBoundNode checks whether a reported or attested nodeID belongs to
// the Kubernetes node bound to the caller's projected ServiceAccount token.
func matchesBoundNode(nodeID, boundNode string, allowStubNodes bool) bool {
	if nodeID == "" || boundNode == "" {
		return false
	}
	if nodeID == boundNode {
		return true
	}
	if allowStubNodes {
		switch nodeID {
		case boundNode + "-canary", boundNode + "-n1", boundNode + "-n2":
			return true
		}
	}
	return false
}
