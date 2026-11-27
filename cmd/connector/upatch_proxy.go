package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
)

// maxUpatchBytes caps proxied upatch payloads. Matches the agent-side limit.
const maxUpatchBytes = 16 << 20

// registerUpatchRoutes exposes signed upatch payloads and unload directives to
// the local Shirudo agent. The agent calls GET /v1/upatches/{sha} and
// GET /v1/upatches/{sha}/unload on the connector; the connector forwards them to
// the control plane with its enrolled credential, so the VM never holds one.
func registerUpatchRoutes(mux *http.ServeMux, apiURL string, creds *credManager, localToken string, localAuthDisabled bool) {
	mux.HandleFunc("GET /v1/upatches/{sha}", requireLocalAuth(localToken, localAuthDisabled, func(w http.ResponseWriter, r *http.Request) {
		proxyUpatch(w, apiURL, creds, r.PathValue("sha"), "")
	}))
	mux.HandleFunc("GET /v1/upatches/{sha}/unload", requireLocalAuth(localToken, localAuthDisabled, func(w http.ResponseWriter, r *http.Request) {
		proxyUpatch(w, apiURL, creds, r.PathValue("sha"), "/unload")
	}))
}

func proxyUpatch(w http.ResponseWriter, apiURL string, creds *credManager, sha, suffix string) {
	if b, err := hex.DecodeString(sha); err != nil || len(b) != 32 {
		http.Error(w, "invalid_sha256", http.StatusBadRequest)
		return
	}
	tok, _ := creds.snapshot()
	status, hdr, body, err := fetchUpatchBytes(apiURL+"/v1/upatches/"+sha+suffix, tok)
	if err != nil {
		var he *httpError
		if asHTTPError(err, &he) && he.code == http.StatusUnauthorized {
			if rerr := creds.reenroll(tok); rerr != nil {
				log.Printf("re-enroll: %v", rerr)
			} else {
				tok, _ = creds.snapshot()
				status, hdr, body, err = fetchUpatchBytes(apiURL+"/v1/upatches/"+sha+suffix, tok)
			}
		}
	}
	if err != nil {
		var he *httpError
		if asHTTPError(err, &he) {
			http.Error(w, he.body, he.code)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		http.Error(w, "upstream status "+fmt.Sprint(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if v := hdr.Get("x-upatch-sha256"); v != "" {
		w.Header().Set("x-upatch-sha256", v)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func fetchUpatchBytes(url, token string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxUpatchBytes+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(data) > maxUpatchBytes {
		return 0, nil, nil, &httpError{code: http.StatusBadGateway, body: "upstream upatch exceeds size limit"}
	}
	if res.StatusCode >= 300 {
		return res.StatusCode, res.Header, nil, &httpError{code: res.StatusCode, body: string(data)}
	}
	return res.StatusCode, res.Header, data, nil
}

func asHTTPError(err error, target **httpError) bool {
	he, ok := err.(*httpError)
	if ok {
		*target = he
	}
	return ok
}
