package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/treeward-ai/treeward/internal/runtime"
	"github.com/treeward-ai/treeward/internal/store"
	"github.com/treeward-ai/treeward/internal/types"
)

const maxJSONBodyBytes = 4 << 20 // 4 MiB

type ctxKeyOperatorToken struct{}
type ctxKeyConnector struct{}

type Server struct {
	Store        *store.Store
	Mux          *http.ServeMux
	Verifier     AttestVerifier
	AuthDisabled bool
}

func New(st *store.Store) *Server {
	s := &Server{
		Store: st,
		Mux:   http.NewServeMux(),
	}
	if v := NewShirudoVerifierFromEnv(); v != nil {
		s.Verifier = v
	}
	if st != nil && parseEnvBool(os.Getenv("TREEWARD_ALLOW_STUB_ATTEST"), false) {
		st.AllowStubAttest = true
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	s.Mux.HandleFunc("POST /v1/connectors/enroll", s.handleEnroll)
	s.Mux.HandleFunc("POST /v1/inventory", s.withConnector(s.handleInventory))
	s.Mux.HandleFunc("GET /v1/desired", s.withConnector(s.handleDesired))
	s.Mux.HandleFunc("POST /v1/agents/report", s.withConnector(s.handleAgentReport))

	s.Mux.HandleFunc("POST /v1/tokens", s.withAdminBootstrap(s.handleCreateToken))
	s.Mux.HandleFunc("GET /v1/tokens", s.withRoles(s.handleListTokens, types.RoleAdmin))
	s.Mux.HandleFunc("DELETE /v1/tokens/{id}", s.withRoles(s.handleRevokeToken, types.RoleAdmin))

	s.Mux.HandleFunc("GET /v1/nodes", s.withRoles(s.handleListNodes, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/artifacts", s.withRoles(s.handleCreateArtifact, types.RoleOperator, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/artifacts", s.withRoles(s.handleListArtifacts, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/upatches/{sha}", s.withConnector(s.handleGetUpatch))
	s.Mux.HandleFunc("GET /v1/upatches/{sha}/unload", s.withConnector(s.handleGetUpatchUnload))
	s.Mux.HandleFunc("POST /v1/bindings", s.withRoles(s.handleCreateBinding, types.RoleOperator, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/bindings", s.withRoles(s.handleListBindings, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/bindings/{id}", s.withRoles(s.handleGetBinding, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/bindings/{id}/approve", s.withRoles(s.handleApprove, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/bindings/{id}/canary", s.withRoles(s.handleCanary, types.RoleOperator, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/bindings/{id}/promote", s.withRoles(s.handlePromote, types.RoleOperator, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/bindings/{id}/revert", s.withRoles(s.handleRevert, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/tree", s.withRoles(s.handleTree, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/audit", s.withRoles(s.handleAudit, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/attest/campaigns", s.withRoles(s.handleStartAttest, types.RoleOperator, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/attest/campaigns", s.withRoles(s.handleListAttest, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("GET /v1/attest/active", s.withConnector(s.handleActiveAttest))
	s.Mux.HandleFunc("GET /v1/attest/campaigns/{id}", s.withRoles(s.handleGetAttest, types.RoleViewer, types.RoleOperator, types.RoleApprover, types.RoleAdmin))
	s.Mux.HandleFunc("POST /v1/attest/campaigns/{id}/results", s.withConnector(s.handleAttestResults))
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
}

func roleAllowed(role string, allowed []string) bool {
	for _, a := range allowed {
		if role == a {
			return true
		}
	}
	return false
}

func (s *Server) withRoles(next http.HandlerFunc, allowed ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AuthDisabled {
			next(w, r)
			return
		}
		raw := bearerToken(r)
		tok, ok := s.Store.AuthenticateToken(raw)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		role := tok.Role
		if role == "" {
			role = types.RoleAdmin
		}
		if !roleAllowed(role, allowed) {
			http.Error(w, "forbidden: insufficient role", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyOperatorToken{}, tok)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) withAdminBootstrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" || s.Store.AdminBootstrapToken == "" ||
			(s.Store.EnrollToken != "" && subtle.ConstantTimeCompare([]byte(s.Store.AdminBootstrapToken), []byte(s.Store.EnrollToken)) == 1) ||
			subtle.ConstantTimeCompare([]byte(raw), []byte(s.Store.AdminBootstrapToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func operatorTokenFromContext(ctx context.Context) *types.APIToken {
	tok, _ := ctx.Value(ctxKeyOperatorToken{}).(*types.APIToken)
	return tok
}

func actorFromRequest(r *http.Request, fallback string) string {
	if tok := operatorTokenFromContext(r.Context()); tok != nil {
		if tok.Name != "" {
			return tok.Name
		}
		if tok.ID != "" {
			return tok.ID
		}
	}
	return fallback
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req types.CreateTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp, err := s.Store.CreateTokenWithRole(req.Name, req.Role, req.ExpiresAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListTokens(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListTokens())
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	actor := actorFromRequest(r, "operator")
	tok, err := s.Store.RevokeToken(r.PathValue("id"), actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, tok)
}

func connectorFromContext(ctx context.Context) *types.Connector {
	c, _ := ctx.Value(ctxKeyConnector{}).(*types.Connector)
	return c
}

func (s *Server) withConnector(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		conn, ok := s.Store.LookupConnector(tok)
		if !ok {
			http.Error(w, "unauthorized connector", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyConnector{}, conn)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req types.EnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp, err := s.Store.Enroll(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	conn := connectorFromContext(r.Context())
	if conn == nil {
		http.Error(w, "unauthorized connector", http.StatusUnauthorized)
		return
	}
	var req types.InventoryUpsert
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ClusterID != "" && req.ClusterID != conn.ClusterID {
		http.Error(w, "cluster mismatch", http.StatusForbidden)
		return
	}
	if err := s.Store.UpsertInventoryForCluster(req.Nodes, conn.ClusterID); err != nil {
		if errors.Is(err, store.ErrClusterForbidden) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"upserted": len(req.Nodes)})
}

func (s *Server) handleDesired(w http.ResponseWriter, r *http.Request) {
	conn := connectorFromContext(r.Context())
	if conn == nil {
		http.Error(w, "unauthorized connector", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, s.Store.DesiredForCluster(conn.ClusterID))
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	conn := connectorFromContext(r.Context())
	if conn == nil {
		http.Error(w, "unauthorized connector", http.StatusUnauthorized)
		return
	}
	var reports []types.AgentReport
	if !decodeJSON(w, r, &reports) {
		return
	}
	if err := s.Store.ProcessAgentReportsForCluster(reports, conn.ClusterID); err != nil {
		if errors.Is(err, store.ErrClusterForbidden) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reported": len(reports)})
}

func (s *Server) handleListNodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListNodes())
}

// createArtifactRequest is the artifact metadata plus, for bpf artifacts, the
// signed upatch and its unload directive as standard base64. When the bytes are
// present the digest is derived from them ("<name>@sha256:<upatch sha256>") and
// the connector can then serve them to agents.
type createArtifactRequest struct {
	types.Artifact
	UpatchB64       string `json:"upatchB64,omitempty"`
	UpatchUnloadB64 string `json:"upatchUnloadB64,omitempty"`
}

func (s *Server) handleCreateArtifact(w http.ResponseWriter, r *http.Request) {
	var req createArtifactRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := actorFromRequest(r, "api")
	if req.UpatchB64 == "" && req.UpatchUnloadB64 == "" {
		writeJSON(w, http.StatusCreated, s.Store.CreateArtifactBy(req.Artifact, actor))
		return
	}
	a, upatch, unload, err := registerUpatchArtifact(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := s.Store.CreateUpatchArtifactBy(a, upatch, unload, actor)
	if errors.Is(err, store.ErrDuplicateArtifact) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// registerUpatchArtifact decodes and checks the signed bytes of a bpf artifact
// and derives its digest from them.
func registerUpatchArtifact(req createArtifactRequest) (types.Artifact, []byte, []byte, error) {
	if req.Type != "" && req.Type != "bpf" {
		return types.Artifact{}, nil, nil, fmt.Errorf("upatch bytes are only accepted for type bpf")
	}
	if req.UpatchB64 == "" || req.UpatchUnloadB64 == "" {
		return types.Artifact{}, nil, nil, fmt.Errorf("upatchB64 and upatchUnloadB64 must both be set")
	}
	upatch, err := base64.StdEncoding.DecodeString(req.UpatchB64)
	if err != nil || len(upatch) == 0 {
		return types.Artifact{}, nil, nil, fmt.Errorf("upatchB64 must be non-empty standard base64")
	}
	unload, err := base64.StdEncoding.DecodeString(req.UpatchUnloadB64)
	if err != nil || len(unload) == 0 {
		return types.Artifact{}, nil, nil, fmt.Errorf("upatchUnloadB64 must be non-empty standard base64")
	}
	upSum := sha256.Sum256(upatch)
	unSum := sha256.Sum256(unload)
	upSHA := hex.EncodeToString(upSum[:])
	digest := req.Name + "@sha256:" + upSHA
	// Same validation the Shirudo runtime applies to desired entries.
	if _, err := runtime.ParseDesiredUpatch(digest); err != nil {
		return types.Artifact{}, nil, nil, err
	}
	if req.Digest != "" && req.Digest != digest {
		return types.Artifact{}, nil, nil, fmt.Errorf("digest must be omitted or equal to %s", digest)
	}
	a := req.Artifact
	a.Type = "bpf"
	a.Digest = digest
	a.UpatchSHA256 = upSHA
	a.UnloadSHA256 = hex.EncodeToString(unSum[:])
	return a, upatch, unload, nil
}

// handleGetUpatch serves the signed upatch registered under {sha} to a connector.
func (s *Server) handleGetUpatch(w http.ResponseWriter, r *http.Request) {
	s.serveUpatch(w, r, false)
}

// handleGetUpatchUnload serves the unload directive of the upatch registered under {sha}.
func (s *Server) handleGetUpatchUnload(w http.ResponseWriter, r *http.Request) {
	s.serveUpatch(w, r, true)
}

func (s *Server) serveUpatch(w http.ResponseWriter, r *http.Request, unload bool) {
	sha := strings.ToLower(r.PathValue("sha"))
	if b, err := hex.DecodeString(sha); err != nil || len(b) != sha256.Size {
		http.Error(w, "invalid_sha256", http.StatusBadRequest)
		return
	}
	body, ok := s.Store.UpatchBytes(sha, unload)
	if !ok {
		http.Error(w, "upatch not found", http.StatusNotFound)
		return
	}
	sum := sha256.Sum256(body)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("x-upatch-sha256", hex.EncodeToString(sum[:]))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListArtifacts())
}

func (s *Server) handleCreateBinding(w http.ResponseWriter, r *http.Request) {
	var b types.Binding
	if !decodeJSON(w, r, &b) {
		return
	}
	// Never trust client-supplied CreatedBy; bind to authenticated principal.
	b.CreatedBy = ""
	out, err := s.Store.CreateBindingBy(b, actorFromRequest(r, ""))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleListBindings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListBindings())
}

func (s *Server) handleGetBinding(w http.ResponseWriter, r *http.Request) {
	b, ok := s.Store.GetBinding(r.PathValue("id"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	b, err := s.Store.Approve(r.PathValue("id"), actorFromRequest(r, req.Actor))
	if err != nil {
		if errors.Is(err, store.ErrSelfApproveForbidden) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if errors.Is(err, store.ErrInvalidTransition) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleCanary(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	b, err := s.Store.Canary(r.PathValue("id"), actorFromRequest(r, req.Actor))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	b, err := s.Store.Promote(r.PathValue("id"), actorFromRequest(r, req.Actor))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleRevert(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	b, err := s.Store.Revert(r.PathValue("id"), actorFromRequest(r, req.Actor))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleTree(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.TreeOps())
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListAudit())
}

func (s *Server) handleStartAttest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, s.Store.StartAttestCampaignBy(actorFromRequest(r, "api")))
}

func (s *Server) handleListAttest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListCampaigns())
}

func (s *Server) handleActiveAttest(w http.ResponseWriter, _ *http.Request) {
	p := s.Store.ActiveAttest()
	if p == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleGetAttest(w http.ResponseWriter, r *http.Request) {
	c, ok := s.Store.GetCampaign(r.PathValue("id"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleAttestResults(w http.ResponseWriter, r *http.Request) {
	conn := connectorFromContext(r.Context())
	if conn == nil {
		http.Error(w, "unauthorized connector", http.StatusUnauthorized)
		return
	}
	var results []types.AttestResult
	if !decodeJSON(w, r, &results) {
		return
	}
	// Never trust client-supplied verdict fields.
	nodeIDs := make([]string, len(results))
	for i := range results {
		results[i].Verified = false
		results[i].Pass = false
		nodeIDs[i] = results[i].NodeID
	}
	if err := s.Store.ValidateNodesInCluster(nodeIDs, conn.ClusterID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	campaignID := r.PathValue("id")
	if s.Verifier != nil {
		c, ok := s.Store.GetCampaign(campaignID)
		if !ok {
			http.Error(w, "campaign not found", http.StatusBadRequest)
			return
		}
		if c.Status == "complete" {
			http.Error(w, "campaign already complete", http.StatusBadRequest)
			return
		}
		for i := range results {
			results[i] = s.Verifier.VerifyResult(r.Context(), c.Nonce, results[i])
		}
	}
	c, err := s.Store.SubmitAttestForCluster(campaignID, conn.ClusterID, results)
	if err != nil {
		if errors.Is(err, store.ErrClusterForbidden) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
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

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
