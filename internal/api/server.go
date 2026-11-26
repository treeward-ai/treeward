package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/treeward-ai/treeward/internal/store"
	"github.com/treeward-ai/treeward/internal/types"
)

type Server struct {
	Store *store.Store
	Mux   *http.ServeMux
}

func New(st *store.Store) *Server {
	s := &Server{Store: st, Mux: http.NewServeMux()}
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

	s.Mux.HandleFunc("GET /v1/nodes", s.handleListNodes)
	s.Mux.HandleFunc("POST /v1/artifacts", s.handleCreateArtifact)
	s.Mux.HandleFunc("GET /v1/artifacts", s.handleListArtifacts)
	s.Mux.HandleFunc("POST /v1/bindings", s.handleCreateBinding)
	s.Mux.HandleFunc("GET /v1/bindings", s.handleListBindings)
	s.Mux.HandleFunc("GET /v1/bindings/{id}", s.handleGetBinding)
	s.Mux.HandleFunc("POST /v1/bindings/{id}/approve", s.handleApprove)
	s.Mux.HandleFunc("POST /v1/bindings/{id}/canary", s.handleCanary)
	s.Mux.HandleFunc("POST /v1/bindings/{id}/promote", s.handlePromote)
	s.Mux.HandleFunc("POST /v1/bindings/{id}/revert", s.handleRevert)
	s.Mux.HandleFunc("GET /v1/tree", s.handleTree)
	s.Mux.HandleFunc("GET /v1/audit", s.handleAudit)
	s.Mux.HandleFunc("POST /v1/attest/campaigns", s.handleStartAttest)
	s.Mux.HandleFunc("GET /v1/attest/campaigns", s.handleListAttest)
	s.Mux.HandleFunc("GET /v1/attest/active", s.withConnector(s.handleActiveAttest))
	s.Mux.HandleFunc("GET /v1/attest/campaigns/{id}", s.handleGetAttest)
	s.Mux.HandleFunc("POST /v1/attest/campaigns/{id}/results", s.withConnector(s.handleAttestResults))
}

func (s *Server) withConnector(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.Header.Get("X-Treeward-Token")
		}
		if _, ok := s.Store.LookupConnector(tok); !ok {
			http.Error(w, "unauthorized connector", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req types.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	var req types.InventoryUpsert
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Store.UpsertInventory(req.Nodes, req.ClusterID)
	writeJSON(w, http.StatusOK, map[string]any{"upserted": len(req.Nodes)})
}

func (s *Server) handleDesired(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Desired())
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	var reports []types.AgentReport
	if err := json.NewDecoder(r.Body).Decode(&reports); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cluster := ""
	if len(reports) > 0 {
		cluster = reports[0].Node.ClusterID
	}
	s.Store.ProcessAgentReports(reports, cluster)
	writeJSON(w, http.StatusOK, map[string]any{"reported": len(reports)})
}

func (s *Server) handleListNodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListNodes())
}

func (s *Server) handleCreateArtifact(w http.ResponseWriter, r *http.Request) {
	var a types.Artifact
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, s.Store.CreateArtifact(a))
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.ListArtifacts())
}

func (s *Server) handleCreateBinding(w http.ResponseWriter, r *http.Request) {
	var b types.Binding
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := s.Store.CreateBinding(b)
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
	_ = json.NewDecoder(r.Body).Decode(&req)
	b, err := s.Store.Approve(r.PathValue("id"), req.Actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleCanary(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	b, err := s.Store.Canary(r.PathValue("id"), req.Actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	b, err := s.Store.Promote(r.PathValue("id"), req.Actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleRevert(w http.ResponseWriter, r *http.Request) {
	var req types.ApproveRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	b, err := s.Store.Revert(r.PathValue("id"), req.Actor)
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

func (s *Server) handleStartAttest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusCreated, s.Store.StartAttestCampaign())
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
	var results []types.AttestResult
	if err := json.NewDecoder(r.Body).Decode(&results); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := s.Store.SubmitAttest(r.PathValue("id"), results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
