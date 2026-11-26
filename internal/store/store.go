package store

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/types"
)

// ErrClusterForbidden is returned when a connector attempts to act on a node
// or cluster outside its own enrolled cluster.
var ErrClusterForbidden = errors.New("forbidden: cross-cluster access denied")

// ErrSelfApproveForbidden is returned when the principal who created a binding
// attempts to approve that same binding while two-person separation of duties is enforced.
var ErrSelfApproveForbidden = errors.New("forbidden: binding creator cannot approve own binding")

type Store struct {
	mu sync.RWMutex

	EnrollToken         string
	AdminBootstrapToken string
	AllowSelfApprove    bool
	Signer              signer.Signer
	db                  *sql.DB

	Connectors map[string]*types.Connector // by connector ID
	Nodes      map[string]*types.Node
	Artifacts  map[string]*types.Artifact // by id
	Bindings   map[string]*types.Binding
	Tree       []types.TreeOp
	Audit      []types.AuditEvent
	Campaigns  map[string]*types.AttestCampaign
	tokens     map[string]*storedToken // by token ID
}

// New returns an in-memory store (tests / no persistence).
func New(enrollToken, adminBootstrapToken string, s signer.Signer) *Store {
	return &Store{
		EnrollToken:         enrollToken,
		AdminBootstrapToken: adminBootstrapToken,
		Signer:              s,
		Connectors:          map[string]*types.Connector{},
		Nodes:               map[string]*types.Node{},
		Artifacts:           map[string]*types.Artifact{},
		Bindings:            map[string]*types.Binding{},
		Campaigns:           map[string]*types.AttestCampaign{},
		tokens:              map[string]*storedToken{},
	}
}

func id(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func (s *Store) Enroll(req types.EnrollRequest) (*types.EnrollResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.BootstrapToken == "" || s.EnrollToken == "" || subtle.ConstantTimeCompare([]byte(req.BootstrapToken), []byte(s.EnrollToken)) != 1 {
		return nil, fmt.Errorf("invalid enroll token")
	}
	if req.ClusterName == "" {
		req.ClusterName = "default"
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("generate connector token: %w", err)
	}
	tok := "ctok_" + hex.EncodeToString(raw[:])
	c := &types.Connector{
		ID:        id("conn"),
		ClusterID: req.ClusterName,
		TokenHash: hashToken(tok),
		Enrolled:  time.Now().UTC(),
	}
	s.Connectors[c.ID] = c
	s.auditLocked("enroll", "connector", "", "", "cluster="+c.ClusterID)
	s.persistLocked()
	return &types.EnrollResponse{
		ConnectorID: c.ID,
		ClusterID:   c.ClusterID,
		Token:       tok,
	}, nil
}

func (s *Store) LookupConnector(rawToken string) (*types.Connector, bool) {
	if rawToken == "" {
		return nil, false
	}
	wantHash := []byte(hashToken(rawToken))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.Connectors {
		if c.TokenHash != "" && subtle.ConstantTimeCompare([]byte(c.TokenHash), wantHash) == 1 {
			cp := *c
			return &cp, true
		}
	}
	return nil, false
}

func (s *Store) UpsertInventory(nodes []types.Node, clusterID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertInventoryLocked(nodes, clusterID)
	s.persistLocked()
}

// UpsertInventoryForCluster validates that none of the nodes claim or collide
// with a different cluster, then upserts them under clusterID.
func (s *Store) UpsertInventoryForCluster(nodes []types.Node, clusterID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range nodes {
		if n.ClusterID != "" && n.ClusterID != clusterID {
			return ErrClusterForbidden
		}
		if existing, ok := s.Nodes[n.ID]; ok && existing.ClusterID != "" && existing.ClusterID != clusterID {
			return ErrClusterForbidden
		}
	}
	s.upsertInventoryLocked(nodes, clusterID)
	s.persistLocked()
	return nil
}

// ProcessAgentReports upserts inventory from agent reports and pauses canary
// bindings on hard load failures (errors mentioning the binding digest).
func (s *Store) ProcessAgentReports(reports []types.AgentReport, clusterID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.processAgentReportsLocked(reports, clusterID)
	s.persistLocked()
}

// ProcessAgentReportsForCluster enforces cluster ownership on all reported
// nodes before upserting and evaluating load errors.
func (s *Store) ProcessAgentReportsForCluster(reports []types.AgentReport, clusterID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rep := range reports {
		if rep.Node.ClusterID != "" && rep.Node.ClusterID != clusterID {
			return ErrClusterForbidden
		}
		if existing, ok := s.Nodes[rep.Node.ID]; ok && existing.ClusterID != "" && existing.ClusterID != clusterID {
			return ErrClusterForbidden
		}
	}
	s.processAgentReportsLocked(reports, clusterID)
	s.persistLocked()
	return nil
}

func (s *Store) processAgentReportsLocked(reports []types.AgentReport, clusterID string) {
	nodes := make([]types.Node, 0, len(reports))
	accepted := make([]types.AgentReport, 0, len(reports))
	for _, rep := range reports {
		if existing, ok := s.Nodes[rep.Node.ID]; ok && existing.ClusterID != "" && existing.ClusterID != clusterID {
			continue
		}
		n := rep.Node
		n.Loaded = rep.Loaded
		nodes = append(nodes, n)
		accepted = append(accepted, rep)
	}
	s.upsertInventoryLocked(nodes, clusterID)
	for _, rep := range accepted {
		s.pauseOnLoadErrorsLocked(rep)
	}
}

func (s *Store) upsertInventoryLocked(nodes []types.Node, clusterID string) {
	now := time.Now().UTC()
	for i := range nodes {
		n := nodes[i]
		if existing, ok := s.Nodes[n.ID]; ok {
			if existing.ClusterID != "" && existing.ClusterID != clusterID {
				continue
			}
			// Preserve attest status unless reporter sets it.
			if n.AttestStatus == "" {
				n.AttestStatus = existing.AttestStatus
			}
		}
		n.ClusterID = clusterID
		n.LastSeen = now
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		if n.Loaded == nil {
			n.Loaded = []string{}
		}
		cp := n
		s.Nodes[n.ID] = &cp
	}
}

func (s *Store) ListNodes() []types.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Node, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) CreateArtifact(a types.Artifact) types.Artifact {
	return s.CreateArtifactBy(a, "api")
}

func (s *Store) CreateArtifactBy(a types.Artifact, actor string) types.Artifact {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		a.ID = id("art")
	}
	if a.Type == "" {
		a.Type = "bpf"
	}
	if a.Digest == "" {
		a.Digest = signer.ArtifactDigest(a.Name, a.Type, a.Fixes)
	}
	if actor == "" {
		actor = "api"
	}
	cp := a
	s.Artifacts[a.ID] = &cp
	s.auditLocked("artifact.create", actor, "", a.Digest, a.Name)
	s.persistLocked()
	return a
}

func (s *Store) ListArtifacts() []types.Artifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Artifact, 0, len(s.Artifacts))
	for _, a := range s.Artifacts {
		out = append(out, *a)
	}
	return out
}

func (s *Store) CreateBinding(b types.Binding) (types.Binding, error) {
	return s.CreateBindingBy(b, "")
}

func (s *Store) CreateBindingBy(b types.Binding, actor string) (types.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.ArtifactDigest == "" {
		return types.Binding{}, fmt.Errorf("artifactDigest required")
	}
	found := false
	for _, a := range s.Artifacts {
		if a.Digest == b.ArtifactDigest {
			found = true
			break
		}
	}
	if !found {
		return types.Binding{}, fmt.Errorf("unknown artifact digest")
	}
	b.ID = id("bind")
	b.Status = "draft"
	b.CreatedAt = time.Now().UTC()
	if actor != "" {
		b.CreatedBy = actor
	}
	if b.TreeRef == "" {
		b.TreeRef = "default"
	}
	if b.Selector.Labels == nil {
		b.Selector.Labels = map[string]string{}
	}
	auditActor := actor
	if auditActor == "" {
		auditActor = "api"
	}
	cp := b
	s.Bindings[b.ID] = &cp
	s.auditLocked("binding.create", auditActor, b.ID, b.ArtifactDigest, "")
	s.persistLocked()
	return b, nil
}

func (s *Store) GetBinding(id string) (*types.Binding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.Bindings[id]
	if !ok {
		return nil, false
	}
	cp := *b
	return &cp, true
}

func (s *Store) ListBindings() []types.Binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Binding, 0, len(s.Bindings))
	for _, b := range s.Bindings {
		out = append(out, *b)
	}
	return out
}

func (s *Store) Approve(bindingID, actor string) (*types.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.Bindings[bindingID]
	if !ok {
		return nil, fmt.Errorf("binding not found")
	}
	if b.Status != "draft" && b.Status != "approved" {
		return nil, fmt.Errorf("cannot approve binding in status %s", b.Status)
	}
	if actor == "" {
		actor = "operator"
	}
	if !s.AllowSelfApprove && b.CreatedBy != "" && strings.EqualFold(strings.TrimSpace(b.CreatedBy), strings.TrimSpace(actor)) {
		return nil, ErrSelfApproveForbidden
	}
	b.Status = "approved"
	b.ApprovedBy = actor
	b.ApprovedAt = time.Now().UTC()
	s.auditLocked("approve", actor, b.ID, b.ArtifactDigest, fmt.Sprintf("selector=%v", b.Selector.Labels))
	s.persistLocked()
	cp := *b
	return &cp, nil
}

func (s *Store) Canary(bindingID, actor string) (*types.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.Bindings[bindingID]
	if !ok {
		return nil, fmt.Errorf("binding not found")
	}
	if b.Status != "approved" && b.Status != "canary" {
		return nil, fmt.Errorf("binding must be approved first (status=%s)", b.Status)
	}
	sel := mergeLabels(b.Selector.Labels, map[string]string{types.LabelRollout: types.RolloutCanary})
	if err := s.appendTreeLocked(b, "add", sel); err != nil {
		return nil, err
	}
	b.Status = "canary"
	s.auditLocked("canary", actorOr(actor), b.ID, b.ArtifactDigest, fmt.Sprintf("selector=%v", sel))
	s.persistLocked()
	cp := *b
	return &cp, nil
}

func (s *Store) Promote(bindingID, actor string) (*types.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.Bindings[bindingID]
	if !ok {
		return nil, fmt.Errorf("binding not found")
	}
	// paused (and any non-canary) cannot promote — human decides revert/continue.
	if b.Status != "canary" {
		return nil, fmt.Errorf("binding must be in canary (status=%s)", b.Status)
	}
	sel := copyLabels(b.Selector.Labels)
	delete(sel, types.LabelRollout) // widen: full binding selector
	if err := s.appendTreeLocked(b, "add", sel); err != nil {
		return nil, err
	}
	b.Status = "promoted"
	s.auditLocked("promote", actorOr(actor), b.ID, b.ArtifactDigest, fmt.Sprintf("selector=%v", sel))
	s.persistLocked()
	cp := *b
	return &cp, nil
}

func (s *Store) Revert(bindingID, actor string) (*types.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.Bindings[bindingID]
	if !ok {
		return nil, fmt.Errorf("binding not found")
	}
	if b.Status != "canary" && b.Status != "promoted" && b.Status != "paused" {
		return nil, fmt.Errorf("nothing to revert (status=%s)", b.Status)
	}
	// Delete with empty selector = unload everywhere this digest was targeted.
	sel := map[string]string{}
	if err := s.appendTreeLocked(b, "delete", sel); err != nil {
		return nil, err
	}
	b.Status = "reverted"
	s.auditLocked("revert", actorOr(actor), b.ID, b.ArtifactDigest, "signed delete")
	s.persistLocked()
	cp := *b
	return &cp, nil
}

func (s *Store) appendTreeLocked(b *types.Binding, op string, sel map[string]string) error {
	if s.Signer == nil {
		return fmt.Errorf("tree signer not configured")
	}
	var prevHash string
	if len(s.Tree) > 0 {
		var err error
		prevHash, err = signer.TreeOpHash(s.Tree[len(s.Tree)-1])
		if err != nil {
			return fmt.Errorf("hash previous tree op: %w", err)
		}
	}
	opRec := types.TreeOp{
		Seq:       int64(len(s.Tree) + 1),
		PrevHash:  prevHash,
		Op:        op,
		Digest:    b.ArtifactDigest,
		Selector:  copyLabels(sel),
		BindingID: b.ID,
		At:        time.Now().UTC(),
	}
	payload, err := signer.CanonicalTreePayload(opRec)
	if err != nil {
		return err
	}
	sig, err := s.Signer.Sign(payload)
	if err != nil {
		return err
	}
	opRec.Signature = sig
	s.Tree = append(s.Tree, opRec)
	return nil
}

func (s *Store) TreeOps() []types.TreeOp {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.TreeOp, len(s.Tree))
	copy(out, s.Tree)
	return out
}

// Desired computes per-node digests from the signed tree + current inventory.
func (s *Store) Desired() types.DesiredState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.desiredLocked("")
}

// DesiredForCluster computes per-node digests restricted to nodes belonging to clusterID.
func (s *Store) DesiredForCluster(clusterID string) types.DesiredState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.desiredLocked(clusterID)
}

func (s *Store) desiredLocked(clusterID string) types.DesiredState {
	nodes := make(map[string][]string)
	for id, n := range s.Nodes {
		if clusterID != "" && n.ClusterID != clusterID {
			continue
		}
		nodes[id] = signer.ReplayDesiredForNode(s.Tree, n.Labels)
	}

	ops := make([]types.TreeOp, len(s.Tree))
	copy(ops, s.Tree)
	seq := int64(0)
	if len(ops) > 0 {
		seq = ops[len(ops)-1].Seq
	}
	pubKey := ""
	if s.Signer != nil {
		pubKey = s.Signer.PublicKeyHex()
	}
	return types.DesiredState{TreeSeq: seq, TreePubKey: pubKey, Ops: ops, Nodes: nodes}
}

func (s *Store) ListAudit() []types.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.AuditEvent, len(s.Audit))
	copy(out, s.Audit)
	return out
}

func (s *Store) StartAttestCampaign() types.AttestCampaign {
	return s.StartAttestCampaignBy("api")
}

func (s *Store) StartAttestCampaignBy(actor string) types.AttestCampaign {
	s.mu.Lock()
	defer s.mu.Unlock()
	if actor == "" {
		actor = "api"
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	c := types.AttestCampaign{
		ID:      id("attest"),
		Nonce:   hex.EncodeToString(nonce[:]),
		Status:  "open",
		Results: []types.AttestResult{},
		Created: time.Now().UTC(),
	}
	s.Campaigns[c.ID] = &c
	// Clear stale posture so prior campaigns don't linger in inventory.
	for _, n := range s.Nodes {
		n.AttestStatus = "unknown"
	}
	s.auditLocked("attest.start", actor, "", "", "nonce="+c.Nonce)
	s.persistLocked()
	return c
}

func (s *Store) ActiveAttest() *types.PendingAttest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var newest *types.AttestCampaign
	for _, c := range s.Campaigns {
		if c.Status != "open" {
			continue
		}
		if newest == nil || c.Created.After(newest.Created) {
			newest = c
		}
	}
	if newest == nil {
		return nil
	}
	return &types.PendingAttest{ID: newest.ID, Nonce: newest.Nonce}
}

func (s *Store) ListCampaigns() []types.AttestCampaign {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.AttestCampaign, 0, len(s.Campaigns))
	for _, c := range s.Campaigns {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// ValidateNodesInCluster returns ErrClusterForbidden if any nodeID is unknown
// or does not belong to clusterID.
func (s *Store) ValidateNodesInCluster(nodeIDs []string, clusterID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, nid := range nodeIDs {
		n, ok := s.Nodes[nid]
		if !ok || n.ClusterID != clusterID {
			return ErrClusterForbidden
		}
	}
	return nil
}

func (s *Store) SubmitAttest(campaignID string, results []types.AttestResult) (*types.AttestCampaign, error) {
	return s.submitAttest(campaignID, "", results)
}

// SubmitAttestForCluster enforces that every result targets a known node
// belonging to clusterID before recording attestation results.
func (s *Store) SubmitAttestForCluster(campaignID, clusterID string, results []types.AttestResult) (*types.AttestCampaign, error) {
	return s.submitAttest(campaignID, clusterID, results)
}

func (s *Store) submitAttest(campaignID, clusterID string, results []types.AttestResult) (*types.AttestCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if clusterID != "" {
		for _, r := range results {
			n, ok := s.Nodes[r.NodeID]
			if !ok || n.ClusterID != clusterID {
				return nil, ErrClusterForbidden
			}
		}
	}
	c, ok := s.Campaigns[campaignID]
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	if c.Status == "complete" {
		return nil, fmt.Errorf("campaign already complete")
	}
	byNode := map[string]types.AttestResult{}
	for _, existing := range c.Results {
		byNode[existing.NodeID] = existing
	}
	passCount, failCount := 0, 0
	for _, r := range results {
		var pass bool
		if r.Verified {
			pass = r.Pass
		} else {
			// Stub verify: quote must contain nonce; "FAIL" substring forces fail.
			pass = strings.Contains(r.Quote, c.Nonce) && !strings.Contains(strings.ToUpper(r.Quote), "FAIL")
		}
		r.Pass = pass
		r.Nonce = c.Nonce
		byNode[r.NodeID] = r
		if n, ok := s.Nodes[r.NodeID]; ok {
			if pass {
				n.AttestStatus = "pass"
				passCount++
			} else {
				n.AttestStatus = "fail"
				failCount++
			}
		}
	}
	c.Results = c.Results[:0]
	for _, r := range byNode {
		c.Results = append(c.Results, r)
	}
	sort.Slice(c.Results, func(i, j int) bool { return c.Results[i].NodeID < c.Results[j].NodeID })

	// Complete when every currently known node has a result.
	if len(s.Nodes) > 0 && len(c.Results) >= len(s.Nodes) {
		allCovered := true
		have := map[string]bool{}
		for _, r := range c.Results {
			have[r.NodeID] = true
		}
		for id := range s.Nodes {
			if !have[id] {
				allCovered = false
				break
			}
		}
		if allCovered {
			c.Status = "complete"
			s.auditLocked("attest.complete", "api", "", "", fmt.Sprintf("campaign=%s pass=%d fail=%d", c.ID, passCount, failCount))
			s.pauseOnCanaryAttestFailLocked(c)
		}
	}
	s.persistLocked()
	cp := *c
	return &cp, nil
}

// pauseOnLoadErrorsLocked pauses canary bindings when a matching canary-set
// node reports load errors for that binding's digest. Caller holds s.mu.
func (s *Store) pauseOnLoadErrorsLocked(rep types.AgentReport) {
	if len(rep.Errors) == 0 {
		return
	}
	n := rep.Node
	if n.Labels == nil {
		if existing, ok := s.Nodes[n.ID]; ok {
			n.Labels = existing.Labels
		}
	}
	for _, b := range s.Bindings {
		if b.Status != "canary" {
			continue
		}
		canarySel := mergeLabels(b.Selector.Labels, map[string]string{types.LabelRollout: types.RolloutCanary})
		if !matchSelector(n.Labels, canarySel) {
			continue
		}
		if !errorsMentionDigest(rep.Errors, b.ArtifactDigest) {
			continue
		}
		s.pauseLocked(b, "system", fmt.Sprintf("load error node=%s digest=%s errors=%v", n.ID, b.ArtifactDigest, rep.Errors))
	}
}

// pauseOnCanaryAttestFailLocked pauses canary bindings when any canary-labeled
// node failed attest verify. Caller holds s.mu.
func (s *Store) pauseOnCanaryAttestFailLocked(c *types.AttestCampaign) {
	failedCanary := false
	var failNodes []string
	for _, r := range c.Results {
		if r.Pass {
			continue
		}
		n, ok := s.Nodes[r.NodeID]
		if !ok || n.Labels[types.LabelRollout] != types.RolloutCanary {
			continue
		}
		failedCanary = true
		failNodes = append(failNodes, r.NodeID)
	}
	if !failedCanary {
		return
	}
	reason := fmt.Sprintf("attest verify fail campaign=%s canaryNodes=%v", c.ID, failNodes)
	for _, b := range s.Bindings {
		if b.Status != "canary" {
			continue
		}
		s.pauseLocked(b, "system", reason)
	}
}

// pauseLocked sets binding to paused and audits. No auto-revert. Caller holds s.mu.
func (s *Store) pauseLocked(b *types.Binding, actor, reason string) {
	if b.Status == "paused" {
		return
	}
	b.Status = "paused"
	s.auditLocked("pause", actorOr(actor), b.ID, b.ArtifactDigest, reason)
}

func errorsMentionDigest(errs []string, digest string) bool {
	if digest == "" {
		return false
	}
	for _, e := range errs {
		if strings.Contains(e, digest) {
			return true
		}
	}
	return false
}

func (s *Store) GetCampaign(id string) (*types.AttestCampaign, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.Campaigns[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

func (s *Store) auditLocked(action, actor, bindingID, digest, detail string) {
	s.Audit = append(s.Audit, types.AuditEvent{
		ID:        id("aud"),
		Action:    action,
		Actor:     actor,
		BindingID: bindingID,
		Digest:    digest,
		Detail:    detail,
		At:        time.Now().UTC(),
	})
}

func matchSelector(labels, sel map[string]string) bool {
	if len(sel) == 0 {
		return true
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func mergeLabels(a, b map[string]string) map[string]string {
	out := copyLabels(a)
	for k, v := range b {
		out[k] = v
	}
	return out
}

func copyLabels(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func actorOr(a string) string {
	if a == "" {
		return "operator"
	}
	return a
}
