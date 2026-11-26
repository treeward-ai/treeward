package types

import "time"

const (
	LabelRollout  = "treeward.ai/rollout"
	RolloutCanary = "canary"
)

type Node struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	Arch         string            `json:"arch"`
	Kernel       string            `json:"kernel"`
	Labels       map[string]string `json:"labels"`
	Loaded       []string          `json:"loaded"` // digests
	LastSeen     time.Time         `json:"lastSeen"`
	ClusterID    string            `json:"clusterId"`
	AttestStatus string            `json:"attestStatus,omitempty"` // pass|fail|unknown
}

type Artifact struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Digest string   `json:"digest"`
	Type   string   `json:"type"` // bpf|java
	Fixes  []string `json:"fixes,omitempty"`
}

type Selector struct {
	Labels map[string]string `json:"labels,omitempty"`
}

type Binding struct {
	ID             string    `json:"id"`
	ArtifactDigest string    `json:"artifactDigest"`
	Selector       Selector  `json:"selector"`
	TreeRef        string    `json:"treeRef"`
	Status         string    `json:"status"` // draft|approved|canary|promoted|reverted|paused
	ApprovedBy     string    `json:"approvedBy,omitempty"`
	ApprovedAt     time.Time `json:"approvedAt,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	BindingID string    `json:"bindingId,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	At        time.Time `json:"at"`
}

type TreeOp struct {
	Seq       int64             `json:"seq"`
	PrevHash  string            `json:"prevHash,omitempty"`
	Op        string            `json:"op"` // add|delete
	Digest    string            `json:"digest"`
	Selector  map[string]string `json:"selector"`
	Signature string            `json:"signature"`
	BindingID string            `json:"bindingId"`
	At        time.Time         `json:"at"`
}

type DesiredState struct {
	TreeSeq    int64               `json:"treeSeq"`
	TreePubKey string              `json:"treePubKey,omitempty"`
	Ops        []TreeOp            `json:"ops"`
	Nodes      map[string][]string `json:"nodes"` // nodeID -> digests that should be loaded
}

type Connector struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"clusterId"`
	Token     string    `json:"-"`
	TokenHash string    `json:"tokenHash,omitempty"`
	Enrolled  time.Time `json:"enrolledAt"`
}

type AttestResult struct {
	NodeID   string `json:"nodeId"`
	Nonce    string `json:"nonce"`
	Quote    string `json:"quote"`
	Pass     bool   `json:"pass"`
	Verified bool   `json:"verified,omitempty"`
}

type AttestCampaign struct {
	ID      string         `json:"id"`
	Nonce   string         `json:"nonce"`
	Status  string         `json:"status"` // open|complete
	Results []AttestResult `json:"results"`
	Created time.Time      `json:"createdAt"`
}

// PendingAttest is what connectors/agents poll for.
type PendingAttest struct {
	ID    string `json:"id"`
	Nonce string `json:"nonce"`
}

type EnrollRequest struct {
	BootstrapToken string `json:"bootstrapToken"`
	ClusterName    string `json:"clusterName"`
}

type EnrollResponse struct {
	ConnectorID string `json:"connectorId"`
	ClusterID   string `json:"clusterId"`
	Token       string `json:"token"`
}

type InventoryUpsert struct {
	ClusterID string `json:"clusterId"`
	Nodes     []Node `json:"nodes"`
}

type ApproveRequest struct {
	Actor string `json:"actor"`
}

type AgentReport struct {
	Node   Node     `json:"node"`
	Loaded []string `json:"loaded"`
	Errors []string `json:"errors,omitempty"`
}

type APIToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Revoked   bool       `json:"revoked"`
}

type CreateTokenRequest struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type CreateTokenResponse struct {
	APIToken
	Token string `json:"token"`
}
