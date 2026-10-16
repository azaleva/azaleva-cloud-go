package cloudtest

import (
	"crypto/ed25519"
	"regexp"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// Setup: what an installation's operators do, and the consumer API cannot. A test calls these
// methods directly; they are not HTTP routes.

var (
	poolNameRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	signerNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}\*?$`)
)

// Consumer describes a consumer for CreateConsumer.
type Consumer struct {
	// Name is unique among the server's consumers.
	Name string
	// Pools are the pools the consumer may use (empty: every pool).
	Pools []string
	// AllowedProfiles and AllowedTemplates restrict the profiles and built-in templates the
	// consumer may use (empty: all of them).
	AllowedProfiles, AllowedTemplates []string
}

// CreateConsumer adds a consumer and returns its ID. Give it an API key with CreateKey.
func (s *Server) CreateConsumer(in Consumer) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(in.Name) == "" {
		return "", errf("cloudtest: a consumer needs a name")
	}
	for _, cs := range s.st.consumers {
		if cs.name == in.Name {
			return "", errf("cloudtest: a consumer named %q exists", in.Name)
		}
	}
	pools := in.Pools
	if len(pools) == 0 {
		pools = sortedKeys(s.st.pools)
	}
	if err := s.st.checkPools(pools); err != nil {
		return "", err
	}
	cs := &consumer{id: newID("csm"), name: in.Name, state: "active", pools: append([]string(nil), pools...),
		allowedProfiles: in.AllowedProfiles, allowedTemplates: in.AllowedTemplates, notify: make(chan struct{})}
	s.st.consumers[cs.id] = cs
	return cs.id, nil
}

// SetConsumerPools replaces the pools a consumer may use.
func (s *Server) SetConsumerPools(consumer string, pools ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.st.consumer(consumer)
	if err != nil {
		return err
	}
	if len(pools) == 0 {
		return errf("cloudtest: a consumer needs at least one pool")
	}
	if err := s.st.checkPools(pools); err != nil {
		return err
	}
	cs.pools = append([]string(nil), pools...)
	return nil
}

// DisableConsumer disables a consumer: its API keys stop working.
func (s *Server) DisableConsumer(consumer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.st.consumer(consumer)
	if err != nil {
		return err
	}
	cs.state = "disabled"
	return nil
}

// SetCeilings sets a consumer's ceilings: the bounds of its project quotas and of their sum
// (zero Quotas: none).
func (s *Server) SetCeilings(consumer string, q cloud.Quotas) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.st.consumer(consumer)
	if err != nil {
		return err
	}
	for name, v := range quotaFields(q) {
		if v != nil && *v < 0 {
			return errf("cloudtest: ceiling %s is negative", name)
		}
	}
	cs.ceilings = q
	return nil
}

// CreateKey makes an API key for a consumer and returns it (ack_<id>_<secret>). Without
// scopes the key has every scope; with project it is pinned to that project.
func (s *Server) CreateKey(consumer, project string, scopes ...cloud.Scope) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.st.consumer(consumer)
	if err != nil {
		return "", err
	}
	if len(scopes) == 0 {
		scopes = cloud.AllScopes
	}
	for _, sc := range scopes {
		known := false
		for _, x := range cloud.AllScopes {
			known = known || x == sc
		}
		if !known {
			return "", errf("cloudtest: unknown scope %q", sc)
		}
	}
	if project != "" {
		if p := s.st.projects[project]; p == nil || p.consumer != cs.id {
			return "", errf("cloudtest: project %s is not the consumer's", project)
		}
	}
	id := "ack_" + randHex(6)
	token := id + "_" + randHex(24)
	s.st.keys[hashToken(token)] = &apiKey{id: id, consumer: cs.id, name: "cloudtest",
		scopes: append([]cloud.Scope(nil), scopes...), project: project, createdAt: s.now()}
	return token, nil
}

// RevokeKey revokes an API key CreateKey made: it stops working at once, and the service
// connections its tickets opened close.
func (s *Server) RevokeKey(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.st.keys[hashToken(key)]
	if k == nil {
		return errf("cloudtest: unknown API key")
	}
	if k.revokedAt == nil {
		k.revokedAt = ptrTime(s.now())
	}
	return nil
}

// AddTemplateSigner registers an Ed25519 public key that may sign the consumer's template
// packages, for the template names matching names ("runner-*" matches a prefix).
func (s *Server) AddTemplateSigner(consumer string, pub ed25519.PublicKey, names ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.st.consumer(consumer)
	if err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return errf("cloudtest: not an Ed25519 public key")
	}
	if len(names) == 0 {
		return errf("cloudtest: a signer needs at least one name")
	}
	for _, n := range names {
		if !signerNameRE.MatchString(n) {
			return errf("cloudtest: invalid name pattern %q", n)
		}
	}
	keyID := cloud.KeyID(pub)
	for _, sg := range cs.signers {
		if sg.keyID == keyID {
			return errf("cloudtest: key %s is registered", keyID)
		}
	}
	cs.signers = append(cs.signers, signer{keyID: keyID, pub: append(ed25519.PublicKey(nil), pub...),
		names: append([]string(nil), names...)})
	return nil
}

// SetWebhook makes the server POST the consumer's events to url ("": stop) and returns a new
// signing secret. The previous secret stays valid for 24 hours, as after a rotation.
func (s *Server) SetWebhook(consumer, url string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.st.consumer(consumer)
	if err != nil {
		return "", err
	}
	secret := "whsec_" + randHex(24)
	if cs.webhookSecret != "" {
		cs.prevWebhookSecret, cs.prevWebhookUntil = cs.webhookSecret, s.now().Add(24*time.Hour)
	}
	cs.webhookSecret = secret
	cs.webhookURL = nil
	if url != "" {
		cs.webhookURL = ptrStr(url)
	}
	return secret, nil
}

// Pools lists the pools' names.
func (s *Server) Pools() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedKeys(s.st.pools)
}

// CreatePool adds a pool without nodes (move nodes into it with SetNodePool).
func (s *Server) CreatePool(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !poolNameRE.MatchString(name) {
		return errf("cloudtest: invalid pool name %q", name)
	}
	if s.st.pools[name] {
		return errf("cloudtest: pool %s exists", name)
	}
	s.st.pools[name] = true
	return nil
}

// SetNodePool moves a node into another pool.
func (s *Server) SetNodePool(node, pool string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.st.nodes[node]
	if n == nil {
		return errf("cloudtest: unknown node %s", node)
	}
	if !s.st.pools[pool] {
		return errf("cloudtest: unknown pool %s", pool)
	}
	n.pool = pool
	return nil
}

// SetNodeConnected simulates a node losing (or regaining) its edge sessions: its consumers get
// node.unavailable (node.available) for their machines on it, and nothing is placed on it.
func (s *Server) SetNodeConnected(node string, up bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	n := st.nodes[node]
	if n == nil {
		return errf("cloudtest: unknown node %s", node)
	}
	if n.connected == up {
		return nil
	}
	n.connected = up
	byConsumer := map[string][]string{}
	for _, mid := range sortedKeys(st.machines) {
		m := st.machines[mid]
		if deref(m.Node) == node && m.State != cloud.MachineDestroyed {
			byConsumer[m.consumer] = append(byConsumer[m.consumer], m.ID)
		}
	}
	typ := cloud.EventNodeUnavailable
	if up {
		typ = cloud.EventNodeAvailable
	}
	for _, cid := range sortedKeys(byConsumer) {
		st.emit(cid, "", typ, "node", node, cloud.EventNodeData{Node: node, Machines: byConsumer[cid]})
	}
	return nil
}

// KillInstance kills a job, sandbox or machine as an operator would: a job ends
// killed/operator, a machine is destroyed and its consumer gets machine.operator_action.
func (s *Server) KillInstance(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	switch {
	case st.jobs[id] != nil:
		if j := st.jobs[id]; j.State != cloud.JobExited {
			st.killJob(j, "operator")
		}
	case st.sandboxes[id] != nil:
		if sb := st.sandboxes[id]; sb.State != "destroyed" {
			st.destroySandbox(sb, "operator")
		}
	case st.machines[id] != nil:
		m := st.machines[id]
		if m.State == cloud.MachineDestroyed {
			return nil
		}
		st.destroyMachine(m, "operator")
		st.emit(m.consumer, m.Project, cloud.EventMachineOperatorAction, "machine", m.ID,
			cloud.EventOperatorActionData{Action: "kill", Operator: "cloudtest", Reason: reason})
	default:
		return errf("cloudtest: unknown instance %s", id)
	}
	return nil
}

func (st *state) consumer(id string) (*consumer, error) {
	cs := st.consumers[id]
	if cs == nil {
		return nil, errf("cloudtest: unknown consumer %s", id)
	}
	return cs, nil
}

func (st *state) checkPools(pools []string) error {
	for _, p := range pools {
		if !st.pools[p] {
			return errf("cloudtest: unknown pool %q", p)
		}
	}
	return nil
}
