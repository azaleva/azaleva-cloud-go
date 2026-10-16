// Package contract is the Azaleva Cloud API contract suite. It runs against any implementation
// of the API through the Go SDK: the in-memory fake (cloudtest) and the real server (with its
// own mock driver or real machines). Both must pass it, so the fake cannot drift from the
// product.
//
// The suite runs as consumers (two of them, to prove tenancy isolation). What the consumer API
// cannot do itself (consumers, their keys, pools, ceilings, signers, webhooks) it asks of the
// Env's Provisioner. Tests that need to move the server's clock or simulate node failures run
// only when the Env provides those hooks.
//
// Programs run by jobs and execs use the mock driver's commands (see docs/MOCK-DRIVER.md).
package contract

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// Provisioner does the setup the consumer API cannot: the consumers, API keys, pools and
// consumer settings an installation's operators manage. cloudtest.Server has a method for each
// (see its contract test); for a running installation, wire it to the installation's own
// tooling. A method may return errors.ErrUnsupported: the cases that need it skip.
type Provisioner interface {
	// Pools returns a pool with at least two schedulable nodes and a pool without nodes.
	Pools(ctx context.Context) (pool, empty string, err error)
	// CreateConsumer creates a consumer that may use pools and returns its ID and an API key
	// with every scope.
	CreateConsumer(ctx context.Context, name string, pools []string) (id, key string, err error)
	// CreateKey creates another API key of a consumer with scopes, pinned to project unless it
	// is empty.
	CreateKey(ctx context.Context, consumer, project string, scopes []cloud.Scope) (string, error)
	// RevokeKey revokes a key of the consumer's.
	RevokeKey(ctx context.Context, consumer, key string) error
	// DisableConsumer disables a consumer (its keys stop working).
	DisableConsumer(ctx context.Context, consumer string) error
	// SetCeilings sets a consumer's ceilings (zero Quotas: none).
	SetCeilings(ctx context.Context, consumer string, q cloud.Quotas) error
	// AddTemplateSigner registers a key that signs the consumer's template packages whose
	// names match names.
	AddTemplateSigner(ctx context.Context, consumer string, pub ed25519.PublicKey, names []string) error
	// SetWebhook points the consumer's webhooks at url and returns their signing secret.
	SetWebhook(ctx context.Context, consumer, url string) (secret string, err error)
}

// Env describes the implementation under test.
type Env struct {
	// URL is the API base URL (with or without /v1).
	URL string
	// Provisioner sets up consumers, keys and pools (required).
	Provisioner Provisioner

	// Advance moves the server's clock forward (optional; TTL, lease, retention, usage and
	// reference-report tests need it).
	Advance func(time.Duration)
	// SetNodeConnected simulates a node losing its edge sessions (optional).
	SetNodeConnected func(node string, up bool) error
	// WebhooksReachable says the server can POST to a local httptest receiver.
	WebhooksReachable bool
	// NoEgressBinding says the nodes do not bind egress allowlists yet (real nodes before the
	// network phase): the binding failure marker (docs/MOCK-DRIVER.md, "Deterministic failures")
	// is not checked.
	NoEgressBinding bool
	// RealRecipes makes the suite's template packages real recipes for the pinned template SDK
	// (see the Azaleva Cloud documentation) instead of the mock driver's: a minimal Debian-based job
	// template, and one that fails to build. Real nodes need it.
	RealRecipes bool
	// MachineWait bounds each wait for a machine state (create, start, restart, migrate); 0:
	// 120 s. A migration carries /workspace between nodes, which takes minutes over a slow
	// link between them.
	MachineWait time.Duration
	// BuildWait bounds how long a create retries 409 template_not_ready while the template's
	// build for the profile is queued or building (decision C38: a profile added or resized is
	// built after the fact, and placement waits for it); 0: 20 minutes.
	BuildWait time.Duration
	// SetServiceListening makes a machine's declared service stop or start accepting
	// connections (optional; the transport's app_not_listening and readiness checks need it).
	SetServiceListening func(machine, service string, up bool) error
	// ServiceTemplate names an existing ready machine template that declares exactly the
	// service web on port 8080 (optional, real nodes): the transport case then uses it instead of
	// building the echo recipe, and starts the echo service in its machines through the API.
	ServiceTemplate string
	// RemoveService removes a declared service from a machine, as a reset onto a template
	// version without it (optional; else the suite closes connections by deleting the machine).
	RemoveService func(machine, service string) error
}

// suite is the shared state of one run.
type suite struct {
	env                          Env
	ctx                          context.Context
	prov                         Provisioner
	pool                         string // a pool with at least two schedulable nodes
	empty                        string // a pool without nodes (capacity_exhausted)
	a, b                         *tenant
	jobProfile, machineProfile   string
	jobTemplate, machineTemplate string
	signer                       ed25519.PrivateKey
	tag                          string
}

// tenant is one test consumer with a full-scope key and a project.
type tenant struct {
	id      string
	c       *cloud.Client // all scopes
	key     string
	project *cloud.Project
	name    string
}

// Run runs the contract suite.
func Run(t *testing.T, env Env) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute+4*env.MachineWait)
	defer cancel()
	if env.Provisioner == nil {
		t.Fatal("contract: Env.Provisioner is required")
	}
	s := &suite{env: env, ctx: ctx, prov: env.Provisioner, tag: randTag()}
	s.setup(t)

	t.Run("Auth", s.testAuth)
	t.Run("ConsumerSelf", s.testConsumerSelf)
	t.Run("Errors", s.testErrors)
	t.Run("Projects", s.testProjects)
	t.Run("Idempotency", s.testIdempotency)
	t.Run("Quotas", s.testQuotas)
	t.Run("Jobs", s.testJobs)
	t.Run("JobOutput", s.testJobOutput)
	t.Run("JobIsolation", s.testJobSupervisor)
	t.Run("Sandboxes", s.testSandboxes)
	t.Run("Machines", s.testMachines)
	t.Run("MachineDisk", s.testMachineDisk)
	t.Run("ExecConcurrency", s.testExecConcurrency)
	t.Run("Files", s.testFiles)
	t.Run("Terminals", s.testTerminals)
	t.Run("ServiceTransport", s.testServiceTransport)
	t.Run("Network", s.testNetwork)
	t.Run("Presets", s.testPresets)
	t.Run("Templates", s.testTemplates)
	t.Run("ProfileTemplates", s.testProfileTemplates)
	t.Run("Capacity", s.testCapacity)
	t.Run("Events", s.testEvents)
	t.Run("Webhooks", s.testWebhooks)
	t.Run("Tenancy", s.testTenancy)
	t.Run("ProjectPinnedKey", s.testPinnedKey)
	t.Run("Usage", s.testUsage)
	t.Run("Expiry", s.testExpiry)
	t.Run("References", s.testReferences)
	t.Run("NodeUnavailable", s.testNodeUnavailable)
}

func randTag() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// provisioned fails on err, or skips the test when the Provisioner does not support the call.
func provisioned(t testing.TB, err error) {
	t.Helper()
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skipf("the Provisioner cannot do this: %v", err)
	}
	must(t, err)
}

// wantCode fails unless err is a problem with code (and its HTTP status).
func wantCode(t testing.TB, err error, code cloud.Code) *cloud.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got success", code)
	}
	e, ok := cloud.AsError(err)
	if !ok {
		t.Fatalf("want %s, got non-problem error %v", code, err)
	}
	if e.Code != code {
		t.Fatalf("want %s, got %s (%s)", code, e.Code, e.Detail)
	}
	if want := cloud.CodeStatus[code]; e.Status != want {
		t.Fatalf("%s: status %d, want %d", code, e.Status, want)
	}
	if e.Type != cloud.ProblemType(code) || e.Title == "" {
		t.Fatalf("%s: problem type %q title %q", code, e.Type, e.Title)
	}
	return e
}

func (s *suite) setup(t *testing.T) {
	var err error
	s.pool, s.empty, err = s.prov.Pools(s.ctx)
	must(t, err)
	if s.pool == "" || s.empty == "" {
		t.Fatal("the contract suite needs a pool with at least two schedulable nodes and a pool without nodes")
	}
	_, s.signer, err = ed25519.GenerateKey(rand.Reader)
	must(t, err)
	s.a = s.newTenant(t, "a")
	s.b = s.newTenant(t, "b")

	for _, kind := range []cloud.TemplateKind{cloud.KindJob, cloud.KindMachine} {
		profs, err := s.a.c.Profiles.List(s.ctx, kind)
		must(t, err)
		if len(profs) == 0 {
			t.Fatalf("no %s profile", kind)
		}
		tpls, err := s.a.c.Templates.List(s.ctx, cloud.TemplateListOptions{Kind: kind})
		must(t, err)
		// The smallest profile of the kind that runs in the pool and has the suite's defaults
		// (no default mode or user, no forced restart policy, every template: the suite's own
		// template packages use it too), with a ready built-in template it allows.
		var best *cloud.Profile
		ref := ""
		for _, tp := range tpls.Data {
			if tp.Origin != "builtin" || tp.State != "ready" {
				continue
			}
			for i, p := range profs {
				if !p.AllowsTemplate(tp.Name) || !p.AllowsPool(s.pool) || p.DefaultMode != "" || p.DefaultUser != "" ||
					p.Restart != "" || len(p.Templates) > 0 {
					continue
				}
				if best == nil || p.MemoryMiB < best.MemoryMiB {
					best, ref = &profs[i], tp.Ref()
				}
			}
			if best != nil {
				break
			}
		}
		if best == nil {
			t.Fatalf("no ready built-in %s template with a profile of pool %s", kind, s.pool)
		}
		if kind == cloud.KindJob {
			s.jobProfile, s.jobTemplate = best.Name, ref
		} else {
			s.machineProfile, s.machineTemplate = best.Name, ref
		}
	}
}

func (s *suite) newTenant(t *testing.T, name string) *tenant {
	cname := "contract-" + name + "-" + s.tag
	id, key, err := s.prov.CreateConsumer(s.ctx, cname, []string{s.pool, s.empty})
	provisioned(t, err)
	if !strings.HasPrefix(key, "ack_") || strings.Count(key, "_") < 2 {
		t.Fatalf("API key %q does not have the form ack_<id>_<secret>", key)
	}
	c, err := cloud.New(s.env.URL, key)
	must(t, err)
	tn := &tenant{id: id, c: c, key: key, name: cname}
	tn.project, err = c.Projects.Create(s.ctx, cloud.ProjectCreate{Name: "main", ExternalID: "ext-main-" + name, Pool: s.pool})
	must(t, err)
	return tn
}

// keyWith creates another key for a tenant with the given scopes (and optional project pin).
func (s *suite) keyWith(t *testing.T, tn *tenant, project string, scopes ...cloud.Scope) *cloud.Client {
	key, err := s.prov.CreateKey(s.ctx, tn.id, project, scopes)
	provisioned(t, err)
	c, err := cloud.New(s.env.URL, key)
	must(t, err)
	return c
}

func (s *suite) needAdvance(t *testing.T) {
	if s.env.Advance == nil {
		t.Skip("needs Env.Advance (a controllable clock)")
	}
}

// newProject creates a fresh project for one test.
func (s *suite) newProject(t *testing.T, tn *tenant, pc cloud.ProjectCreate) *cloud.Project {
	t.Helper()
	if pc.Name == "" {
		pc.Name = t.Name()
	}
	if pc.Pool == "" {
		pc.Pool = s.pool
	}
	p, err := tn.c.Projects.Create(s.ctx, pc)
	must(t, err)
	return p
}

func (s *suite) job(t *testing.T, tn *tenant, project string, argv []string, mod func(*cloud.JobCreate)) *cloud.Job {
	t.Helper()
	in := cloud.JobCreate{Project: project, Template: s.jobTemplate, Profile: s.jobProfile, Exec: cloud.JobExec{Argv: argv}}
	if mod != nil {
		mod(&in)
	}
	var j *cloud.Job
	s.placed(t, func() (err error) { j, err = tn.c.Jobs.Create(s.ctx, in); return err })
	return j
}

// placed runs a create until it is not refused with a retryable template_not_ready (the
// template's build for the profile is queued or building, C38), for at most BuildWait, and
// fails the test on any other error. A retryable refusal is not stored under an idempotency
// key, so a keyed create may be retried with its key.
func (s *suite) placed(t testing.TB, create func() error) {
	t.Helper()
	wait := s.env.BuildWait
	if wait <= 0 {
		wait = 20 * time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		err := create()
		e, ok := cloud.AsError(err)
		if err == nil || !ok || e.Code != cloud.CodeTemplateNotReady || !e.Retryable || time.Now().After(deadline) {
			must(t, err)
			return
		}
		d := min(max(e.RetryDelay(), time.Second), 15*time.Second)
		select {
		case <-s.ctx.Done():
			must(t, err)
			return
		case <-time.After(d):
		}
	}
}

func (s *suite) waitJob(t *testing.T, tn *tenant, id string) *cloud.Job {
	t.Helper()
	ctx, cancel := context.WithTimeout(s.ctx, 120*time.Second)
	defer cancel()
	j, err := tn.c.Jobs.Wait(ctx, id)
	must(t, err)
	return j
}

func (s *suite) machine(t *testing.T, tn *tenant, project string, mod func(*cloud.MachineCreate)) *cloud.Machine {
	t.Helper()
	in := cloud.MachineCreate{Project: project, Template: s.machineTemplate, Profile: s.machineProfile}
	if mod != nil {
		mod(&in)
	}
	var m *cloud.Machine
	s.placed(t, func() (err error) { m, err = tn.c.Machines.Create(s.ctx, in); return err })
	// A test that fails before its own delete must not leave the machine behind: against a
	// real implementation it keeps holding its node's disk (and memory) for every later run,
	// and placements there fail for room the suite itself took. Deleting a machine the test
	// already deleted, or of a tenant it removed, fails harmlessly.
	id := m.ID
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 30*time.Second)
		defer cancel()
		_, _ = tn.c.Machines.Delete(ctx, id)
	})
	if m.State != cloud.MachineCreating && m.State != cloud.MachineReady {
		t.Fatalf("new machine state %s", m.State)
	}
	return s.waitMachine(t, tn, m.ID, cloud.MachineReady)
}

func (s *suite) waitMachine(t *testing.T, tn *tenant, id string, states ...string) *cloud.Machine {
	t.Helper()
	wait := s.env.MachineWait
	if wait <= 0 {
		wait = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(s.ctx, wait)
	defer cancel()
	m, err := tn.c.Machines.WaitState(ctx, id, states...)
	if err != nil {
		t.Fatalf("machine %s did not reach %v: %v", id, states, err)
	}
	return m
}

func outcome(j *cloud.Job) string {
	if j.Outcome == nil {
		return ""
	}
	r := *j.Outcome
	if j.OutcomeReason != nil {
		r += "/" + *j.OutcomeReason
	}
	return r
}

// latestSeq returns the tenant's current event cursor.
func (s *suite) latestSeq(t *testing.T, tn *tenant) int64 {
	t.Helper()
	l, err := tn.c.Events.List(s.ctx, cloud.EventListOptions{Limit: 1})
	must(t, err)
	return l.LatestSeq
}

// waitEvent reads events after `after` until one matches, or fails after 60 s (real nodes are slower than the mock).
func (s *suite) waitEvent(t *testing.T, tn *tenant, after int64, match func(cloud.Event) bool) cloud.Event {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		l, err := tn.c.Events.List(s.ctx, cloud.EventListOptions{After: after, Wait: 2, Limit: 1000})
		must(t, err)
		for _, ev := range l.Data {
			if match(ev) {
				return ev
			}
		}
		after = l.NextAfter
	}
	t.Fatalf("no matching event after seq %d", after)
	return cloud.Event{}
}

func eventFor(typ cloud.EventType, id string) func(cloud.Event) bool {
	return func(ev cloud.Event) bool { return ev.Type == typ && ev.Resource.ID == id }
}
