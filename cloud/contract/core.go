package contract

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

func (s *suite) testAuth(t *testing.T) {
	anon, _ := cloud.New(s.env.URL, "")
	_, err := anon.Consumer(s.ctx)
	wantCode(t, err, cloud.CodeUnauthenticated)

	bogus, _ := cloud.New(s.env.URL, "ack_nope_nope")
	_, err = bogus.Projects.List(s.ctx, cloud.ListOptions{})
	wantCode(t, err, cloud.CodeUnauthenticated)

	// Scopes.
	jobsOnly := s.keyWith(t, s.a, "", cloud.ScopeJobs)
	_, err = jobsOnly.Machines.List(s.ctx, cloud.ListOptions{})
	e := wantCode(t, err, cloud.CodeScopeMissing)
	if e.Scope != string(cloud.ScopeMachines) {
		t.Fatalf("scope_missing names %q, want machines", e.Scope)
	}
	if _, err := jobsOnly.Jobs.List(s.ctx, cloud.ListOptions{}); err != nil {
		t.Fatalf("jobs scope: %v", err)
	}
	if _, err := jobsOnly.Profiles.List(s.ctx, ""); err != nil {
		t.Fatalf("profiles need no scope: %v", err)
	}

	// Revocation is immediate.
	key, err := s.prov.CreateKey(s.ctx, s.a.id, "", []cloud.Scope{cloud.ScopeProjects})
	provisioned(t, err)
	rc, _ := cloud.New(s.env.URL, key)
	if _, err := rc.Projects.List(s.ctx, cloud.ListOptions{}); err != nil {
		t.Fatal(err)
	}
	provisioned(t, s.prov.RevokeKey(s.ctx, s.a.id, key))
	_, err = rc.Projects.List(s.ctx, cloud.ListOptions{})
	wantCode(t, err, cloud.CodeUnauthenticated)

	// A disabled consumer's keys stop working.
	tmp := s.newTenant(t, "disabled")
	provisioned(t, s.prov.DisableConsumer(s.ctx, tmp.id))
	_, err = tmp.c.Projects.List(s.ctx, cloud.ListOptions{})
	wantCode(t, err, cloud.CodeUnauthenticated)
}

func mustJSON(t testing.TB, v any) string {
	b, err := json.Marshal(v)
	must(t, err)
	return string(b)
}

func (s *suite) testConsumerSelf(t *testing.T) {
	me, err := s.a.c.Consumer(s.ctx)
	must(t, err)
	if me.ID != s.a.id || me.Name != s.a.name || len(me.Pools) != 2 || len(me.Key.Scopes) != len(cloud.AllScopes) {
		t.Fatalf("consumer self: %+v", me)
	}
}

func (s *suite) testErrors(t *testing.T) {
	// The raw problem document: content type, members, retryable.
	req, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, strings.TrimSuffix(strings.TrimRight(s.env.URL, "/"), "/v1")+"/v1/jobs/job_doesnotexist", nil)
	req.Header.Set("Authorization", "Bearer "+s.a.key)
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != 404 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
		t.Fatalf("status %d content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var raw map[string]any
	must(t, json.NewDecoder(resp.Body).Decode(&raw))
	for _, k := range []string{"type", "title", "status", "code", "retryable"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("problem lacks %q: %v", k, raw)
		}
	}
	if raw["code"] != "not_found" || raw["retryable"] != false || raw["status"] != float64(404) {
		t.Fatalf("problem: %v", raw)
	}

	// Validation errors name the field.
	_, err = s.a.c.Projects.Create(s.ctx, cloud.ProjectCreate{Name: ""})
	e := wantCode(t, err, cloud.CodeInvalidRequest)
	if len(e.Errors) == 0 || e.Errors[0].Field != "name" {
		t.Fatalf("errors[]: %+v", e.Errors)
	}
	// Unknown pool for the consumer.
	_, err = s.a.c.Projects.Create(s.ctx, cloud.ProjectCreate{Name: "x", Pool: "no-such-pool"})
	wantCode(t, err, cloud.CodeInvalidRequest)
}

func (s *suite) testProjects(t *testing.T) {
	c := s.a.c
	ext := "ext-" + s.tag
	var meta cloud.ResponseMeta
	p, err := c.Projects.Create(s.ctx, cloud.ProjectCreate{Name: "projects", ExternalID: ext, Pool: s.pool, Labels: cloud.Labels{"team": "x"}}, cloud.WithResponse(&meta))
	must(t, err)
	if meta.StatusCode != 201 || !strings.HasPrefix(p.ID, "prj_") || p.Version < 1 || !p.OperatorTerminal || p.State != "active" {
		t.Fatalf("create: %d %+v", meta.StatusCode, p)
	}
	if meta.ETag != strconv.Quote(strconv.FormatInt(p.Version, 10)) {
		t.Fatalf("ETag %q for version %d", meta.ETag, p.Version)
	}
	// Idempotent on external_id: the same request returns the project with 200 …
	again, err := c.Projects.Create(s.ctx, cloud.ProjectCreate{Name: "projects", ExternalID: ext, Pool: s.pool, Labels: cloud.Labels{"team": "x"}}, cloud.WithResponse(&meta))
	must(t, err)
	if again.ID != p.ID || meta.StatusCode != 200 {
		t.Fatalf("external_id replay: %d %s vs %s", meta.StatusCode, again.ID, p.ID)
	}
	// … a different one is a conflict.
	_, err = c.Projects.Create(s.ctx, cloud.ProjectCreate{Name: "other", ExternalID: ext, Pool: s.pool})
	wantCode(t, err, cloud.CodeConflict)

	// Get by ID and by external ID.
	byExt, err := c.Projects.Get(s.ctx, ext)
	must(t, err)
	if byExt.ID != p.ID {
		t.Fatal("get by external_id")
	}
	// Preconditions.
	up, err := c.Projects.Update(s.ctx, p.ID, cloud.ProjectUpdate{Name: cloud.String("renamed")}, cloud.IfMatch(p.Version))
	must(t, err)
	if up.Name != "renamed" || up.Version <= p.Version {
		t.Fatalf("update: %+v", up)
	}
	_, err = c.Projects.Update(s.ctx, p.ID, cloud.ProjectUpdate{Name: cloud.String("stale")}, cloud.IfMatch(p.Version))
	wantCode(t, err, cloud.CodePreconditionFailed)
	// Unconditional writes are allowed.
	_, err = c.Projects.Update(s.ctx, p.ID, cloud.ProjectUpdate{Labels: cloud.Labels{"team": "y"}})
	must(t, err)

	// Lists: label filter and pagination.
	for i := 0; i < 3; i++ {
		s.newProject(t, s.a, cloud.ProjectCreate{Name: "page", Labels: cloud.Labels{"page": s.tag}})
	}
	first, err := c.Projects.List(s.ctx, cloud.ListOptions{Limit: 2, Labels: cloud.Labels{"page": s.tag}})
	must(t, err)
	if len(first.Data) != 2 || first.NextCursor == nil {
		t.Fatalf("page 1: %d items, cursor %v", len(first.Data), first.NextCursor)
	}
	second, err := c.Projects.List(s.ctx, cloud.ListOptions{Limit: 2, Cursor: *first.NextCursor, Labels: cloud.Labels{"page": s.tag}})
	must(t, err)
	if len(second.Data) != 1 || second.NextCursor != nil {
		t.Fatalf("page 2: %d items, cursor %v", len(second.Data), second.NextCursor)
	}
	n := 0
	for _, err := range cloud.Iterate(s.ctx, cloud.ListOptions{Limit: 1, Labels: cloud.Labels{"page": s.tag}}, c.Projects.List) {
		must(t, err)
		n++
	}
	if n != 3 {
		t.Fatalf("iterate: %d", n)
	}

	// Pool changes stay within the consumer's pools.
	_, err = c.Projects.SetPool(s.ctx, p.ID, s.empty)
	must(t, err)
	_, err = c.Projects.SetPool(s.ctx, p.ID, "not-mine")
	wantCode(t, err, cloud.CodeInvalidRequest)
	_, err = c.Projects.SetPool(s.ctx, p.ID, s.pool)
	must(t, err)

	// Delete: refused with live resources, then allowed.
	m := s.machine(t, s.a, p.ID, nil)
	err = c.Projects.Delete(s.ctx, p.ID)
	wantCode(t, err, cloud.CodeConflict)
	_, err = c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, s.a, m.ID, cloud.MachineDestroyed)
	must(t, c.Projects.Delete(s.ctx, p.ID))
	_, err = c.Projects.Get(s.ctx, p.ID)
	wantCode(t, err, cloud.CodeNotFound)
}

func (s *suite) testIdempotency(t *testing.T) {
	c := s.a.c
	in := cloud.JobCreate{Project: s.a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"echo", "once"}}}
	key := "contract-" + s.tag
	var m1, m2 cloud.ResponseMeta
	var j1 *cloud.Job
	var err error
	s.placed(t, func() (err error) {
		j1, err = c.Jobs.Create(s.ctx, in, cloud.WithIdempotencyKey(key), cloud.WithResponse(&m1))
		return err
	})
	j2, err := c.Jobs.Create(s.ctx, in, cloud.WithIdempotencyKey(key), cloud.WithResponse(&m2))
	must(t, err)
	if j1.ID != j2.ID || m1.Replayed || !m2.Replayed || m2.StatusCode != m1.StatusCode {
		t.Fatalf("replay: %s/%v %s/%v", j1.ID, m1.Replayed, j2.ID, m2.Replayed)
	}
	// The same key with another body.
	in2 := in
	in2.Exec.Argv = []string{"echo", "twice"}
	_, err = c.Jobs.Create(s.ctx, in2, cloud.WithIdempotencyKey(key))
	wantCode(t, err, cloud.CodeIdempotencyMismatch)
	// Keys are per consumer: B's use of the same key is independent.
	inB := in
	inB.Project = s.b.project.ID
	jb, err := s.b.c.Jobs.Create(s.ctx, inB, cloud.WithIdempotencyKey(key))
	must(t, err)
	if jb.ID == j1.ID {
		t.Fatal("idempotency keys leak across consumers")
	}
	// Without a caller key, the SDK sends a fresh one per call: two jobs.
	j3, err := c.Jobs.Create(s.ctx, in)
	must(t, err)
	j4, err := c.Jobs.Create(s.ctx, in)
	must(t, err)
	if j3.ID == j4.ID {
		t.Fatal("two calls without a key created one job")
	}
	// DELETE replays too.
	m := s.machine(t, s.a, s.a.project.ID, nil)
	_, err = c.Machines.Delete(s.ctx, m.ID, cloud.WithIdempotencyKey("del-"+s.tag))
	must(t, err)
	var md cloud.ResponseMeta
	_, err = c.Machines.Delete(s.ctx, m.ID, cloud.WithIdempotencyKey("del-"+s.tag), cloud.WithResponse(&md))
	must(t, err)
	if !md.Replayed {
		t.Fatal("DELETE was not replayed")
	}
	for _, id := range []string{j1.ID, j3.ID, j4.ID} {
		s.waitJob(t, s.a, id)
	}
	s.waitJob(t, s.b, jb.ID)
}

func (s *suite) testQuotas(t *testing.T) {
	c := s.a.c
	p := s.newProject(t, s.a, cloud.ProjectCreate{Quotas: &cloud.Quotas{ConcurrentJobs: cloud.Int(1), Machines: cloud.Int(1)}})
	q, err := c.Projects.Quotas(s.ctx, p.ID)
	must(t, err)
	if q.Limits.ConcurrentJobs == nil || *q.Limits.ConcurrentJobs != 1 {
		t.Fatalf("quotas: %+v", q.Limits)
	}
	j := s.job(t, s.a, p.ID, []string{"sleep", "30"}, nil)
	_, err = c.Jobs.Create(s.ctx, cloud.JobCreate{Project: p.ID, Template: s.jobTemplate, Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	e := wantCode(t, err, cloud.CodeQuotaExceeded)
	if e.Quota == nil || e.Quota.Name != "concurrent_jobs" || e.Quota.Limit != 1 || e.Quota.Used != 1 || e.Retryable {
		t.Fatalf("quota violation: %+v", e.Quota)
	}
	_, err = c.Jobs.Cancel(s.ctx, j.ID)
	must(t, err)
	s.waitJob(t, s.a, j.ID)
	j2 := s.job(t, s.a, p.ID, []string{"true"}, nil)
	s.waitJob(t, s.a, j2.ID)

	s.machine(t, s.a, p.ID, nil)
	_, err = c.Machines.Create(s.ctx, cloud.MachineCreate{Project: p.ID, Template: s.machineTemplate, Profile: s.machineProfile})
	e = wantCode(t, err, cloud.CodeQuotaExceeded)
	if e.Quota.Name != "machines" {
		t.Fatalf("quota name %s", e.Quota.Name)
	}

	// Ceilings bound project quotas and the sum over projects.
	provisioned(t, s.prov.SetCeilings(s.ctx, s.b.id, cloud.Quotas{Machines: cloud.Int(1)}))
	defer s.prov.SetCeilings(context.Background(), s.b.id, cloud.Quotas{})
	_, err = s.b.c.Projects.SetQuotas(s.ctx, s.b.project.ID, cloud.Quotas{Machines: cloud.Int(5)})
	e = wantCode(t, err, cloud.CodeQuotaExceeded)
	if e.Quota.Name != "machines" || e.Quota.Scope != "consumer" {
		t.Fatalf("ceiling violation: %+v", e.Quota)
	}
	pb := s.newProject(t, s.b, cloud.ProjectCreate{})
	mb := s.machine(t, s.b, pb.ID, nil)
	_, err = s.b.c.Machines.Create(s.ctx, cloud.MachineCreate{Project: s.b.project.ID, Template: s.machineTemplate, Profile: s.machineProfile})
	e = wantCode(t, err, cloud.CodeQuotaExceeded)
	if e.Quota.Scope != "consumer" {
		t.Fatalf("sum over projects: %+v", e.Quota)
	}
	_, err = s.b.c.Machines.Delete(s.ctx, mb.ID)
	must(t, err)
}

func (s *suite) testCapacity(t *testing.T) {
	c := s.a.c
	capa, err := c.Capacity(s.ctx, s.pool, s.jobProfile)
	must(t, err)
	if capa.NodesSchedulable < 2 || capa.JobSlotsFree <= 0 {
		t.Fatalf("capacity: %+v", capa)
	}
	// A pool without schedulable nodes: capacity_exhausted, retryable.
	p := s.newProject(t, s.a, cloud.ProjectCreate{Pool: s.empty})
	_, err = noRetryClient(c).Jobs.Create(s.ctx, cloud.JobCreate{Project: p.ID, Template: s.jobTemplate, Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	e := wantCode(t, err, cloud.CodeCapacityExhausted)
	if !e.Retryable {
		t.Fatal("capacity_exhausted must be retryable")
	}
	_, err = c.Capacity(s.ctx, "not-mine", "")
	wantCode(t, err, cloud.CodeNotFound)
}

func (s *suite) testTenancy(t *testing.T) {
	a, b := s.a, s.b
	// A's resources of every kind.
	m := s.machine(t, a, a.project.ID, func(in *cloud.MachineCreate) { in.Address = true })
	ex, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"echo", "x"}})
	must(t, err)
	term, err := a.c.Machines.CreateTerminal(s.ctx, m.ID, cloud.TerminalCreate{Actor: "user-1"})
	must(t, err)
	j := s.job(t, a, a.project.ID, []string{"echo", "secret-output"}, nil)
	s.waitJob(t, a, j.ID)
	sb, err := a.c.Sandboxes.Create(s.ctx, cloud.SandboxCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile})
	must(t, err)
	_, err = a.c.Presets.PutProject(s.ctx, a.project.ID, "tenancy", cloud.PresetPut{Domains: []string{"example.com"}})
	must(t, err)
	addr := *s.waitMachine(t, a, m.ID, cloud.MachineReady).Address

	notFound := func(what string, err error) {
		t.Helper()
		if !cloud.IsCode(err, cloud.CodeNotFound) {
			t.Fatalf("%s: B got %v, want not_found", what, err)
		}
	}
	_, err = b.c.Projects.Get(s.ctx, a.project.ID)
	notFound("project by id", err)
	_, err = b.c.Projects.Get(s.ctx, *a.project.ExternalID)
	notFound("project by external id", err)
	_, err = b.c.Projects.Update(s.ctx, a.project.ID, cloud.ProjectUpdate{Name: cloud.String("x")})
	notFound("project update", err)
	_, err = b.c.Jobs.Get(s.ctx, j.ID)
	notFound("job", err)
	_, err = b.c.Jobs.Cancel(s.ctx, j.ID)
	notFound("job cancel", err)
	r, err := b.c.Jobs.Output(s.ctx, j.ID, cloud.OutputOptions{NoFollow: true})
	must(t, err)
	_, err = io.ReadAll(r)
	notFound("job output", err)
	_, err = b.c.Sandboxes.Get(s.ctx, sb.ID)
	notFound("sandbox", err)
	_, err = b.c.Machines.Get(s.ctx, m.ID)
	notFound("machine", err)
	_, err = b.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"echo"}})
	notFound("machine exec", err)
	_, err = b.c.Machines.GetExec(s.ctx, m.ID, ex.ID)
	notFound("exec", err)
	_, err = b.c.Machines.ReadFile(s.ctx, m.ID, "/workspace", cloud.FileOptions{})
	notFound("files", err)
	_, err = b.c.Machines.GetTerminal(s.ctx, m.ID, term.ID)
	notFound("terminal", err)
	_, err = b.c.Machines.SetEgress(s.ctx, m.ID, cloud.EgressPut{EgressPolicy: cloud.EgressPolicy{Mode: cloud.EgressNone}})
	notFound("egress", err)
	_, err = b.c.Addresses.Get(s.ctx, addr)
	notFound("address", err)
	_, err = b.c.Presets.GetProject(s.ctx, a.project.ID, "tenancy")
	notFound("preset", err)
	_, err = b.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	notFound("job in A's project", err)
	_, err = b.c.Projects.ReportReferences(s.ctx, a.project.ID, []string{})
	notFound("references", err)

	// Lists, events and usage never show A's resources to B.
	for _, list := range []func() (string, error){
		func() (string, error) {
			p, err := b.c.Projects.List(s.ctx, cloud.ListOptions{Limit: 200})
			return mustJSON(t, p), err
		},
		func() (string, error) {
			p, err := b.c.Jobs.List(s.ctx, cloud.ListOptions{Limit: 200})
			return mustJSON(t, p), err
		},
		func() (string, error) {
			p, err := b.c.Machines.List(s.ctx, cloud.ListOptions{Limit: 200})
			return mustJSON(t, p), err
		},
		func() (string, error) {
			p, err := b.c.Sandboxes.List(s.ctx, cloud.ListOptions{Limit: 200})
			return mustJSON(t, p), err
		},
		func() (string, error) {
			p, err := b.c.Addresses.List(s.ctx, cloud.ListOptions{Limit: 200})
			return mustJSON(t, p), err
		},
		func() (string, error) {
			p, err := b.c.Events.List(s.ctx, cloud.EventListOptions{Limit: 1000})
			return mustJSON(t, p), err
		},
	} {
		out, err := list()
		must(t, err)
		for _, id := range []string{a.project.ID, j.ID, m.ID, sb.ID, addr, ex.ID, term.ID} {
			if strings.Contains(out, id) {
				t.Fatalf("B's listing contains A's %s", id)
			}
		}
	}
	// A list filtered by A's project is not_found for B (no existence oracle).
	_, err = b.c.Machines.List(s.ctx, cloud.ListOptions{Project: a.project.ID})
	notFound("list filtered by A's project", err)
	_, err = a.c.Machines.CloseTerminal(s.ctx, m.ID, term.ID)
	must(t, err)
}

func (s *suite) testPinnedKey(t *testing.T) {
	p1 := s.newProject(t, s.a, cloud.ProjectCreate{})
	p2 := s.newProject(t, s.a, cloud.ProjectCreate{})
	pinned := s.keyWith(t, s.a, p1.ID, cloud.ScopeProjects, cloud.ScopeJobs)
	if _, err := pinned.Projects.Get(s.ctx, p1.ID); err != nil {
		t.Fatal(err)
	}
	_, err := pinned.Projects.Get(s.ctx, p2.ID)
	wantCode(t, err, cloud.CodeNotFound)
	l, err := pinned.Projects.List(s.ctx, cloud.ListOptions{Limit: 200})
	must(t, err)
	if len(l.Data) != 1 || l.Data[0].ID != p1.ID {
		t.Fatalf("a pinned key lists %d projects", len(l.Data))
	}
	_, err = pinned.Projects.Create(s.ctx, cloud.ProjectCreate{Name: "nope"})
	wantCode(t, err, cloud.CodeForbidden)
	me, err := pinned.Consumer(s.ctx)
	must(t, err)
	if me.Key.Project == nil || *me.Key.Project != p1.ID {
		t.Fatalf("pinned key project: %v", me.Key.Project)
	}
}
