package contract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

func (s *suite) output(t *testing.T, tn *tenant, jobID string, o cloud.OutputOptions) string {
	t.Helper()
	r, err := tn.c.Jobs.Output(s.ctx, jobID, o)
	must(t, err)
	b, err := io.ReadAll(r)
	must(t, err)
	return string(b)
}

func (s *suite) testJobs(t *testing.T) {
	a := s.a
	after := s.latestSeq(t, a)
	j := s.job(t, a, a.project.ID, []string{"echo", "hello", "world"}, func(in *cloud.JobCreate) {
		in.Labels = cloud.Labels{"kind": "test"}
	})
	if !strings.HasPrefix(j.ID, "job_") || j.State != cloud.JobPlacing && j.State != cloud.JobCreating && j.State != cloud.JobRunning {
		t.Fatalf("created job: %s %s", j.ID, j.State)
	}
	done := s.waitJob(t, a, j.ID)
	if outcome(done) != cloud.OutcomeSucceeded || done.ExitCode == nil || *done.ExitCode != 0 || done.Sandbox == nil || done.Node == nil {
		t.Fatalf("job: %s exit %v", outcome(done), done.ExitCode)
	}
	if got := s.output(t, a, j.ID, cloud.OutputOptions{}); got != "hello world\n" {
		t.Fatalf("output %q", got)
	}
	started := s.waitEvent(t, a, after, eventFor(cloud.EventJobStarted, j.ID))
	exited := s.waitEvent(t, a, after, eventFor(cloud.EventJobExited, j.ID))
	if started.Seq >= exited.Seq {
		t.Fatal("job.started after job.exited")
	}
	var data cloud.EventJobData
	must(t, exited.DecodeData(&data))
	if data.Outcome != cloud.OutcomeSucceeded || data.Labels["kind"] != "test" || exited.Project == nil || *exited.Project != a.project.ID {
		t.Fatalf("job.exited data: %+v", data)
	}
	// The job's sandbox is gone with the job.
	sb, err := a.c.Sandboxes.Get(s.ctx, *done.Sandbox)
	must(t, err)
	if sb.State != "destroyed" || sb.Job == nil || *sb.Job != j.ID {
		t.Fatalf("job sandbox: %s", sb.State)
	}

	// Failure, exit code, stderr.
	f := s.waitJob(t, a, s.job(t, a, a.project.ID, []string{"sh", "-c", "stderr oops; exit 3"}, nil).ID)
	if outcome(f) != cloud.OutcomeFailed || *f.ExitCode != 3 {
		t.Fatalf("failing job: %s %v", outcome(f), f.ExitCode)
	}
	if got := s.output(t, a, f.ID, cloud.OutputOptions{Stream: "stderr"}); got != "oops\n" {
		t.Fatalf("stderr %q", got)
	}
	// stdin and secret environment; secrets never come back.
	in := s.job(t, a, a.project.ID, []string{"sh", "-c", "cat; printenv TOKEN"}, func(in *cloud.JobCreate) {
		in.Exec.Stdin = []byte("from-stdin\n")
		in.Exec.SecretEnv = map[string]string{"TOKEN": "s3cr3t-" + s.tag}
	})
	in = s.waitJob(t, a, in.ID)
	if got := s.output(t, a, in.ID, cloud.OutputOptions{}); got != "from-stdin\ns3cr3t-"+s.tag+"\n" {
		t.Fatalf("stdin/env output %q", got)
	}
	if js := mustJSON(t, in); strings.Contains(js, "s3cr3t-"+s.tag) || !strings.Contains(js, "TOKEN") {
		t.Fatalf("job shows its secret or hides the key: %s", js)
	}
	// Cancel.
	sl := s.job(t, a, a.project.ID, []string{"sleep", "60"}, nil)
	_, err = a.c.Jobs.Cancel(s.ctx, sl.ID)
	must(t, err)
	if c := s.waitJob(t, a, sl.ID); outcome(c) != "killed/cancel" {
		t.Fatalf("cancelled job: %s", outcome(c))
	}
	// Exec timeout.
	to := s.job(t, a, a.project.ID, []string{"sleep", "30"}, func(in *cloud.JobCreate) { in.Exec.TimeoutSeconds = 1 })
	if c := s.waitJob(t, a, to.ID); outcome(c) != "killed/timeout" {
		t.Fatalf("timed out job: %s", outcome(c))
	}
	// Lines framing: a longer line fails the job.
	fr := s.job(t, a, a.project.ID, []string{"emit", "1", "2000"}, func(in *cloud.JobCreate) {
		in.Output = &cloud.JobOutputSpec{Framing: "lines", MaxFrameBytes: 1000}
	})
	if c := s.waitJob(t, a, fr.ID); outcome(c) != "failed/frame_too_large" {
		t.Fatalf("frame limit: %s", outcome(c))
	}
	// Egress binding refused: the job never started (nodes that bind allowlists only).
	if s.env.NoEgressBinding {
		t.Log("egress binding refusal not checked: the nodes do not bind allowlists yet")
	} else {
		rf := s.job(t, a, a.project.ID, []string{"true"}, func(in *cloud.JobCreate) {
			in.Egress = &cloud.EgressPolicy{Mode: cloud.EgressAllowlist, Domains: []string{"x.refuse-binding.test"}}
		})
		if c := s.waitJob(t, a, rf.ID); outcome(c) != "refused/egress_binding" || c.StartedAt != nil {
			t.Fatalf("refused binding: %s started %v", outcome(c), c.StartedAt)
		}
	}
	// Invalid egress policies are refused with errors per field.
	_, err = a.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile,
		Exec: cloud.JobExec{Argv: []string{"true"}}, Egress: &cloud.EgressPolicy{Mode: cloud.EgressAllowlist, Domains: []string{"8.8.8.8", "dns.google"}}})
	e := wantCode(t, err, cloud.CodeInvalidPolicy)
	codes := map[string]bool{}
	for _, fe := range e.Errors {
		codes[fe.Code] = true
	}
	if !codes["ip_literal"] || !codes["doh_resolver"] {
		t.Fatalf("invalid_policy errors: %+v", e.Errors)
	}
	// Unknown template, wrong kinds.
	_, err = a.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: "no-such-template@1", Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	wantCode(t, err, cloud.CodeNotFound)
	_, err = a.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.machineProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	wantCode(t, err, cloud.CodeInvalidRequest)
	// Lease renewal.
	lj := s.job(t, a, a.project.ID, []string{"sleep", "30"}, func(in *cloud.JobCreate) { in.LeaseSeconds = cloud.Int(60) })
	l, err := a.c.Jobs.RenewLease(s.ctx, lj.ID, 120)
	must(t, err)
	if l.LeaseSeconds != 120 || !l.LeaseExpiresAt.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("lease: %+v", l)
	}
	_, err = a.c.Jobs.Cancel(s.ctx, lj.ID)
	must(t, err)
	_, err = a.c.Jobs.RenewLease(s.ctx, s.waitJob(t, a, lj.ID).ID, 0)
	wantCode(t, err, cloud.CodeConflict)
	// Lists filter by state and label.
	ls, err := a.c.Jobs.List(s.ctx, cloud.ListOptions{Labels: cloud.Labels{"kind": "test"}, States: []string{cloud.JobExited}})
	must(t, err)
	if len(ls.Data) != 1 || ls.Data[0].ID != j.ID {
		t.Fatalf("job list by label: %d", len(ls.Data))
	}
}

func (s *suite) testJobOutput(t *testing.T) {
	a := s.a
	// Resume from any offset.
	j := s.waitJob(t, a, s.job(t, a, a.project.ID, []string{"seq", "1000"}, nil).ID)
	full := s.output(t, a, j.ID, cloud.OutputOptions{})
	if !strings.HasPrefix(full, "1\n2\n") || !strings.HasSuffix(full, "1000\n") || int64(len(full)) != j.Output.StdoutBytes {
		t.Fatalf("seq output: %d bytes, job says %d", len(full), j.Output.StdoutBytes)
	}
	if rest := s.output(t, a, j.ID, cloud.OutputOptions{After: 100}); rest != full[100:] {
		t.Fatal("resumed output differs")
	}
	// Follow a running job: output arrives while it runs, and the reader ends at the exit.
	f := s.job(t, a, a.project.ID, []string{"sh", "-c", "echo first; sleep 0.5; echo second"}, nil)
	r, err := a.c.Jobs.Output(s.ctx, f.ID, cloud.OutputOptions{})
	must(t, err)
	buf := make([]byte, 6)
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "first\n" {
		t.Fatalf("first chunk %q %v", buf, err)
	}
	rest, err := io.ReadAll(r)
	must(t, err)
	if string(rest) != "second\n" || r.Offset() != 13 {
		t.Fatalf("followed rest %q offset %d", rest, r.Offset())
	}
	// A snapshot read (no follow) of a running job ends at what is journaled.
	sl := s.job(t, a, a.project.ID, []string{"sh", "-c", "echo now; sleep 30"}, nil)
	time.Sleep(200 * time.Millisecond)
	snap := s.output(t, a, sl.ID, cloud.OutputOptions{NoFollow: true})
	if snap != "now\n" && snap != "" {
		t.Fatalf("snapshot %q", snap)
	}
	_, err = a.c.Jobs.Cancel(s.ctx, sl.ID)
	must(t, err)
	// An offset beyond the end of a finished stream.
	r2, err := a.c.Jobs.Output(s.ctx, j.ID, cloud.OutputOptions{After: int64(len(full)) + 10})
	must(t, err)
	_, err = io.ReadAll(r2)
	wantCode(t, err, cloud.CodeInvalidRequest)
}

func (s *suite) testJobSupervisor(t *testing.T) {
	a := s.a
	files := func(in *cloud.JobCreate) {
		in.Files = []cloud.JobFile{
			{Path: "/run/job/secret.json", Content: []byte("root-only"), Mode: "0400"},
			{Path: "/run/job/shared.json", Content: []byte("shared"), Mode: "0444"},
			{Path: "/run/job/mine.txt", Content: []byte("mine"), Owner: "user", Mode: "0600"},
		}
	}
	// Supervised (the default): runs as the unprivileged uid; root-owned 0400 is unreadable.
	j := s.waitJob(t, a, s.job(t, a, a.project.ID, []string{"sh", "-c", "id -u; cat-file /run/job/shared.json; cat-file /run/job/mine.txt; cat-file /run/job/secret.json"}, files).ID)
	if outcome(j) != cloud.OutcomeFailed {
		t.Fatalf("supervised read of a 0400 root file: %s", outcome(j))
	}
	if got := s.output(t, a, j.ID, cloud.OutputOptions{}); got != "10001\nsharedmine" {
		t.Fatalf("supervised output %q", got)
	}
	if len(j.Files) != 3 || j.Files[0].Owner != "root" || j.Files[0].Mode != "0400" || j.Supervisor == nil || j.Supervisor.Unsupervised {
		t.Fatalf("job files/supervisor: %+v %+v", j.Files, j.Supervisor)
	}
	// supervisor "none" needs jobs:unsupervised.
	jobsOnly := s.keyWith(t, a, "", cloud.ScopeJobs)
	_, err := jobsOnly.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile,
		Exec: cloud.JobExec{Argv: []string{"true"}}, Supervisor: &cloud.Supervisor{Unsupervised: true}})
	e := wantCode(t, err, cloud.CodeScopeMissing)
	if e.Scope != string(cloud.ScopeJobsUnsupervised) {
		t.Fatalf("scope %q", e.Scope)
	}
	u := s.waitJob(t, a, s.job(t, a, a.project.ID, []string{"sh", "-c", "id -u; cat-file /run/job/secret.json"}, func(in *cloud.JobCreate) {
		files(in)
		in.Supervisor = &cloud.Supervisor{Unsupervised: true}
	}).ID)
	if got := s.output(t, a, u.ID, cloud.OutputOptions{}); outcome(u) != cloud.OutcomeSucceeded || got != "0\nroot-only" {
		t.Fatalf("unsupervised: %s %q", outcome(u), got)
	}
}

func (s *suite) testSandboxes(t *testing.T) {
	a := s.a
	sb, err := a.c.Sandboxes.Create(s.ctx, cloud.SandboxCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile,
		TTLSeconds: 600, Labels: cloud.Labels{"t": "sandbox"}})
	must(t, err)
	if !strings.HasPrefix(sb.ID, "sbx_") || sb.TTLSeconds != 600 || sb.Job != nil {
		t.Fatalf("sandbox: %+v", sb)
	}
	sb, err = a.c.Sandboxes.WaitReady(s.ctx, sb.ID)
	must(t, err)
	if sb.State != "ready" {
		t.Fatalf("sandbox state %s", sb.State)
	}
	ex, err := a.c.Sandboxes.Exec(s.ctx, sb.ID, cloud.ExecRequest{Shell: "echo in-sandbox"})
	must(t, err)
	if ex.State != "exited" || string(ex.Stdout) != "in-sandbox\n" || *ex.Outcome != cloud.OutcomeSucceeded || ex.Target.Kind != "sandbox" {
		t.Fatalf("sandbox exec: %+v", ex)
	}
	_, err = a.c.Sandboxes.WriteFile(s.ctx, sb.ID, "/tmp/x.txt", []byte("x"), cloud.FileOptions{})
	must(t, err)
	b, err := a.c.Sandboxes.ReadFile(s.ctx, sb.ID, "/tmp/x.txt", cloud.FileOptions{})
	must(t, err)
	if string(b) != "x" {
		t.Fatalf("sandbox file %q", b)
	}
	// Async exec, list, get, output, cancel.
	ax, err := a.c.Sandboxes.Exec(s.ctx, sb.ID, cloud.ExecRequest{Shell: "echo go; sleep 30", Async: true, TimeoutSeconds: 120})
	must(t, err)
	el, err := a.c.Sandboxes.ListExecs(s.ctx, sb.ID, cloud.ListOptions{States: []string{"running"}})
	must(t, err)
	if len(el.Data) != 1 || el.Data[0].ID != ax.ID {
		t.Fatalf("running execs: %d", len(el.Data))
	}
	or, err := a.c.Sandboxes.ExecOutput(s.ctx, sb.ID, ax.ID, cloud.OutputOptions{})
	must(t, err)
	goLine := make([]byte, 3)
	_, err = io.ReadFull(or, goLine)
	must(t, err)
	_, err = a.c.Sandboxes.CancelExec(s.ctx, sb.ID, ax.ID)
	must(t, err)
	_, _ = io.ReadAll(or)
	gx, err := a.c.Sandboxes.WaitExec(s.ctx, sb.ID, ax.ID)
	must(t, err)
	if string(goLine) != "go\n" || gx.State != "exited" || *gx.OutcomeReason != "cancel" {
		t.Fatalf("sandbox async exec: %q %+v", goLine, gx)
	}
	// Files: list, tree, archive, delete.
	fl, err := a.c.Sandboxes.ListFiles(s.ctx, sb.ID, "/tmp", cloud.FileOptions{})
	must(t, err)
	// A real sandbox's /tmp holds more (system sockets): x.txt must be there.
	found := false
	for _, e := range fl.Entries {
		found = found || (e.Name == "x.txt" && e.Type == "file")
	}
	if !found {
		t.Fatalf("sandbox files: %+v", fl.Entries)
	}
	tr, err := a.c.Sandboxes.PutTree(s.ctx, sb.ID, cloud.FileTree{Root: "/opt/cfg", Files: []cloud.TreeFile{{Path: "a", Content: []byte("1")}}})
	must(t, err)
	if !tr.Changed {
		t.Fatal("sandbox tree")
	}
	arc, err := a.c.Sandboxes.Archive(s.ctx, sb.ID, cloud.ArchiveRequest{Path: "/opt/cfg"})
	must(t, err)
	gz, err := gzip.NewReader(arc)
	must(t, err)
	hdr, err := tar.NewReader(gz).Next()
	must(t, err)
	arc.Close()
	if hdr.Name != "a" {
		t.Fatalf("sandbox archive entry %s", hdr.Name)
	}
	must(t, a.c.Sandboxes.DeleteFile(s.ctx, sb.ID, "/tmp/x.txt", cloud.FileOptions{}))
	// Leases: a sandbox without one cannot renew; one with a lease can.
	_, err = a.c.Sandboxes.RenewLease(s.ctx, sb.ID, 60)
	must(t, err) // setting lease_seconds starts a lease
	ls, err := a.c.Sandboxes.RenewLease(s.ctx, sb.ID, 0)
	must(t, err)
	if ls.LeaseSeconds != 60 {
		t.Fatalf("sandbox lease %+v", ls)
	}
	l, err := a.c.Sandboxes.List(s.ctx, cloud.ListOptions{Labels: cloud.Labels{"t": "sandbox"}})
	must(t, err)
	if len(l.Data) != 1 {
		t.Fatalf("sandbox list %d", len(l.Data))
	}
	after := s.latestSeq(t, a)
	d, err := a.c.Sandboxes.Delete(s.ctx, sb.ID)
	must(t, err)
	if d.State != "destroyed" {
		sb2, err := a.c.Sandboxes.Get(s.ctx, sb.ID)
		must(t, err)
		d = sb2
	}
	s.waitEvent(t, a, after, func(ev cloud.Event) bool {
		var st cloud.EventStateData
		return ev.Type == cloud.EventSandboxState && ev.Resource.ID == sb.ID && ev.DecodeData(&st) == nil && st.State == "destroyed"
	})
	_, err = a.c.Sandboxes.Exec(s.ctx, sb.ID, cloud.ExecRequest{Argv: []string{"true"}})
	wantCode(t, err, cloud.CodeConflict)
}

func (s *suite) testMachines(t *testing.T) {
	a := s.a
	after := s.latestSeq(t, a)
	m := s.machine(t, a, a.project.ID, func(in *cloud.MachineCreate) {
		in.Hostname = "box-" + s.tag
		in.Labels = cloud.Labels{"owner": "u1"}
	})
	if !strings.HasPrefix(m.ID, "mch_") || m.Node == nil || m.Mode != cloud.OnDemand || m.RunningSince == nil || m.EffectiveProfile != s.machineProfile {
		t.Fatalf("machine: %+v", m)
	}
	s.waitEvent(t, a, after, func(ev cloud.Event) bool {
		var st cloud.EventStateData
		return ev.Type == cloud.EventMachineState && ev.Resource.ID == m.ID && ev.DecodeData(&st) == nil && st.State == cloud.MachineReady
	})
	ex, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"hostname"}, Actor: "user-1"})
	must(t, err)
	if string(ex.Stdout) != "box-"+s.tag+"\n" || ex.User != "agent" || ex.Actor != "user-1" {
		t.Fatalf("exec: %q %s", ex.Stdout, ex.User)
	}
	// Root needs machines:root.
	noRoot := s.keyWith(t, a, "", cloud.ScopeMachines, cloud.ScopeMachinesExec)
	_, err = noRoot.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"whoami"}, User: "root"})
	if e := wantCode(t, err, cloud.CodeScopeMissing); e.Scope != string(cloud.ScopeMachinesRoot) {
		t.Fatalf("scope %q", e.Scope)
	}
	rx, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"whoami"}, User: "root"})
	must(t, err)
	if string(rx.Stdout) != "root\n" {
		t.Fatalf("root exec %q", rx.Stdout)
	}
	// Sync timeout cap; async exec, get, cancel.
	_, err = a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"true"}, TimeoutSeconds: 301})
	wantCode(t, err, cloud.CodeInvalidRequest)
	ax, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Shell: "echo started; sleep 30", Async: true, TimeoutSeconds: 600})
	must(t, err)
	if ax.State != "running" {
		t.Fatalf("async exec %s", ax.State)
	}
	r, err := a.c.Machines.ExecOutput(s.ctx, m.ID, ax.ID, cloud.OutputOptions{})
	must(t, err)
	first := make([]byte, 8)
	_, err = io.ReadFull(r, first)
	must(t, err)
	if string(first) != "started\n" {
		t.Fatalf("async output %q", first)
	}
	running, err := a.c.Machines.ListExecs(s.ctx, m.ID, cloud.ListOptions{})
	must(t, err)
	if len(running.Data) == 0 || running.Data[0].ID != ax.ID || running.Data[0].State != "running" {
		t.Fatalf("exec list: %+v", running.Data)
	}
	_, err = a.c.Machines.CancelExec(s.ctx, m.ID, ax.ID)
	must(t, err)
	_, _ = io.ReadAll(r)
	done, err := a.c.Machines.WaitExec(s.ctx, m.ID, ax.ID)
	must(t, err)
	if done.State != "exited" || *done.Outcome != cloud.OutcomeKilled || *done.OutcomeReason != "cancel" {
		t.Fatalf("cancelled exec %+v", done)
	}
	// Output cap.
	cx, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"emit", "10", "100"}, OutputCapBytes: 50})
	must(t, err)
	if len(cx.Stdout) != 50 || !cx.Truncated {
		t.Fatalf("output cap: %d truncated=%v", len(cx.Stdout), cx.Truncated)
	}
	// Stop, exec refused, start, a /workspace file survives restart.
	_, err = a.c.Machines.WriteFile(s.ctx, m.ID, "/workspace/sentinel", []byte("keep"), cloud.FileOptions{})
	must(t, err)
	_, err = a.c.Machines.Stop(s.ctx, m.ID)
	must(t, err)
	st := s.waitMachine(t, a, m.ID, cloud.MachineStopped)
	if st.RunningSince != nil {
		t.Fatal("a stopped machine has running_since")
	}
	_, err = a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"true"}})
	wantCode(t, err, cloud.CodeConflict)
	_, err = a.c.Machines.Start(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	_, err = a.c.Machines.Restart(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	b, err := a.c.Machines.ReadFile(s.ctx, m.ID, "/workspace/sentinel", cloud.FileOptions{})
	must(t, err)
	if string(b) != "keep" {
		t.Fatal("/workspace was not carried over the restart")
	}
	// PATCH with preconditions; a profile change takes effect at the next restart.
	cur, err := a.c.Machines.Get(s.ctx, m.ID)
	must(t, err)
	up, err := a.c.Machines.Update(s.ctx, m.ID, cloud.MachineUpdate{Hold: cloud.Bool(true), Labels: cloud.Labels{"owner": "u2"}}, cloud.IfMatch(cur.Version))
	must(t, err)
	if !up.Hold || up.Labels["owner"] != "u2" || up.Version <= cur.Version {
		t.Fatalf("update: %+v", up)
	}
	_, err = a.c.Machines.Update(s.ctx, m.ID, cloud.MachineUpdate{Hold: cloud.Bool(false)}, cloud.IfMatch(cur.Version))
	wantCode(t, err, cloud.CodePreconditionFailed)
	// Metrics, migrate to the other node of the pool.
	met, err := a.c.Machines.Metrics(s.ctx, m.ID)
	must(t, err)
	if met.Machine != m.ID || met.MemoryTotalMiB <= 0 {
		t.Fatalf("metrics: %+v", met)
	}
	before := *s.waitMachine(t, a, m.ID, cloud.MachineReady).Node
	_, err = a.c.Machines.Migrate(s.ctx, m.ID, "")
	must(t, err)
	mm := s.waitMachine(t, a, m.ID, cloud.MachineReady)
	if *mm.Node == before {
		t.Fatal("migrate kept the node")
	}
	if b, err := a.c.Machines.ReadFile(s.ctx, m.ID, "/workspace/sentinel", cloud.FileOptions{}); err != nil || string(b) != "keep" {
		t.Fatal("/workspace was not carried over the migration")
	}
	// Always-on mode needs a profile that allows it; quota always_on_machines applies.
	_, err = a.c.Machines.Update(s.ctx, m.ID, cloud.MachineUpdate{Mode: modePtr("sometimes")})
	wantCode(t, err, cloud.CodeInvalidRequest)
	// Delete.
	after = s.latestSeq(t, a)
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineDestroyed)
	s.waitEvent(t, a, after, func(ev cloud.Event) bool {
		var sd cloud.EventStateData
		return ev.Type == cloud.EventMachineState && ev.Resource.ID == m.ID && ev.DecodeData(&sd) == nil && sd.State == cloud.MachineDestroyed
	})
	_, err = a.c.Machines.Start(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeConflict)
}

func modePtr(m cloud.MachineMode) *cloud.MachineMode { return &m }

func (s *suite) testExecConcurrency(t *testing.T) {
	a := s.a
	m := s.machine(t, a, a.project.ID, nil)
	p, err := a.c.Profiles.Get(s.ctx, m.EffectiveProfile)
	must(t, err)
	limit := p.MaxConcurrentExecs
	if limit == 0 {
		limit = 8
	}
	var ids []string
	for i := 0; i < limit; i++ {
		ex, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"sleep", "60"}, Async: true, TimeoutSeconds: 120})
		must(t, err)
		ids = append(ids, ex.ID)
	}
	noRetry := a.c.WithToken(a.key)
	_, err = noRetryClient(noRetry).Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"true"}})
	e := wantCode(t, err, cloud.CodeBusy)
	if !e.Retryable {
		t.Fatal("busy must be retryable")
	}
	// Concurrent commands on another machine are unaffected (no lock across machines).
	other := s.machine(t, a, a.project.ID, nil)
	if _, err := a.c.Machines.Exec(s.ctx, other.ID, cloud.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("another machine: %v", err)
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _ = a.c.Machines.CancelExec(s.ctx, m.ID, id)
		}(id)
	}
	wg.Wait()
	if _, err := a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("after cancelling: %v", err)
	}
	for _, id := range []string{m.ID, other.ID} {
		_, err := a.c.Machines.Delete(s.ctx, id)
		must(t, err)
	}
}

func noRetryClient(c *cloud.Client) *cloud.Client {
	return c.WithRetry(cloud.RetryPolicy{MaxAttempts: 1})
}

func (s *suite) testFiles(t *testing.T) {
	a := s.a
	m := s.machine(t, a, a.project.ID, nil)
	defer a.c.Machines.Delete(s.ctx, m.ID)
	fe, err := a.c.Machines.WriteFile(s.ctx, m.ID, "/workspace/dir/a.txt", []byte("alpha"), cloud.FileOptions{Mode: "0640"})
	must(t, err)
	if fe.Size != 5 || fe.Mode != "0640" || fe.Owner != "agent" {
		t.Fatalf("write: %+v", fe)
	}
	got, err := a.c.Machines.ReadFile(s.ctx, m.ID, "/workspace/dir/a.txt", cloud.FileOptions{})
	must(t, err)
	if string(got) != "alpha" {
		t.Fatalf("read %q", got)
	}
	l, err := a.c.Machines.ListFiles(s.ctx, m.ID, "/workspace", cloud.FileOptions{})
	must(t, err)
	if len(l.Entries) != 1 || l.Entries[0].Name != "dir" || l.Entries[0].Type != "dir" {
		t.Fatalf("list: %+v", l.Entries)
	}
	_, err = a.c.Machines.ReadFile(s.ctx, m.ID, "/workspace/missing", cloud.FileOptions{})
	wantCode(t, err, cloud.CodeNotFound)
	_, err = a.c.Machines.WriteFile(s.ctx, m.ID, "/etc/passwd", []byte("x"), cloud.FileOptions{})
	wantCode(t, err, cloud.CodeForbidden)
	// Archive.
	rc, err := a.c.Machines.Archive(s.ctx, m.ID, cloud.ArchiveRequest{Path: "/workspace"})
	must(t, err)
	gz, err := gzip.NewReader(rc)
	must(t, err)
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	for err == nil && hdr.Typeflag == tar.TypeDir { // real archives carry directory entries
		hdr, err = tr.Next()
	}
	must(t, err)
	body, _ := io.ReadAll(tr)
	rc.Close()
	if hdr.Name != "dir/a.txt" || string(body) != "alpha" {
		t.Fatalf("archive entry %s %q", hdr.Name, body)
	}
	// Read-only tree sync: atomic, root-owned, idempotent.
	tree := cloud.FileTree{Root: "/opt/bundle", Files: []cloud.TreeFile{{Path: "bin/tool", Content: []byte("#!/bin/sh\n"), Mode: "0755"}, {Path: "README", Content: []byte("v1")}}}
	res, err := a.c.Machines.PutTree(s.ctx, m.ID, tree)
	must(t, err)
	if !res.Changed || res.Files != 2 || res.Digest == "" {
		t.Fatalf("tree: %+v", res)
	}
	res2, err := a.c.Machines.PutTree(s.ctx, m.ID, tree)
	must(t, err)
	if res2.Changed || res2.Digest != res.Digest {
		t.Fatal("re-sending the same tree changed it")
	}
	tl, err := a.c.Machines.ListFiles(s.ctx, m.ID, "/opt/bundle/bin", cloud.FileOptions{})
	must(t, err)
	if len(tl.Entries) != 1 || tl.Entries[0].Owner != "root" || tl.Entries[0].Mode != "0555" {
		t.Fatalf("tree entry: %+v", tl.Entries)
	}
	_, err = a.c.Machines.WriteFile(s.ctx, m.ID, "/opt/bundle/README", []byte("tamper"), cloud.FileOptions{User: "root"})
	wantCode(t, err, cloud.CodeForbidden)
	_, err = a.c.Machines.PutTree(s.ctx, m.ID, cloud.FileTree{Root: "/workspace/x", Files: nil})
	wantCode(t, err, cloud.CodeInvalidRequest)
	_, err = a.c.Machines.PutTree(s.ctx, m.ID, cloud.FileTree{Root: "/opt/bundle", Files: []cloud.TreeFile{{Path: "../escape", Content: []byte("x")}}})
	wantCode(t, err, cloud.CodeInvalidRequest)
	// Replacing the tree removes files not in the new one.
	_, err = a.c.Machines.PutTree(s.ctx, m.ID, cloud.FileTree{Root: "/opt/bundle", Files: []cloud.TreeFile{{Path: "README", Content: []byte("v2")}}})
	must(t, err)
	_, err = a.c.Machines.ReadFile(s.ctx, m.ID, "/opt/bundle/bin/tool", cloud.FileOptions{})
	wantCode(t, err, cloud.CodeNotFound)
	// Delete.
	err = a.c.Machines.DeleteFile(s.ctx, m.ID, "/workspace/dir", cloud.FileOptions{})
	wantCode(t, err, cloud.CodeConflict)
	must(t, a.c.Machines.DeleteFile(s.ctx, m.ID, "/workspace/dir", cloud.FileOptions{Recursive: true}))
	_, err = a.c.Machines.ReadFile(s.ctx, m.ID, "/workspace/dir/a.txt", cloud.FileOptions{})
	wantCode(t, err, cloud.CodeNotFound)
	// Files are reachable from execs and the other way round.
	_, err = a.c.Machines.Exec(s.ctx, m.ID, cloud.ExecRequest{Shell: "write /workspace/from-exec hi there"})
	must(t, err)
	b, err := a.c.Machines.ReadFile(s.ctx, m.ID, "/workspace/from-exec", cloud.FileOptions{})
	must(t, err)
	if !bytes.Equal(b, []byte("hi there")) {
		t.Fatalf("exec-written file %q", b)
	}
}

func (s *suite) testTerminals(t *testing.T) {
	a := s.a
	m := s.machine(t, a, a.project.ID, nil)
	defer a.c.Machines.Delete(s.ctx, m.ID)
	after := s.latestSeq(t, a)
	term, err := a.c.Machines.CreateTerminal(s.ctx, m.ID, cloud.TerminalCreate{Rows: 30, Cols: 100, Actor: "user-7"})
	must(t, err)
	if !strings.HasPrefix(term.ID, "trm_") || term.State != "open" || term.Rows != 30 || term.Actor != "user-7" {
		t.Fatalf("terminal: %+v", term)
	}
	stream, err := a.c.Machines.StreamTerminal(s.ctx, m.ID, term.ID, 0)
	must(t, err)
	defer stream.Close()
	ev, err := stream.Next()
	must(t, err)
	if ev.Type != "output" || len(ev.Data) == 0 {
		t.Fatalf("first terminal event: %+v", ev)
	}
	must(t, a.c.Machines.SendTerminalInput(s.ctx, m.ID, term.ID, []byte("echo hi\r")))
	var seen strings.Builder
	for !strings.Contains(seen.String(), "echo hi") {
		ev, err := stream.Next()
		must(t, err)
		seen.Write(ev.Data)
	}
	rt, err := a.c.Machines.ResizeTerminal(s.ctx, m.ID, term.ID, 40, 120)
	must(t, err)
	if rt.Rows != 40 || rt.Cols != 120 {
		t.Fatalf("resize: %+v", rt)
	}
	ls, err := a.c.Machines.ListTerminals(s.ctx, m.ID, cloud.ListOptions{})
	must(t, err)
	if len(ls.Data) != 1 {
		t.Fatalf("terminals: %d", len(ls.Data))
	}
	// "exit" ends the session; the stream reports the close.
	must(t, a.c.Machines.SendTerminalInput(s.ctx, m.ID, term.ID, []byte("exit\r")))
	for {
		ev, err := stream.Next()
		must(t, err)
		if ev.Type == "closed" {
			if ev.Reason != "exit" {
				t.Fatalf("close reason %s", ev.Reason)
			}
			break
		}
	}
	closed := s.waitEvent(t, a, after, eventFor(cloud.EventTerminalClosed, term.ID))
	var cd cloud.EventTerminalClosedData
	must(t, closed.DecodeData(&cd))
	if cd.Reason != "exit" || cd.Actor != "user-7" || cd.Machine != m.ID {
		t.Fatalf("terminal.closed: %+v", cd)
	}
	err = a.c.Machines.SendTerminalInput(s.ctx, m.ID, term.ID, []byte("x"))
	wantCode(t, err, cloud.CodeGone)
	// Session limit per machine.
	p, err := a.c.Profiles.Get(s.ctx, m.EffectiveProfile)
	must(t, err)
	for i := 0; i < p.MaxTerminals; i++ {
		_, err := a.c.Machines.CreateTerminal(s.ctx, m.ID, cloud.TerminalCreate{})
		must(t, err)
	}
	_, err = noRetryClient(a.c).Machines.CreateTerminal(s.ctx, m.ID, cloud.TerminalCreate{})
	wantCode(t, err, cloud.CodeBusy)
	// Stopping the machine closes its terminals.
	after = s.latestSeq(t, a)
	_, err = a.c.Machines.Stop(s.ctx, m.ID)
	must(t, err)
	ev2 := s.waitEvent(t, a, after, func(ev cloud.Event) bool { return ev.Type == cloud.EventTerminalClosed })
	must(t, ev2.DecodeData(&cd))
	if cd.Reason != "machine_stopped" {
		t.Fatalf("close reason on stop: %s", cd.Reason)
	}
}

// testMachineDisk: what a restart keeps. An always-on machine keeps its whole disk
// across a restart; an on-demand one starts from its template with /workspace carried over; a
// reset needs confirm_disk_reset and keeps /workspace only.
func (s *suite) testMachineDisk(t *testing.T) {
	a := s.a
	prof, err := a.c.Profiles.Get(s.ctx, s.machineProfile)
	must(t, err)
	root := cloud.FileOptions{User: "root"}
	check := func(id, path, want string) {
		t.Helper()
		b, err := a.c.Machines.ReadFile(s.ctx, id, path, root)
		if want == "" {
			if err == nil {
				t.Fatalf("%s survived: %q", path, b)
			}
			return
		}
		if err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", path, b, err)
		}
	}
	write := func(id, path, v string) {
		t.Helper()
		_, err := a.c.Machines.WriteFile(s.ctx, id, path, []byte(v), root)
		must(t, err)
	}
	// On demand: a fresh machine from the template.
	m := s.machine(t, a, a.project.ID, func(in *cloud.MachineCreate) { in.Mode = cloud.OnDemand })
	if m.Restart != cloud.RestartFreshTemplate {
		t.Fatalf("on-demand restart policy %q", m.Restart)
	}
	write(m.ID, "/workspace/kept", "ws")
	write(m.ID, "/etc/cloud-contract", "etc")
	_, err = a.c.Machines.Restart(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	check(m.ID, "/workspace/kept", "ws")
	check(m.ID, "/etc/cloud-contract", "")
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
	if !modeAllowed(prof, cloud.AlwaysOn) {
		t.Logf("profile %s has no always_on mode: the whole-disk restart is not checked", prof.Name)
		return
	}
	// Always on: the whole disk; a reset needs the confirmation and keeps /workspace only.
	m = s.machine(t, a, a.project.ID, func(in *cloud.MachineCreate) { in.Mode = cloud.AlwaysOn })
	if m.Restart != cloud.RestartKeepDisk {
		t.Fatalf("always-on restart policy %q", m.Restart)
	}
	write(m.ID, "/workspace/kept", "ws")
	write(m.ID, "/etc/cloud-contract", "etc")
	_, err = a.c.Machines.Restart(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	check(m.ID, "/workspace/kept", "ws")
	check(m.ID, "/etc/cloud-contract", "etc")
	_, err = a.c.Machines.Reset(s.ctx, m.ID, cloud.MachineReset{})
	wantCode(t, err, cloud.CodeInvalidRequest)
	_, err = a.c.Machines.Reset(s.ctx, m.ID, cloud.MachineReset{ConfirmDiskReset: true})
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	check(m.ID, "/workspace/kept", "ws")
	check(m.ID, "/etc/cloud-contract", "")
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
}

func modeAllowed(p *cloud.Profile, m cloud.MachineMode) bool {
	for _, x := range p.Modes {
		if x == m {
			return true
		}
	}
	return false
}
