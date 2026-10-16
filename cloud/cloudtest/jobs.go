package cloudtest

import (
	"bytes"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

type timeT = time.Time

const timeHour = time.Hour

var modeRE = regexp.MustCompile(`^0?[0-7]{3}$`)

// later runs f under the server lock shortly after the current request (an asynchronous
// transition, like a node acknowledging).
func (st *state) later(d time.Duration, f func()) {
	s := st.s
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-s.closed:
			return
		case <-t.C:
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		select {
		case <-s.closed:
			return
		default:
		}
		f()
	}()
}

func (st *state) profileFor(cs *consumer, name string) cloud.Profile {
	p, ok := st.profiles[name]
	if !ok || (len(cs.allowedProfiles) > 0 && !contains(cs.allowedProfiles, name)) {
		notFound("profile " + name)
	}
	return p
}

func (st *state) profileForCreate(cs *consumer, name string, kind cloud.TemplateKind) cloud.Profile {
	p, ok := st.profiles[name]
	if !ok {
		invalid("profile", "unknown", "unknown profile %q", name)
	}
	if len(cs.allowedProfiles) > 0 && !contains(cs.allowedProfiles, name) {
		invalid("profile", "not_allowed", "profile %q is not allowed for this consumer", name)
	}
	if p.Kind != kind {
		invalid("profile", "wrong_kind", "profile %q is for %s, not %s", name, p.Kind, kind)
	}
	return p
}

// resolveTemplate finds a template the consumer may use: a built-in it is allowed, or its own.
func (st *state) resolveTemplate(cs *consumer, ref string, readyOnly bool) *template {
	name, version, err := cloud.ParseTemplateRef(ref)
	if err != nil {
		notFound("template " + ref)
	}
	var cands []*template
	for _, t := range st.builtins {
		if t.Name == name && (len(cs.allowedTemplates) == 0 || contains(cs.allowedTemplates, name)) {
			cands = append(cands, t)
		}
	}
	for _, t := range st.consumerT[cs.id] {
		if t.Name == name {
			cands = append(cands, t)
		}
	}
	var best *template
	for _, t := range cands {
		if version != 0 && t.Version != version {
			continue
		}
		if version == 0 && readyOnly && t.State == "failed" {
			continue
		}
		if best == nil || t.Version > best.Version {
			best = t
		}
	}
	if best == nil {
		if version == 0 && readyOnly && len(cands) > 0 {
			fail(409, cloud.CodeTemplateNotReady, "no version of template %s is built", name)
		}
		notFound("template " + ref)
	}
	return best
}

func (st *state) templateForCreate(cs *consumer, ref string, kind cloud.TemplateKind) *template {
	t := st.resolveTemplate(cs, ref, true)
	if t.Kind != kind {
		invalid("template", "wrong_kind", "template %s is a %s template", t.ID, t.Kind)
	}
	return t
}

// checkProfileAllows refuses a profile whose templates list does not allow the template (by
// name): 400 invalid_request with a field error on profile.
func checkProfileAllows(prof cloud.Profile, template string) {
	name, _, err := cloud.ParseTemplateRef(strings.TrimPrefix(template, "tpl_"))
	if err != nil {
		name = template
	}
	if !prof.AllowsTemplate(name) {
		invalid("profile", "not_allowed", "profile %q does not allow template %s", prof.Name, name)
	}
}

// profilesFor are the profiles a template is built for: those of its kind that allow it.
func (st *state) profilesFor(kind cloud.TemplateKind, name string) []cloud.Profile {
	var out []cloud.Profile
	for _, n := range sortedKeys(st.profiles) {
		if p := st.profiles[n]; p.Kind == kind && p.AllowsTemplate(name) {
			out = append(out, p)
		}
	}
	return out
}

func validTTL(field string, ttl, max int) int {
	if ttl == 0 {
		return max
	}
	if ttl < 10 || (max > 0 && ttl > max) {
		invalid(field, "out_of_range", "%s must be between 10 and %d", field, max)
	}
	return ttl
}

func validLease(l *int) {
	if l != nil && (*l < 10 || *l > 3600) {
		invalid("lease_seconds", "out_of_range", "lease_seconds must be between 10 and 3600")
	}
}

// ---- jobs ----

func createJob(c *ctx) {
	var in cloud.JobCreate
	c.decode(&in)
	p := c.project(in.Project)
	prof := c.st.profileForCreate(c.csm, in.Profile, cloud.KindJob)
	ttl := validTTL("ttl_seconds", in.TTLSeconds, prof.TimeoutSeconds)
	validLease(in.LeaseSeconds)
	validateLabels("labels", in.Labels)
	if len(in.Exec.Argv) == 0 {
		invalid("exec.argv", "required", "exec.argv is required")
	}
	if len(in.Exec.Stdin) > 2<<20 {
		invalid("exec.stdin_b64", "too_long", "stdin is at most 2 MiB")
	}
	if in.Exec.TimeoutSeconds < 0 {
		invalid("exec.timeout_seconds", "invalid", "timeout_seconds must be positive")
	}
	total := 0
	for i, f := range in.Files {
		fld := "files[" + strconv.Itoa(i) + "]"
		if !strings.HasPrefix(f.Path, "/") {
			invalid(fld+".path", "invalid", "file paths are absolute")
		}
		if f.Owner != "" && f.Owner != "root" && f.Owner != "user" {
			invalid(fld+".owner", "invalid", "owner is root or user")
		}
		if f.Mode != "" && !modeRE.MatchString(f.Mode) {
			invalid(fld+".mode", "invalid", "mode is octal, e.g. 0400")
		}
		total += len(f.Content)
	}
	if total > 8<<20 {
		invalid("files", "too_long", "files are at most 8 MiB in all")
	}
	framing, maxFrame := "raw", 1<<20
	if in.Output != nil {
		switch in.Output.Framing {
		case "", "raw":
		case "lines":
			framing = "lines"
		default:
			invalid("output.framing", "invalid", "framing is lines or raw")
		}
		if in.Output.MaxFrameBytes != 0 {
			if in.Output.MaxFrameBytes < 1 || in.Output.MaxFrameBytes > stdoutLimit {
				invalid("output.max_frame_bytes", "out_of_range", "max_frame_bytes is 1 to 16 MiB")
			}
			maxFrame = in.Output.MaxFrameBytes
		}
	}
	if in.Supervisor != nil && in.Supervisor.Unsupervised && !c.key.hasScope(string(cloud.ScopeJobsUnsupervised)) {
		e := perr(403, cloud.CodeScopeMissing, "supervisor none needs the jobs:unsupervised scope")
		e.Scope = string(cloud.ScopeJobsUnsupervised)
		panic(e)
	}
	if in.Supervisor != nil && in.Supervisor.Seccomp != "" && in.Supervisor.Seccomp != "default" && in.Supervisor.Seccomp != "strict" {
		invalid("supervisor.seccomp", "invalid", "seccomp is default or strict")
	}
	egress := c.st.validateEgress(p, prof, in.Egress, "egress")
	tpl := c.st.templateForCreate(c.csm, in.Template, cloud.KindJob)
	checkProfileAllows(prof, tpl.Name)
	c.st.reserve(p, map[string]int{"concurrent_jobs": 1, "running_vcpu": prof.VCPU, "running_memory_mib": prof.MemoryMiB})
	nodeID := c.st.place(p.Pool, prof, true, tpl, "")

	now := c.s.now()
	j := &job{consumer: c.csm.id, secretEnv: in.Exec.SecretEnv, stdin: in.Exec.Stdin, files: in.Files, out: newJournal(), cancel: make(chan struct{})}
	j.Job = cloud.Job{ID: newID("job"), Project: p.ID, Template: tpl.ID, Profile: prof.Name, State: cloud.JobPlacing,
		TTLSeconds: ttl, ExpiresAt: now.Add(time.Duration(ttl) * time.Second), Egress: egress, Gateway: in.Gateway,
		Labels: nonNilLabels(in.Labels), CreatedAt: now, Version: 1}
	if in.LeaseSeconds != nil {
		l := *in.LeaseSeconds
		j.LeaseSeconds = &l
		j.LeaseExpiresAt = ptrTime(now.Add(time.Duration(l) * time.Second))
	}
	for _, f := range in.Files {
		owner, mode := f.Owner, f.Mode
		if owner == "" {
			owner = "root"
		}
		if mode == "" {
			mode = "0400"
		}
		j.Files = append(j.Files, cloud.JobFileInfo{Path: f.Path, Owner: owner, Mode: mode, Size: int64(len(f.Content))})
	}
	j.Exec.Argv, j.Exec.Cwd, j.Exec.Env, j.Exec.StdinBytes = in.Exec.Argv, in.Exec.Cwd, in.Exec.Env, len(in.Exec.Stdin)
	j.Exec.TimeoutSeconds = in.Exec.TimeoutSeconds
	if j.Exec.TimeoutSeconds == 0 {
		j.Exec.TimeoutSeconds = ttl
	}
	for k := range in.Exec.SecretEnv {
		j.Exec.SecretEnvKeys = append(j.Exec.SecretEnvKeys, k)
	}
	sort.Strings(j.Exec.SecretEnvKeys)
	j.Output.Framing, j.Output.MaxFrameBytes = framing, maxFrame
	sup := cloud.Supervisor{UID: 10001, Seccomp: "default"}
	if in.Supervisor != nil {
		sup = *in.Supervisor
		if !sup.Unsupervised {
			if sup.UID == 0 {
				sup.UID = 10001
			}
			if sup.Seccomp == "" {
				sup.Seccomp = "default"
			}
		}
	}
	j.Supervisor = &sup
	sb := &sandbox{job: j, instance: newInstance(c.csm.id)}
	sb.Sandbox = cloud.Sandbox{ID: newID("sbx"), Project: p.ID, Template: tpl.ID, Profile: prof.Name, State: "creating",
		TTLSeconds: ttl, ExpiresAt: j.ExpiresAt, Egress: egress, Gateway: in.Gateway, Labels: j.Labels, CreatedAt: now, Version: 1, Job: &j.ID}
	j.sandbox = sb
	j.Sandbox = &sb.ID
	j.Node = &nodeID
	sb.Node = &nodeID
	c.st.jobs[j.ID] = j
	c.st.sandboxes[sb.ID] = sb
	out := j.Job
	c.json(202, &out)
	c.st.later(2*time.Millisecond, func() { c.st.startJob(j) })
}

func (st *state) bump(j *job) { j.Version++ }

func (st *state) startJob(j *job) {
	if j.State == cloud.JobExited {
		return
	}
	j.State = cloud.JobCreating
	st.bump(j)
	for _, f := range j.files {
		owner, mode := f.Owner, f.Mode
		if owner == "" {
			owner = "root"
		}
		if mode == "" {
			mode = "0400"
		}
		j.sandbox.fs[f.Path] = &fsEntry{data: f.Content, mode: mode, owner: map[string]string{"root": "root", "user": "agent"}[owner], mtime: st.s.now()}
	}
	if j.Egress.Mode == cloud.EgressAllowlist {
		j.State = cloud.JobBinding
		for _, d := range j.Egress.Domains {
			if strings.HasSuffix(d, ".refuse-binding.test") {
				st.finishJob(j, cloud.OutcomeRefused, "egress_binding", nil)
				return
			}
		}
	}
	j.State = cloud.JobStarting
	j.sandbox.State = "ready"
	j.sandbox.Version++
	now := st.s.now()
	j.State, j.StartedAt = cloud.JobRunning, &now
	st.bump(j)
	pr := st.profiles[j.Profile]
	st.segStart(j.consumer, j.Project, *j.Node, "job", j.ID, "running", pr.VCPU, pr.MemoryMiB, pr.DiskMiB, j.Labels)
	st.emit(j.consumer, j.Project, cloud.EventJobStarted, "job", j.ID, cloud.EventJobData{Job: j.ID, Sandbox: j.sandbox.ID, Node: *j.Node, State: j.State, Labels: j.Labels})
	user := "uid:" + strconv.Itoa(j.Supervisor.UID)
	if j.Supervisor.Unsupervised {
		user = "root"
	}
	env := map[string]string{}
	for k, v := range j.Exec.Env {
		env[k] = v
	}
	for k, v := range j.secretEnv {
		env[k] = v
	}
	pe := &procEnv{stdin: j.stdin, env: env, user: user, readFile: j.sandbox.readFor, write: j.sandbox.writeFor, hostname: "sandbox"}
	cmds := parseProgram(j.Exec.Argv, "")
	deadline := time.Now().Add(time.Duration(j.Exec.TimeoutSeconds) * time.Second)
	st.runProgram(cmds, pe, j.cancel, deadline, func(st1 step) (stop bool) {
		return st.jobOutput(j, st1)
	}, func(exit int, reason string) {
		switch {
		case j.State == cloud.JobExited:
		case reason != "":
			st.finishJob(j, cloud.OutcomeKilled, reason, nil)
		case exit == 0:
			st.finishJob(j, cloud.OutcomeSucceeded, "", &exit)
		default:
			st.finishJob(j, cloud.OutcomeFailed, "", &exit)
		}
	})
}

// runProgram runs mock commands in a goroutine. onStep is called under the lock for each
// command's output (returning true stops the program); onExit under the lock at the end with
// the last exit code, or a kill reason ("cancel" via the channel's owner, or "timeout").
func (st *state) runProgram(cmds []mockCmd, pe *procEnv, cancel chan struct{}, deadline time.Time, onStep func(step) bool, onExit func(exit int, reason string)) {
	s := st.s
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		exit := 0
		for _, cmd := range cmds {
			s.mu.Lock()
			r := runMock(cmd, pe)
			stop := onStep(r)
			s.mu.Unlock()
			if stop {
				return
			}
			exit = r.exit
			if r.sleep > 0 {
				wait := r.sleep
				timedOut := false
				if until := time.Until(deadline); until < wait {
					wait, timedOut = until, true
				}
				t := time.NewTimer(wait)
				select {
				case <-s.closed:
					t.Stop()
					return
				case <-cancel:
					t.Stop()
					return // the canceller finalizes
				case <-t.C:
				}
				if timedOut {
					s.mu.Lock()
					onExit(-1, "timeout")
					s.mu.Unlock()
					return
				}
			}
			select {
			case <-cancel:
				return
			default:
			}
		}
		s.mu.Lock()
		onExit(exit, "")
		s.mu.Unlock()
	}()
}

// jobOutput journals a step's output; it stops the job on the output or frame limits.
func (st *state) jobOutput(j *job, r step) bool {
	if j.State == cloud.JobExited {
		return true
	}
	o := j.out
	if len(r.stderr) > 0 && !o.stderrDropped {
		room := stderrLimit - len(o.stderr)
		if len(r.stderr) > room {
			r.stderr, o.stderrDropped = r.stderr[:room], true
		}
		o.stderr = append(o.stderr, r.stderr...)
		j.Output.StderrBytes = int64(len(o.stderr))
	}
	if len(r.stdout) > 0 {
		if len(o.stdout)+len(r.stdout) > stdoutLimit {
			o.stdout = append(o.stdout, r.stdout[:stdoutLimit-len(o.stdout)]...)
			j.Output.StdoutBytes = int64(len(o.stdout))
			st.finishJob(j, cloud.OutcomeKilled, "output_limit", nil)
			return true
		}
		if j.Output.Framing == "lines" {
			last := bytes.LastIndexByte(o.stdout, '\n')
			pending := append(append([]byte{}, o.stdout[last+1:]...), r.stdout...)
			for _, line := range bytes.Split(pending, []byte("\n")) {
				if len(line) > j.Output.MaxFrameBytes {
					st.finishJob(j, cloud.OutcomeFailed, "frame_too_large", nil)
					return true
				}
			}
		}
		o.stdout = append(o.stdout, r.stdout...)
		j.Output.StdoutBytes = int64(len(o.stdout))
	}
	if len(r.stdout)+len(r.stderr) > 0 {
		o.wake()
	}
	return false
}

func (st *state) finishJob(j *job, outcome, reason string, exit *int) {
	if j.State == cloud.JobExited {
		return
	}
	now := st.s.now()
	j.State, j.Outcome, j.ExitedAt = cloud.JobExited, &outcome, &now
	if reason != "" {
		j.OutcomeReason = &reason
	}
	j.ExitCode = exit
	j.Output.RetainedUntil = ptrTime(now.Add(outputRetention))
	j.out.retainedUntil = j.Output.RetainedUntil
	j.out.done = true
	j.out.wake()
	st.bump(j)
	select {
	case <-j.cancel:
	default:
		close(j.cancel)
	}
	st.segEnd(j.ID, "")
	sb := j.sandbox
	if sb.State != "destroyed" {
		sb.State, sb.DestroyedAt = "destroyed", &now
		sb.StateReason = ptrStr("job_exited")
		sb.Version++
	}
	data := cloud.EventJobData{Job: j.ID, Sandbox: sb.ID, State: j.State, Outcome: outcome, OutcomeReason: reason, ExitCode: exit, Labels: j.Labels}
	if j.Node != nil {
		data.Node = *j.Node
	}
	st.emit(j.consumer, j.Project, cloud.EventJobExited, "job", j.ID, data)
}

func (st *state) killJob(j *job, reason string) { st.finishJob(j, cloud.OutcomeKilled, reason, nil) }

func (c *ctx) job(id string) *job {
	j := c.st.jobs[id]
	if j == nil || j.consumer != c.csm.id || (c.key.project != "" && c.key.project != j.Project) {
		notFound("job")
	}
	return j
}

func listJobs(c *ctx) {
	f := c.listFilter()
	var items []cloud.Job
	for _, j := range c.st.jobs {
		node := ""
		if j.Node != nil {
			node = *j.Node
		}
		if j.consumer == c.csm.id && f.match(j.Project, j.State, node, j.Labels) {
			items = append(items, j.Job)
		}
	}
	sortByCreated(items, func(x cloud.Job) time.Time { return x.CreatedAt }, func(x cloud.Job) string { return x.ID })
	page := paginate(c, items)
	c.json(200, &page)
}

type listFilter struct {
	c       *ctx
	project string
	labels  map[string]string
	states  []string
	node    string
}

func (c *ctx) listFilter() listFilter {
	f := listFilter{c: c, labels: c.labelFilter(), states: c.r.URL.Query()["state"], node: c.query("node")}
	if ref := c.query("project"); ref != "" {
		f.project = c.project(ref).ID
	}
	return f
}

func (f listFilter) match(project, state, node string, labels cloud.Labels) bool {
	if f.c.key != nil && f.c.key.project != "" && f.c.key.project != project {
		return false
	}
	return (f.project == "" || f.project == project) && stateMatch(state, f.states) &&
		(f.node == "" || f.node == node) && labelsMatch(labels, f.labels)
}

func getJob(c *ctx) {
	out := c.job(c.r.PathValue("job")).Job
	c.json(200, &out)
}

func cancelJob(c *ctx) {
	j := c.job(c.r.PathValue("job"))
	c.st.killJob(j, "cancel")
	out := j.Job
	c.json(202, &out)
}

func renewJobLease(c *ctx) {
	j := c.job(c.r.PathValue("job"))
	var in struct {
		LeaseSeconds *int `json:"lease_seconds"`
	}
	c.decode(&in)
	validLease(in.LeaseSeconds)
	if j.State == cloud.JobExited {
		fail(409, cloud.CodeConflict, "the job has exited")
	}
	if j.LeaseSeconds == nil && in.LeaseSeconds == nil {
		fail(409, cloud.CodeConflict, "the job has no lease")
	}
	if in.LeaseSeconds != nil {
		l := *in.LeaseSeconds
		j.LeaseSeconds = &l
	}
	j.LeaseExpiresAt = ptrTime(c.s.now().Add(time.Duration(*j.LeaseSeconds) * time.Second))
	j.Version++
	c.json(200, &cloud.Lease{LeaseSeconds: *j.LeaseSeconds, LeaseExpiresAt: *j.LeaseExpiresAt})
}

func getJobOutput(c *ctx) {
	j := c.job(c.r.PathValue("job"))
	c.streamOutput(j.out)
}

// streamOutput serves a journal from an offset (follow until complete, at most 5 minutes).
func (c *ctx) streamOutput(o *journal) {
	if o.expired {
		fail(410, cloud.CodeGone, "the output is no longer retained")
	}
	after := int64(0)
	if v := c.query("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			invalid("after", "invalid", "after is a non-negative byte offset")
		}
		after = n
	}
	stream := c.query("stream")
	if stream == "" {
		stream = "stdout"
	}
	if stream != "stdout" && stream != "stderr" {
		invalid("stream", "invalid", "stream is stdout or stderr")
	}
	follow := c.queryBool("follow")
	buf := func() []byte {
		if stream == "stderr" {
			return o.stderr
		}
		return o.stdout
	}
	if after > int64(len(buf())) && o.done {
		invalid("after", "out_of_range", "after is beyond the end of the stream (%d bytes)", len(buf()))
	}
	h := c.w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cloud-Output-Start", strconv.FormatInt(after, 10))
	h.Set("Cloud-Output-Size", strconv.Itoa(len(buf())))
	h.Set("Cloud-Output-Complete", strconv.FormatBool(o.done))
	c.w.WriteHeader(http.StatusOK)
	off := after
	flusher, _ := c.w.(http.Flusher)
	deadline := time.After(5 * time.Minute)
	for {
		b := buf()
		if off < int64(len(b)) {
			if _, err := c.w.Write(b[off:]); err != nil {
				return
			}
			off = int64(len(b))
			if flusher != nil {
				flusher.Flush()
			}
		}
		if !follow || o.done || o.expired {
			return
		}
		wait := o.notify
		c.unlock()
		select {
		case <-wait:
		case <-deadline:
			c.lock()
			return
		case <-c.r.Context().Done():
			c.lock()
			return
		case <-c.s.closed:
			c.lock()
			return
		}
		c.lock()
	}
}

// ---- sandboxes ----

func newInstance(csm string) instance {
	now := time.Now().UTC()
	return instance{consumer: csm, execs: map[string]*execState{}, treeDigs: map[string]string{}, fs: map[string]*fsEntry{
		"/workspace":  {dir: true, mode: "0755", owner: "agent", mtime: now},
		"/home/agent": {dir: true, mode: "0755", owner: "agent", mtime: now},
		"/tmp":        {dir: true, mode: "1777", owner: "root", mtime: now},
	}}
}

func createSandbox(c *ctx) {
	var in cloud.SandboxCreate
	c.decode(&in)
	p := c.project(in.Project)
	prof := c.st.profileForCreate(c.csm, in.Profile, cloud.KindJob)
	ttl := validTTL("ttl_seconds", in.TTLSeconds, prof.TimeoutSeconds)
	validLease(in.LeaseSeconds)
	validateLabels("labels", in.Labels)
	egress := c.st.validateEgress(p, prof, in.Egress, "egress")
	tpl := c.st.templateForCreate(c.csm, in.Template, cloud.KindJob)
	checkProfileAllows(prof, tpl.Name)
	c.st.reserve(p, map[string]int{"concurrent_sandboxes": 1, "running_vcpu": prof.VCPU, "running_memory_mib": prof.MemoryMiB})
	nodeID := c.st.place(p.Pool, prof, true, tpl, "")
	now := c.s.now()
	sb := &sandbox{instance: newInstance(c.csm.id)}
	sb.Sandbox = cloud.Sandbox{ID: newID("sbx"), Project: p.ID, Template: tpl.ID, Profile: prof.Name, Node: &nodeID, State: "creating",
		TTLSeconds: ttl, ExpiresAt: now.Add(time.Duration(ttl) * time.Second), Egress: egress, Gateway: in.Gateway,
		Labels: nonNilLabels(in.Labels), CreatedAt: now, Version: 1}
	if in.LeaseSeconds != nil {
		l := *in.LeaseSeconds
		sb.LeaseSeconds = &l
		sb.LeaseExpiresAt = ptrTime(now.Add(time.Duration(l) * time.Second))
	}
	c.st.sandboxes[sb.ID] = sb
	out := sb.Sandbox
	c.json(202, &out)
	c.st.later(2*time.Millisecond, func() {
		if sb.State != "creating" {
			return
		}
		sb.State = "ready"
		sb.Version++
		c.st.segStart(sb.consumer, sb.Project, nodeID, "sandbox", sb.ID, "running", prof.VCPU, prof.MemoryMiB, prof.DiskMiB, sb.Labels)
		c.st.emit(sb.consumer, sb.Project, cloud.EventSandboxState, "sandbox", sb.ID, cloud.EventStateData{State: "ready", Previous: "creating", Node: nodeID, Labels: sb.Labels})
	})
}

func (c *ctx) sandbox(id string) *sandbox {
	sb := c.st.sandboxes[id]
	if sb == nil || sb.consumer != c.csm.id || (c.key.project != "" && c.key.project != sb.Project) {
		notFound("sandbox")
	}
	return sb
}

func listSandboxes(c *ctx) {
	f := c.listFilter()
	var items []cloud.Sandbox
	for _, sb := range c.st.sandboxes {
		if sb.consumer == c.csm.id && sb.job == nil && f.match(sb.Project, sb.State, deref(sb.Node), sb.Labels) {
			items = append(items, sb.Sandbox)
		}
	}
	sortByCreated(items, func(x cloud.Sandbox) time.Time { return x.CreatedAt }, func(x cloud.Sandbox) string { return x.ID })
	page := paginate(c, items)
	c.json(200, &page)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getSandbox(c *ctx) {
	out := c.sandbox(c.r.PathValue("sandbox")).Sandbox
	c.json(200, &out)
}

func deleteSandbox(c *ctx) {
	sb := c.sandbox(c.r.PathValue("sandbox"))
	if sb.job != nil {
		c.st.killJob(sb.job, "cancel")
	} else {
		c.st.destroySandbox(sb, "deleted")
	}
	out := sb.Sandbox
	c.json(202, &out)
}

func (st *state) destroySandbox(sb *sandbox, reason string) {
	if sb.State == "destroyed" {
		return
	}
	prev := sb.State
	now := st.s.now()
	sb.State, sb.StateReason, sb.DestroyedAt = "destroyed", &reason, &now
	sb.Version++
	st.killExecs(&sb.instance, "sandbox_destroyed")
	st.segEnd(sb.ID, "")
	st.emit(sb.consumer, sb.Project, cloud.EventSandboxState, "sandbox", sb.ID, cloud.EventStateData{State: "destroyed", Previous: prev, Reason: reason, Node: deref(sb.Node), Labels: sb.Labels})
}

func renewSandboxLease(c *ctx) {
	sb := c.sandbox(c.r.PathValue("sandbox"))
	var in struct {
		LeaseSeconds *int `json:"lease_seconds"`
	}
	c.decode(&in)
	validLease(in.LeaseSeconds)
	if sb.State == "destroyed" {
		fail(409, cloud.CodeConflict, "the sandbox is destroyed")
	}
	if sb.LeaseSeconds == nil && in.LeaseSeconds == nil {
		fail(409, cloud.CodeConflict, "the sandbox has no lease")
	}
	if in.LeaseSeconds != nil {
		l := *in.LeaseSeconds
		sb.LeaseSeconds = &l
	}
	sb.LeaseExpiresAt = ptrTime(c.s.now().Add(time.Duration(*sb.LeaseSeconds) * time.Second))
	sb.Version++
	c.json(200, &cloud.Lease{LeaseSeconds: *sb.LeaseSeconds, LeaseExpiresAt: *sb.LeaseExpiresAt})
}
