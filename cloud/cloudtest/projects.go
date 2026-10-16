package cloudtest

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"reflect"
	"strings"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) registerRoutes() {
	// consumer API
	s.route("GET", "/consumer", "any", getConsumer)
	s.route("GET", "/capacity", "any", getCapacity)
	s.route("POST", "/projects", "projects", createProject)
	s.route("GET", "/projects", "projects", listProjects)
	s.route("GET", "/projects/{project}", "projects", getProject)
	s.route("PATCH", "/projects/{project}", "projects", updateProject)
	s.route("DELETE", "/projects/{project}", "projects", deleteProject)
	s.route("GET", "/projects/{project}/quotas", "projects", getProjectQuotas)
	s.route("PUT", "/projects/{project}/quotas", "projects", putProjectQuotas)
	s.route("PUT", "/projects/{project}/pool", "projects", putProjectPool)
	s.route("PUT", "/projects/{project}/references", "projects", putProjectReferences)
	s.route("GET", "/projects/{project}/references", "projects", getProjectReferences)
	s.route("GET", "/projects/{project}/presets", "network", listProjectPresets)
	s.route("GET", "/projects/{project}/presets/{preset}", "network", getProjectPreset)
	s.route("PUT", "/projects/{project}/presets/{preset}", "network", putProjectPreset)
	s.route("DELETE", "/projects/{project}/presets/{preset}", "network", deleteProjectPreset)
	s.route("GET", "/presets", "any", listPresets)
	s.route("GET", "/presets/{preset}", "any", getPreset)
	s.route("POST", "/jobs", "jobs", createJob)
	s.route("GET", "/jobs", "jobs", listJobs)
	s.route("GET", "/jobs/{job}", "jobs", getJob)
	s.route("GET", "/jobs/{job}/output", "jobs", getJobOutput)
	s.route("POST", "/jobs/{job}/cancel", "jobs", cancelJob)
	s.route("POST", "/jobs/{job}/lease", "jobs", renewJobLease)
	s.route("POST", "/sandboxes", "sandboxes", createSandbox)
	s.route("GET", "/sandboxes", "sandboxes", listSandboxes)
	s.route("GET", "/sandboxes/{sandbox}", "sandboxes", getSandbox)
	s.route("DELETE", "/sandboxes/{sandbox}", "sandboxes", deleteSandbox)
	s.route("POST", "/sandboxes/{sandbox}/lease", "sandboxes", renewSandboxLease)
	s.route("POST", "/machines", "machines", createMachine)
	s.route("GET", "/machines", "machines", listMachines)
	s.route("GET", "/machines/{machine}", "machines", getMachine)
	s.route("PATCH", "/machines/{machine}", "machines", updateMachine)
	s.route("DELETE", "/machines/{machine}", "machines", deleteMachine)
	s.route("POST", "/machines/{machine}/start", "machines", machineAction("start"))
	s.route("POST", "/machines/{machine}/stop", "machines", machineAction("stop"))
	s.route("POST", "/machines/{machine}/restart", "machines", machineAction("restart"))
	s.route("POST", "/machines/{machine}/reset", "machines", resetMachine)
	s.route("POST", "/machines/{machine}/migrate", "machines", machineAction("migrate"))
	s.route("GET", "/machines/{machine}/metrics", "machines", getMachineMetrics)
	for _, k := range []struct{ kinds, param, scope string }{{"sandboxes", "sandbox", "sandboxes"}, {"machines", "machine", "machines:exec"}} {
		base := "/" + k.kinds + "/{" + k.param + "}"
		kind := k.param
		s.route("POST", base+"/exec", k.scope, execCreate(kind))
		s.route("GET", base+"/execs", k.scope, execList(kind))
		s.route("GET", base+"/execs/{exec}", k.scope, execGet(kind))
		s.route("GET", base+"/execs/{exec}/output", k.scope, execOutput(kind))
		s.route("POST", base+"/execs/{exec}/cancel", k.scope, execCancel(kind))
		s.route("GET", base+"/files", k.scope, filesList(kind))
		s.route("DELETE", base+"/files", k.scope, filesDelete(kind))
		s.route("GET", base+"/files/content", k.scope, filesRead(kind))
		s.route("PUT", base+"/files/content", k.scope, filesWrite(kind))
		s.route("PUT", base+"/files/tree", k.scope, filesTree(kind))
		s.route("POST", base+"/archive", k.scope, filesArchive(kind))
	}
	s.route("POST", "/machines/{machine}/terminals", "terminals", createTerminal)
	s.route("GET", "/machines/{machine}/terminals", "terminals", listTerminals)
	s.route("GET", "/machines/{machine}/terminals/{terminal}", "terminals", getTerminal)
	s.route("DELETE", "/machines/{machine}/terminals/{terminal}", "terminals", closeTerminalH)
	s.route("GET", "/machines/{machine}/terminals/{terminal}/stream", "terminals", streamTerminal)
	s.route("POST", "/machines/{machine}/terminals/{terminal}/input", "terminals", terminalInput)
	s.route("POST", "/machines/{machine}/terminals/{terminal}/resize", "terminals", terminalResize)
	s.route("GET", "/capabilities", "any", getCapabilities)
	s.route("GET", "/machines/{machine}/services", "machines:services", listMachineServices)
	s.route("POST", "/machines/{machine}/services/{service}/tickets", "machines:services", createServiceTicket)
	s.route("GET", "/machines/{machine}/companion", "machines:companion", getMachineCompanion)
	s.route("POST", "/machines/{machine}/companion/tickets", "machines:companion", createCompanionTicket)
	s.route("GET", "/machines/{machine}/egress", "network", getMachineEgress)
	s.route("PUT", "/machines/{machine}/egress", "network", putMachineEgress)
	s.route("POST", "/machines/{machine}/address", "network", assignAddress)
	s.route("DELETE", "/machines/{machine}/address", "network", releaseAddress)
	s.route("PUT", "/machines/{machine}/inbound", "network", putMachineInbound)
	s.route("GET", "/machines/{machine}/network", "network", getMachineNetwork)
	s.route("GET", "/addresses", "network", listAddresses)
	s.route("GET", "/addresses/{address}", "network", getAddress)
	s.route("GET", "/profiles", "any", listProfiles)
	s.route("GET", "/profiles/{profile}", "any", getProfile)
	s.route("GET", "/templates", "any", listTemplates)
	s.route("POST", "/templates", "templates", uploadTemplate)
	s.route("GET", "/templates/{template}", "any", getTemplate)
	s.route("DELETE", "/templates/{template}", "templates", deleteTemplate)
	s.route("PUT", "/templates/{template}/pin", "templates", pinTemplate)
	s.route("DELETE", "/templates/{template}/pin", "templates", unpinTemplate)
	s.route("POST", "/templates/{template}/restore", "templates", restoreTemplate)
	s.route("GET", "/templates/{template}/builds/{node}/log", "templates", getTemplateBuildLog)
	s.route("GET", "/events", "events", listEvents)
	s.route("GET", "/usage", "usage", listUsage)
	s.route("GET", "/usage/export", "usage", exportUsage)
}

// ---- consumer self, capacity ----

func getConsumer(c *ctx) {
	cs := c.csm
	out := cloud.ConsumerSelf{ID: cs.id, Name: cs.name, Pools: cs.pools, Ceilings: cs.ceilings,
		AllowedProfiles: nonNil(cs.allowedProfiles), AllowedTemplates: nonNil(cs.allowedTemplates), OperatorTerminalsDefault: true}
	out.Key.ID, out.Key.Scopes, out.Key.ExpiresAt = c.key.id, c.key.scopes, c.key.expiresAt
	if c.key.project != "" {
		out.Key.Project = ptrStr(c.key.project)
	}
	c.json(200, &out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func getCapacity(c *ctx) {
	poolName := c.query("pool")
	if poolName == "" {
		poolName = c.csm.pools[0]
	}
	if !contains(c.csm.pools, poolName) {
		notFound("pool")
	}
	var prof *cloud.Profile
	if name := c.query("profile"); name != "" {
		p := c.st.profileFor(c.csm, name)
		prof = &p
	}
	cap := c.st.capacity(poolName, prof)
	c.json(200, &cap)
}

func (st *state) capacity(poolName string, prof *cloud.Profile) cloud.Capacity {
	out := cloud.Capacity{Pool: poolName, AsOf: st.s.now()}
	for _, id := range sortedKeys(st.nodes) {
		n := st.nodes[id]
		if n.pool != poolName || !n.connected {
			continue
		}
		usedSlots, usedMem := st.nodeUse(n.id)
		out.NodesSchedulable++
		out.JobSlotsFree += n.slots - usedSlots
		out.MemoryFreeMiB += n.memMiB - usedMem
		if prof != nil && prof.MemoryMiB > 0 {
			fit := (n.memMiB - usedMem) / prof.MemoryMiB
			if prof.Kind == cloud.KindJob && n.slots-usedSlots < fit {
				fit = n.slots - usedSlots
			}
			out.Fits += fit
		}
	}
	if prof != nil {
		out.Profile = prof.Name
	}
	return out
}

func (st *state) nodeUse(nodeID string) (slots, memMiB int) {
	for _, j := range st.jobs {
		if j.State != cloud.JobExited && j.Node != nil && *j.Node == nodeID {
			slots++
			memMiB += st.profiles[j.Profile].MemoryMiB
		}
	}
	for _, sb := range st.sandboxes {
		if sb.job == nil && sb.State != "destroyed" && sb.Node != nil && *sb.Node == nodeID {
			slots++
			memMiB += st.profiles[sb.Profile].MemoryMiB
		}
	}
	for _, m := range st.machines {
		if m.Node != nil && *m.Node == nodeID && machineRunning(m.State) {
			memMiB += st.profiles[m.EffectiveProfile].MemoryMiB
		}
	}
	return
}

func machineRunning(state string) bool {
	switch state {
	case cloud.MachineCreating, cloud.MachineStarting, cloud.MachineReady, cloud.MachineRestarting, cloud.MachineMigrating:
		return true
	}
	return false
}

// place picks the schedulable node of the pool with the most free memory that fits.
func (st *state) place(poolName string, prof cloud.Profile, needSlot bool, tpl *template, exclude string) string {
	best, bestFree := "", -1
	anyNode := false
	for _, id := range sortedKeys(st.nodes) {
		n := st.nodes[id]
		if n.pool != poolName || !n.connected || id == exclude {
			continue
		}
		anyNode = true
		if tpl != nil && !tpl.readyOn(id) {
			continue
		}
		slots, mem := st.nodeUse(id)
		free := n.memMiB - mem
		if free < prof.MemoryMiB || (needSlot && slots >= n.slots) {
			continue
		}
		if free > bestFree {
			best, bestFree = id, free
		}
	}
	if best == "" {
		if anyNode && tpl != nil && !tpl.readyInPool(st, poolName) {
			fail(409, cloud.CodeTemplateNotReady, "template %s is not built on any schedulable node of pool %s", tpl.ID, poolName)
		}
		e := perr(409, cloud.CodeCapacityExhausted, "no schedulable node of pool "+poolName+" has room for profile "+prof.Name)
		e.RetryAfter = 5
		panic(e)
	}
	return best
}

func (t *template) readyOn(node string) bool {
	for _, b := range t.Builds {
		if b.Node == node && b.State == "ready" {
			return true
		}
	}
	return false
}

func (t *template) readyInPool(st *state, poolName string) bool {
	for _, b := range t.Builds {
		if n := st.nodes[b.Node]; n != nil && n.pool == poolName && b.State == "ready" {
			return true
		}
	}
	return false
}

// ---- projects ----

// project resolves a project reference (ID or external ID) of the calling consumer, honouring
// a project-pinned key; anything else is not found.
func (c *ctx) project(ref string) *project {
	var p *project
	if strings.HasPrefix(ref, "prj_") {
		p = c.st.projects[ref]
	} else {
		for _, x := range c.st.projects {
			if x.consumer == c.csm.id && x.ExternalID != nil && *x.ExternalID == ref && x.State == "active" {
				p = x
				break
			}
		}
	}
	if p == nil || p.consumer != c.csm.id || p.State != "active" || (c.key.project != "" && c.key.project != p.ID) {
		notFound("project")
	}
	return p
}

func createProject(c *ctx) {
	var in cloud.ProjectCreate
	c.decode(&in)
	if c.key.project != "" {
		fail(403, cloud.CodeForbidden, "a project-pinned key cannot create projects")
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 200 {
		invalid("name", "required", "name is required (at most 200 characters)")
	}
	if strings.HasPrefix(in.ExternalID, "prj_") || len(in.ExternalID) > 200 {
		invalid("external_id", "invalid", "external_id must not start with prj_ (at most 200 characters)")
	}
	validateLabels("labels", in.Labels)
	if in.Pool == "" {
		in.Pool = c.csm.pools[0]
	}
	if !contains(c.csm.pools, in.Pool) {
		invalid("pool", "not_allowed", "pool %q is not allowed for this consumer", in.Pool)
	}
	if in.Quotas != nil {
		c.st.checkWithinCeilings(c.csm, *in.Quotas)
	}
	opTerm := true
	if in.OperatorTerminal != nil {
		opTerm = *in.OperatorTerminal
	}
	if in.ExternalID != "" {
		for _, x := range c.st.projects {
			if x.consumer == c.csm.id && x.State == "active" && x.ExternalID != nil && *x.ExternalID == in.ExternalID {
				same := x.Name == in.Name && x.Pool == in.Pool && x.OperatorTerminal == opTerm &&
					reflect.DeepEqual(nonNilLabels(x.Labels), nonNilLabels(in.Labels)) &&
					(in.Quotas == nil || reflect.DeepEqual(x.Quotas, *in.Quotas))
				if !same {
					fail(409, cloud.CodeConflict, "a project with external_id %q exists with different settings", in.ExternalID)
				}
				out := x.Project
				c.json(200, &out)
				return
			}
		}
	}
	now := c.s.now()
	p := &project{consumer: c.csm.id, presets: map[string][]cloud.Preset{}}
	p.Project = cloud.Project{ID: newID("prj"), Name: in.Name, Pool: in.Pool, Labels: nonNilLabels(in.Labels),
		OperatorTerminal: opTerm, State: "active", CreatedAt: now, UpdatedAt: now, Version: 1}
	if in.ExternalID != "" {
		p.ExternalID = ptrStr(in.ExternalID)
	}
	if in.Quotas != nil {
		p.Quotas = *in.Quotas
	}
	c.st.projects[p.ID] = p
	out := p.Project
	c.json(201, &out)
}

func nonNilLabels(l cloud.Labels) cloud.Labels {
	if l == nil {
		return cloud.Labels{}
	}
	return l
}

func listProjects(c *ctx) {
	labels := c.labelFilter()
	ext := c.query("external_id")
	var items []cloud.Project
	for _, p := range c.st.projects {
		if p.consumer != c.csm.id || p.State != "active" || (c.key.project != "" && c.key.project != p.ID) {
			continue
		}
		if ext != "" && (p.ExternalID == nil || *p.ExternalID != ext) {
			continue
		}
		if !labelsMatch(p.Labels, labels) {
			continue
		}
		items = append(items, p.Project)
	}
	sortByCreated(items, func(p cloud.Project) timeT { return p.CreatedAt }, func(p cloud.Project) string { return p.ID })
	page := paginate(c, items)
	c.json(200, &page)
}

func getProject(c *ctx) {
	out := c.project(c.r.PathValue("project")).Project
	c.json(200, &out)
}

func updateProject(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	var in cloud.ProjectUpdate
	c.decode(&in)
	c.checkIfMatch(p.Version)
	if in.Name == nil && in.Labels == nil && in.OperatorTerminal == nil {
		invalid("", "required", "nothing to update")
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			invalid("name", "required", "name must not be empty")
		}
		p.Name = *in.Name
	}
	if in.Labels != nil {
		validateLabels("labels", in.Labels)
		p.Labels = in.Labels
	}
	if in.OperatorTerminal != nil {
		p.OperatorTerminal = *in.OperatorTerminal
	}
	p.Version++
	p.UpdatedAt = c.s.now()
	out := p.Project
	c.json(200, &out)
}

func deleteProject(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	c.checkIfMatch(p.Version)
	if c.st.projectHasLive(p.ID) {
		fail(409, cloud.CodeConflict, "the project still has live jobs, sandboxes, machines or addresses")
	}
	p.State = "deleted"
	p.Version++
	c.noContent()
}

func (st *state) projectHasLive(id string) bool {
	for _, j := range st.jobs {
		if j.Project == id && j.State != cloud.JobExited {
			return true
		}
	}
	for _, sb := range st.sandboxes {
		if sb.Project == id && sb.State != "destroyed" {
			return true
		}
	}
	for _, m := range st.machines {
		if m.Project == id && m.State != cloud.MachineDestroyed {
			return true
		}
	}
	for _, a := range st.addresses {
		if a.Project == id && a.State == "active" {
			return true
		}
	}
	return false
}

// ---- quotas ----

func quotaFields(q cloud.Quotas) map[string]*int {
	return map[string]*int{
		"concurrent_jobs": q.ConcurrentJobs, "concurrent_sandboxes": q.ConcurrentSandboxes, "running_vcpu": q.RunningVCPU,
		"running_memory_mib": q.RunningMemoryMiB, "machines": q.Machines, "always_on_machines": q.AlwaysOnMachines,
		"always_on_memory_mib": q.AlwaysOnMemoryMiB, "public_addresses": q.PublicAddresses,
		"inbound_ports_per_machine": q.InboundPortsPerMachine, "custom_domains_per_machine": q.CustomDomainsPerMachine,
		"templates": q.Templates, "template_versions_kept": q.TemplateVersionsKept,
	}
}

func quotaExceeded(name, scope string, limit, used, requested int) {
	e := perr(422, cloud.CodeQuotaExceeded, "quota "+name+" exceeded")
	e.Quota = &cloud.QuotaViolation{Name: name, Scope: scope, Limit: int64(limit), Used: int64(used), Requested: int64(requested)}
	panic(e)
}

func (st *state) checkWithinCeilings(cs *consumer, q cloud.Quotas) {
	ceil := quotaFields(cs.ceilings)
	for name, v := range quotaFields(q) {
		if v == nil {
			continue
		}
		if *v < 0 {
			invalid(name, "invalid", "%s must not be negative", name)
		}
		if c := ceil[name]; c != nil && *v > *c {
			quotaExceeded(name, "consumer", *c, 0, *v)
		}
	}
	if q.AllowedEgressModes != nil && cs.ceilings.AllowedEgressModes != nil {
		for _, m := range q.AllowedEgressModes {
			if !containsMode(cs.ceilings.AllowedEgressModes, m) {
				invalid("allowed_egress_modes", "not_allowed", "egress mode %s is above the consumer's ceiling", m)
			}
		}
	}
}

func containsMode(ms []cloud.EgressMode, m cloud.EgressMode) bool {
	for _, x := range ms {
		if x == m {
			return true
		}
	}
	return false
}

// use counts a quota's current use in one project ("" for the whole consumer).
func (st *state) use(csm, projectID string) cloud.QuotaUse {
	var u cloud.QuotaUse
	in := func(c, p string) bool { return c == csm && (projectID == "" || p == projectID) }
	for _, j := range st.jobs {
		if in(j.consumer, j.Project) && j.State != cloud.JobExited {
			u.ConcurrentJobs++
			pr := st.profiles[j.Profile]
			u.RunningVCPU += pr.VCPU
			u.RunningMemoryMiB += pr.MemoryMiB
		}
	}
	for _, sb := range st.sandboxes {
		if sb.job == nil && in(sb.consumer, sb.Project) && sb.State != "destroyed" {
			u.ConcurrentSandboxes++
			pr := st.profiles[sb.Profile]
			u.RunningVCPU += pr.VCPU
			u.RunningMemoryMiB += pr.MemoryMiB
		}
	}
	for _, m := range st.machines {
		if !in(m.consumer, m.Project) || m.State == cloud.MachineDestroyed {
			continue
		}
		u.Machines++
		pr := st.profiles[m.EffectiveProfile]
		if m.Mode == cloud.AlwaysOn {
			u.AlwaysOnMachines++
			u.AlwaysOnMemoryMiB += pr.MemoryMiB
		}
		if machineRunning(m.State) {
			u.RunningVCPU += pr.VCPU
			u.RunningMemoryMiB += pr.MemoryMiB
		}
	}
	for _, a := range st.addresses {
		if in(a.consumer, a.Project) && a.State == "active" {
			u.PublicAddresses++
		}
	}
	return u
}

func useField(u cloud.QuotaUse, name string) int {
	switch name {
	case "concurrent_jobs":
		return u.ConcurrentJobs
	case "concurrent_sandboxes":
		return u.ConcurrentSandboxes
	case "running_vcpu":
		return u.RunningVCPU
	case "running_memory_mib":
		return u.RunningMemoryMiB
	case "machines":
		return u.Machines
	case "always_on_machines":
		return u.AlwaysOnMachines
	case "always_on_memory_mib":
		return u.AlwaysOnMemoryMiB
	case "public_addresses":
		return u.PublicAddresses
	}
	return 0
}

// reserve checks that adding delta to the named counters stays within the project quota and
// the consumer ceiling (the fake is single-threaded under its lock, so check and create are
// atomic, like the row lock of the real store).
func (st *state) reserve(p *project, delta map[string]int) {
	cs := st.consumers[p.consumer]
	pu, cu := st.use(p.consumer, p.ID), st.use(p.consumer, "")
	pq, cq := quotaFields(p.Quotas), quotaFields(cs.ceilings)
	for _, name := range sortedKeys(delta) {
		d := delta[name]
		if d <= 0 {
			continue
		}
		if l := pq[name]; l != nil && useField(pu, name)+d > *l {
			quotaExceeded(name, "project", *l, useField(pu, name), d)
		}
		if l := cq[name]; l != nil && useField(cu, name)+d > *l {
			quotaExceeded(name, "consumer", *l, useField(cu, name), d)
		}
	}
}

func getProjectQuotas(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	out := cloud.ProjectQuotas{Project: p.ID, Limits: p.Quotas, Used: c.st.use(p.consumer, p.ID), Ceilings: c.csm.ceilings, Version: p.Version}
	c.json(200, &out)
}

func putProjectQuotas(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	var in cloud.Quotas
	c.decode(&in)
	c.checkIfMatch(p.Version)
	c.st.checkWithinCeilings(c.csm, in)
	p.Quotas = in
	p.Version++
	p.UpdatedAt = c.s.now()
	out := cloud.ProjectQuotas{Project: p.ID, Limits: p.Quotas, Used: c.st.use(p.consumer, p.ID), Ceilings: c.csm.ceilings, Version: p.Version}
	c.json(200, &out)
}

func putProjectPool(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	var in struct {
		Pool string `json:"pool"`
	}
	c.decode(&in)
	c.checkIfMatch(p.Version)
	if !contains(c.csm.pools, in.Pool) {
		invalid("pool", "not_allowed", "pool %q is not allowed for this consumer", in.Pool)
	}
	p.Pool = in.Pool
	p.Version++
	p.UpdatedAt = c.s.now()
	out := p.Project
	c.json(200, &out)
}

func putProjectReferences(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	var in struct {
		Machines []string `json:"machines"`
	}
	c.decode(&in)
	if in.Machines == nil {
		invalid("machines", "required", "machines is required (the full list; [] for none)")
	}
	set := map[string]bool{}
	unknown := []string{}
	for _, id := range in.Machines {
		set[id] = true
		m := c.st.machines[id]
		if m == nil || m.Project != p.ID || m.State == cloud.MachineDestroyed {
			unknown = append(unknown, id)
		}
	}
	rep := cloud.ReferenceReport{ID: newID("ref"), Project: p.ID, ReceivedAt: c.s.now(), MachinesCount: len(set), Unknown: unknown}
	p.reports = append(p.reports, refReport{report: rep, machines: set})
	if len(p.reports) > 2 {
		p.reports = p.reports[len(p.reports)-2:]
	}
	c.json(200, &rep)
}

func getProjectReferences(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	out := cloud.ProjectReferences{Project: p.ID, Reports: []cloud.ReferenceReport{}, Unreferenced: []string{}}
	for i := len(p.reports) - 1; i >= 0; i-- {
		out.Reports = append(out.Reports, p.reports[i].report)
	}
	for _, id := range sortedKeys(c.st.machines) {
		if m := c.st.machines[id]; m.Project == p.ID && c.st.unreferenced(m) {
			out.Unreferenced = append(out.Unreferenced, id)
		}
	}
	c.json(200, &out)
}

// unreferenced: the last two reports, at least an hour apart, both leave the machine out, and
// it was created before the first of them.
func (st *state) unreferenced(m *machine) bool {
	if m.State == cloud.MachineDestroyed {
		return false
	}
	p := st.projects[m.Project]
	if p == nil || len(p.reports) < 2 {
		return false
	}
	a, b := p.reports[len(p.reports)-2], p.reports[len(p.reports)-1]
	if b.report.ReceivedAt.Sub(a.report.ReceivedAt) < timeHour {
		return false
	}
	return !a.machines[m.ID] && !b.machines[m.ID] && m.CreatedAt.Before(a.report.ReceivedAt)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

var _ = http.MethodGet
