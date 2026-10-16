package cloudtest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

const (
	eventRetention   = 7 * 24 * time.Hour
	outputRetention  = time.Hour
	idemRetention    = 24 * time.Hour
	stdoutLimit      = 16 << 20
	stderrLimit      = 1 << 20
	maxConcurrentDef = 8
	maxTerminalsDef  = 4
)

type consumer struct {
	id, name, state                   string
	pools                             []string
	ceilings                          cloud.Quotas
	allowedProfiles, allowedTemplates []string
	webhookURL                        *string
	webhookSecret                     string
	prevWebhookSecret                 string
	prevWebhookUntil                  time.Time

	seq       int64
	events    []cloud.Event
	notify    chan struct{}
	signers   []signer
	whPending []cloud.Event
	whWake    chan struct{}
}

// signer is a consumer's registered template signing key.
type signer struct {
	keyID string
	pub   ed25519.PublicKey
	names []string
}

type apiKey struct {
	id, consumer, name string
	scopes             []cloud.Scope
	project            string
	createdAt          time.Time
	expiresAt          *time.Time
	lastUsedAt         *time.Time
	revokedAt          *time.Time
}

func (k *apiKey) hasScope(s string) bool {
	for _, x := range k.scopes {
		if string(x) == s {
			return true
		}
	}
	return false
}

type node struct {
	id, pool      string
	connected     bool
	memMiB, slots int
	block         string
	nextAddr      int
}

type refReport struct {
	report   cloud.ReferenceReport
	machines map[string]bool
}

type project struct {
	cloud.Project
	consumer string
	reports  []refReport // newest last
	presets  map[string][]cloud.Preset
}

type journal struct {
	stdout, stderr []byte
	stderrDropped  bool
	done           bool
	expired        bool
	notify         chan struct{}
	retainedUntil  *time.Time
}

func newJournal() *journal { return &journal{notify: make(chan struct{})} }

func (j *journal) wake() {
	close(j.notify)
	j.notify = make(chan struct{})
}

type execState struct {
	cloud.Exec
	out    *journal
	cancel chan struct{}
	reason string
}

type fsEntry struct {
	data    []byte
	mode    string
	owner   string
	dir     bool
	symlink string
	mtime   time.Time
}

type instance struct { // shared by sandboxes and machines
	consumer string
	fs       map[string]*fsEntry
	execs    map[string]*execState
	order    []string
	treeDigs map[string]string
}

type job struct {
	cloud.Job
	consumer  string
	secretEnv map[string]string
	stdin     []byte
	files     []cloud.JobFile
	out       *journal
	cancel    chan struct{}
	killWhy   string
	sandbox   *sandbox
}

type sandbox struct {
	cloud.Sandbox
	instance
	job *job
}

type terminal struct {
	cloud.Terminal
	consumer     string
	buf          []byte
	notify       chan struct{}
	lastActivity time.Time
}

func (t *terminal) wake() {
	close(t.notify)
	t.notify = make(chan struct{})
}

type machine struct {
	cloud.Machine
	instance
	terminals map[string]*terminal
	inbound   int64
	changes   []cloud.NetworkChange
}

type address struct {
	cloud.Address
	consumer string
}

type template struct {
	cloud.Template
	failBuild bool
	logs      map[string]string
	// deletedAt: deleted (in consumerDeleted, restorable within the grace period unless purged).
	deletedAt time.Time
	purged    bool
}

type segment struct {
	consumer, project, node, kind, id string
	state                             string // running, paused, address
	start                             time.Time
	end                               *time.Time
	vcpu, memMiB, diskMiB             int
	labels                            cloud.Labels
}

type state struct {
	s *Server

	consumers map[string]*consumer
	keys      map[string]*apiKey // by token hash
	pools     map[string]bool
	nodes     map[string]*node
	profiles  map[string]cloud.Profile
	builtins  []*template
	consumerT map[string][]*template // consumer → templates
	// consumerDeleted are the consumer's deleted template versions (restorable within
	// the grace period unless purged; their version numbers are never reused).
	consumerDeleted map[string][]*template
	presets         map[string][]cloud.Preset
	projects        map[string]*project
	jobs            map[string]*job
	sandboxes       map[string]*sandbox
	machines        map[string]*machine
	terminals       map[string]*terminal
	addresses       map[string]*address
	idem            map[string]*idemEntry
	segments        []*segment
	usage           []cloud.UsageRecord // closed hours, materialized
	closedTo        time.Time           // usage is materialized up to here
	tr              *transportState
}

func newState(s *Server) *state {
	st := &state{
		s: s, consumers: map[string]*consumer{}, keys: map[string]*apiKey{}, pools: map[string]bool{}, nodes: map[string]*node{},
		profiles: map[string]cloud.Profile{}, consumerT: map[string][]*template{}, consumerDeleted: map[string][]*template{}, presets: map[string][]cloud.Preset{},
		projects: map[string]*project{}, jobs: map[string]*job{}, sandboxes: map[string]*sandbox{},
		machines: map[string]*machine{}, terminals: map[string]*terminal{}, addresses: map[string]*address{},
		idem: map[string]*idemEntry{}, tr: newTransportState(),
	}
	now := s.now()
	st.closedTo = now.Truncate(time.Hour)
	specs := s.opts.Nodes
	if len(specs) == 0 {
		specs = []NodeSpec{
			{ID: "node-1", Pool: "default", IPv6Block: "2001:db8:1::"},
			{ID: "node-2", Pool: "default", IPv6Block: "2001:db8:2::"},
			{ID: "node-3", Pool: "spare", IPv6Block: "2001:db8:3::"},
		}
	}
	for _, n := range specs {
		if n.MemoryMiB == 0 {
			n.MemoryMiB = 65536
		}
		if n.JobSlots == 0 {
			n.JobSlots = 32
		}
		st.pools[n.Pool] = true
		st.nodes[n.ID] = &node{id: n.ID, pool: n.Pool, connected: true, memMiB: n.MemoryMiB, slots: n.JobSlots,
			block: n.IPv6Block, nextAddr: 0x100}
	}
	for _, p := range []cloud.Profile{
		{Name: "job-small", Kind: cloud.KindJob, Description: "one vCPU, 1 GiB", VCPU: 1, MemoryMiB: 1024, DiskMiB: 2048, TimeoutSeconds: 3600, Backend: "envd"},
		{Name: "job-large", Kind: cloud.KindJob, Description: "four vCPU, 4 GiB", VCPU: 4, MemoryMiB: 4096, DiskMiB: 8192, TimeoutSeconds: 3600, Backend: "envd"},
		{Name: "machine-small", Kind: cloud.KindMachine, Description: "two vCPU, 2 GiB", VCPU: 2, MemoryMiB: 2048, DiskMiB: 10240,
			Modes: []cloud.MachineMode{cloud.OnDemand, cloud.AlwaysOn}, IdlePauseSeconds: 1800, Backend: "companion", Hostname: "machine"},
		{Name: "machine-large", Kind: cloud.KindMachine, Description: "four vCPU, 8 GiB", VCPU: 4, MemoryMiB: 8192, DiskMiB: 20480,
			Modes: []cloud.MachineMode{cloud.OnDemand}, IdlePauseSeconds: 1800, Backend: "companion", Hostname: "machine"},
	} {
		if p.Kind == cloud.KindJob {
			p.Egress = &struct {
				Max     cloud.EgressMode `json:"max"`
				Default cloud.EgressMode `json:"default"`
			}{cloud.EgressAllowlist, cloud.EgressNone}
		} else {
			p.Egress = &struct {
				Max     cloud.EgressMode `json:"max"`
				Default cloud.EgressMode `json:"default"`
			}{cloud.EgressInternet, cloud.EgressAllowlist}
		}
		p.MaxConcurrentExecs, p.MaxTerminals = maxConcurrentDef, maxTerminalsDef
		st.profiles[p.Name] = p
	}
	for _, p := range s.opts.Profiles {
		if p.MaxConcurrentExecs == 0 {
			p.MaxConcurrentExecs = maxConcurrentDef
		}
		if p.MaxTerminals == 0 {
			p.MaxTerminals = maxTerminalsDef
		}
		st.profiles[p.Name] = p
	}
	for _, b := range []struct {
		name string
		kind cloud.TemplateKind
	}{{"cloud-job", cloud.KindJob}, {"computer-base", cloud.KindMachine}} {
		t := &template{Template: cloud.Template{ID: "tpl_" + b.name + "@1", Name: b.name, Version: 1, Kind: b.kind, Origin: "builtin",
			RecipeHash: fakeHash(b.name), SDK: "e2b==2.52.0", State: "ready", CreatedAt: now}, logs: map[string]string{}}
		for _, id := range sortedKeys(st.nodes) {
			t.Builds = append(t.Builds, cloud.TemplateBuild{Node: id, State: "ready", BuildID: "bld_" + fakeHash(b.name + id)[:12], StartedAt: &now, FinishedAt: &now})
			t.logs[id] = "built-in template, shipped with the release\n"
		}
		if svcs := s.opts.BuiltinServices[b.name]; len(svcs) > 0 {
			if errs := cloud.ValidateServiceDeclarations(svcs); len(errs) > 0 {
				panic(fmt.Sprintf("cloudtest: BuiltinServices[%s]: %+v", b.name, errs))
			}
			t.Services = svcs
		}
		st.builtins = append(st.builtins, t)
	}
	st.presets["github"] = []cloud.Preset{{Name: "github", Version: 1, Scope: "builtin", Category: "Version control",
		Description: "GitHub web, API and content hosts", Domains: []string{"github.com", "api.github.com", "*.githubusercontent.com"}, Rules: []cloud.EgressRule{}, CreatedAt: now}}
	st.presets["pypi"] = []cloud.Preset{{Name: "pypi", Version: 1, Scope: "builtin", Category: "Package registries",
		Description: "Python package index", Domains: []string{"pypi.org", "files.pythonhosted.org"}, Rules: []cloud.EgressRule{}, CreatedAt: now}}
	return st
}

func fakeHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newID(prefix string) string { return prefix + "_" + randHex(10) }

func (st *state) closeAll() {
	for _, j := range st.jobs {
		if j.cancel != nil {
			select {
			case <-j.cancel:
			default:
				close(j.cancel)
			}
		}
	}
	for _, c := range st.consumers {
		if c.whWake != nil {
			close(c.whWake)
			c.whWake = nil
		}
	}
}

// ---- events ----

func (st *state) emit(csm string, project string, typ cloud.EventType, kind, id string, data any) {
	c := st.consumers[csm]
	if c == nil {
		return
	}
	b, _ := json.Marshal(data)
	c.seq++
	ev := cloud.Event{ID: newID("evt"), Seq: c.seq, Type: typ, Time: st.s.now(), Data: b}
	if project != "" {
		p := project
		ev.Project = &p
	}
	ev.Resource.Kind, ev.Resource.ID = kind, id
	c.events = append(c.events, ev)
	close(c.notify)
	c.notify = make(chan struct{})
	if c.webhookURL != nil && *c.webhookURL != "" {
		c.whPending = append(c.whPending, ev)
		st.startWebhooks(c)
		select {
		case c.whWake <- struct{}{}:
		default:
		}
	}
}

// ---- usage ----

func (st *state) segStart(csm, project, node, kind, id, state string, vcpu, mem, disk int, labels cloud.Labels) {
	st.segments = append(st.segments, &segment{consumer: csm, project: project, node: node, kind: kind, id: id, state: state,
		start: st.s.now(), vcpu: vcpu, memMiB: mem, diskMiB: disk, labels: copyLabels(labels)})
}

func (st *state) segEnd(id, state string) {
	now := st.s.now()
	for _, sg := range st.segments {
		if sg.id == id && sg.end == nil && (state == "" || sg.state == state) {
			t := now
			sg.end = &t
		}
	}
}

// closeUsage materializes the records of every hour that ended since the last call.
func (st *state) closeUsage() {
	now := st.s.now()
	for st.closedTo.Add(time.Hour).Compare(now) <= 0 {
		from, to := st.closedTo, st.closedTo.Add(time.Hour)
		recs := st.usageFor(from, to, true)
		st.usage = append(st.usage, recs...)
		perConsumer := map[string]int{}
		for _, r := range recs {
			perConsumer[r.Consumer]++
		}
		for _, cid := range sortedKeys(st.consumers) {
			st.emit(cid, "", cloud.EventUsagePeriodClosed, "usage", from.Format(time.RFC3339),
				cloud.EventUsagePeriodData{PeriodStart: from, PeriodEnd: to, Records: perConsumer[cid]})
		}
		st.closedTo = to
	}
}

func (st *state) usageFor(from, to time.Time, closed bool) []cloud.UsageRecord {
	type key struct{ id, kind string }
	acc := map[key]*cloud.UsageRecord{}
	var order []key
	for _, sg := range st.segments {
		end := to
		if sg.end != nil && sg.end.Before(end) {
			end = *sg.end
		}
		start := sg.start
		if start.Before(from) {
			start = from
		}
		if !end.After(start) {
			continue
		}
		sec := end.Sub(start).Seconds()
		kind := sg.kind
		if sg.state == "address" {
			kind = "address"
		}
		k := key{sg.id, kind}
		r := acc[k]
		if r == nil {
			r = &cloud.UsageRecord{Consumer: sg.consumer, Project: sg.project, Kind: kind, Node: sg.node,
				PeriodStart: from, PeriodEnd: to, Labels: copyLabels(sg.labels), Closed: closed}
			r.Resource = &struct {
				Kind string `json:"kind"`
				ID   string `json:"id"`
			}{kind, sg.id}
			acc[k] = r
			order = append(order, k)
		}
		switch sg.state {
		case "running":
			r.RunningSeconds += sec
			r.VCPUSeconds += sec * float64(sg.vcpu)
			r.MemoryMiBSeconds += sec * float64(sg.memMiB)
			if sg.kind == "machine" {
				r.DiskGiBHours += float64(sg.diskMiB) / 1024 * sec / 3600
			}
		case "paused":
			r.PausedSeconds += sec
			r.DiskGiBHours += float64(sg.diskMiB) / 1024 * sec / 3600
		case "address":
			r.AddressHours += sec / 3600
		}
	}
	out := make([]cloud.UsageRecord, 0, len(order))
	for _, k := range order {
		out = append(out, *acc[k])
	}
	return out
}

// ---- sweeps (TTL, leases, terminals, retention) ----

func (st *state) sweep() {
	now := st.s.now()
	for _, id := range sortedKeys(st.jobs) {
		j := st.jobs[id]
		if j.State == cloud.JobExited {
			if j.out.retainedUntil != nil && now.After(*j.out.retainedUntil) && !j.out.expired {
				j.out.expired, j.out.stdout, j.out.stderr = true, nil, nil
			}
			continue
		}
		switch {
		case now.After(j.ExpiresAt):
			st.killJob(j, "ttl")
		case j.LeaseExpiresAt != nil && now.After(*j.LeaseExpiresAt):
			st.killJob(j, "lease")
		}
	}
	for _, id := range sortedKeys(st.sandboxes) {
		sb := st.sandboxes[id]
		if sb.State == "destroyed" || sb.job != nil {
			continue
		}
		switch {
		case now.After(sb.ExpiresAt):
			st.destroySandbox(sb, "ttl")
		case sb.LeaseExpiresAt != nil && now.After(*sb.LeaseExpiresAt):
			st.destroySandbox(sb, "lease")
		}
	}
	for _, id := range sortedKeys(st.terminals) {
		t := st.terminals[id]
		if t.State != "open" {
			continue
		}
		switch {
		case now.Sub(t.CreatedAt) > time.Duration(t.MaxSeconds)*time.Second:
			st.closeTerminal(t, "max_time", nil)
		case now.Sub(t.lastActivity) > time.Duration(t.IdleTimeoutSeconds)*time.Second:
			st.closeTerminal(t, "idle", nil)
		}
	}
	for _, c := range st.consumers {
		cut := 0
		for cut < len(c.events) && now.Sub(c.events[cut].Time) > eventRetention {
			cut++
		}
		if cut > 0 {
			c.events = append([]cloud.Event(nil), c.events[cut:]...)
		}
	}
	for k, e := range st.idem {
		if now.Sub(e.storedAt) > idemRetention {
			delete(st.idem, k)
		}
	}
	st.closeUsage()
}

func copyLabels(l cloud.Labels) cloud.Labels {
	out := cloud.Labels{}
	for k, v := range l {
		out[k] = v
	}
	return out
}

func validateLabels(field string, l cloud.Labels) {
	if len(l) > 32 {
		invalid(field, "too_many", "at most 32 labels")
	}
	for k, v := range l {
		if len(k) == 0 || len(k) > 63 || !labelKeyOK(k) {
			invalid(field+"."+k, "invalid", "label keys are at most 63 characters of [a-z0-9._/-], starting and ending alphanumeric")
		}
		if len(v) > 255 {
			invalid(field+"."+k, "too_long", "label values are at most 255 characters")
		}
	}
}

func labelKeyOK(k string) bool {
	alnum := func(r byte) bool { return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') }
	if !alnum(k[0]) || !alnum(k[len(k)-1]) {
		return false
	}
	for i := 0; i < len(k); i++ {
		r := k[i]
		if !alnum(r) && !strings.ContainsRune("._/-", rune(r)) {
			return false
		}
	}
	return true
}

func ptrTime(t time.Time) *time.Time { return &t }

func ptrStr(s string) *string { return &s }

func sortByCreated[T any](items []T, created func(T) time.Time, id func(T) string) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := created(items[i]), created(items[j])
		if !a.Equal(b) {
			return a.After(b) // newest first
		}
		return id(items[i]) > id(items[j])
	})
}

func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }
