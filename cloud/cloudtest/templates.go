package cloudtest

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// ---- profiles ----

func listProfiles(c *ctx) {
	kind := c.query("kind")
	out := struct {
		Data []cloud.Profile `json:"data"`
	}{Data: []cloud.Profile{}}
	for _, n := range sortedKeys(c.st.profiles) {
		p := c.st.profiles[n]
		if (kind == "" || string(p.Kind) == kind) && (len(c.csm.allowedProfiles) == 0 || contains(c.csm.allowedProfiles, n)) {
			out.Data = append(out.Data, p)
		}
	}
	c.json(200, &out)
}

func getProfile(c *ctx) {
	p := c.st.profileFor(c.csm, c.r.PathValue("profile"))
	c.json(200, &p)
}

// ---- templates ----

func (st *state) allTemplates() []*template {
	out := append([]*template{}, st.builtins...)
	for _, id := range sortedKeys(st.consumerT) {
		out = append(out, st.consumerT[id]...)
	}
	return out
}

func (st *state) renderTemplate(t *template) cloud.Template {
	out := t.Template
	out.Consumer = ""
	out.Builds = append([]cloud.TemplateBuild{}, t.Builds...)
	return out
}

func listTemplates(c *ctx) {
	kind, name := c.query("kind"), c.query("name")
	var items []cloud.Template
	add := func(t *template) {
		if (kind == "" || string(t.Kind) == kind) && (name == "" || t.Name == name) {
			items = append(items, c.st.renderTemplate(t))
		}
	}
	for _, t := range c.st.builtins {
		if len(c.csm.allowedTemplates) == 0 || contains(c.csm.allowedTemplates, t.Name) {
			add(t)
		}
	}
	for _, t := range c.st.consumerT[c.csm.id] {
		add(t)
	}
	page := paginate(c, items)
	c.json(200, &page)
}

func getTemplate(c *ctx) {
	t := c.st.resolveTemplate(c.csm, c.r.PathValue("template"), false)
	out := c.st.renderTemplate(t)
	c.json(200, &out)
}

func pkgError(field, code, format string, args ...any) {
	e := perr(400, cloud.CodeInvalidTemplatePackage, fmt.Sprintf(format, args...))
	e.Errors = []cloud.FieldError{{Field: field, Code: code, Message: e.Detail}}
	panic(e)
}

func uploadTemplate(c *ctx) {
	if err := c.r.ParseMultipartForm(32 << 20); err != nil {
		pkgError("package", "invalid", "expected multipart/form-data with package, signature and key_id: %v", err)
	}
	f, _, err := c.r.FormFile("package")
	if err != nil {
		pkgError("package", "required", "the package part is missing")
	}
	pkg, _ := io.ReadAll(io.LimitReader(f, cloud.TemplatePackageMaxBytes+1))
	sig, keyID := c.r.FormValue("signature"), c.r.FormValue("key_id")
	var signer *signer
	for i, s := range c.csm.signers {
		if s.keyID == keyID {
			signer = &c.csm.signers[i]
		}
	}
	if signer == nil {
		pkgError("key_id", "unregistered_key", "key %q is not registered for this consumer", keyID)
	}
	if err := cloud.VerifyTemplatePackage(signer.pub, pkg, sig); err != nil {
		pkgError("signature", "bad_signature", "%v", err)
	}
	m, files, err := cloud.ReadTemplatePackage(pkg)
	if err != nil {
		pkgError("package", "invalid", "%v", err)
	}
	if !cloud.TemplateNameAllowed(signer.names, m.Name) {
		pkgError("package", "name_not_allowed", "key %s may not publish template %q", keyID, m.Name)
	}
	if len(m.Services) > 0 && m.Kind != cloud.KindMachine {
		pkgError("services", "not_allowed", "only machine templates declare services")
	}
	if errs := cloud.ValidateServiceDeclarations(m.Services); len(errs) > 0 {
		e := perr(400, cloud.CodeInvalidTemplatePackage, "invalid services: "+errs[0].Message)
		e.Errors = errs
		panic(e)
	}
	for _, b := range c.st.builtins {
		if b.Name == m.Name {
			pkgError("package", "name_not_allowed", "%q is a built-in template name", m.Name)
		}
	}
	if len(c.st.profilesFor(m.Kind, m.Name)) == 0 {
		pkgError("package", "no_profile", "no %s profile allows template %q (the profiles' templates lists)", m.Kind, m.Name)
	}
	hash := cloud.TemplatePackageHash(pkg)
	own := c.st.consumerT[c.csm.id]
	maxV := 0
	for _, t := range c.st.consumerDeleted[c.csm.id] {
		if t.Name == m.Name && t.Version > maxV {
			maxV = t.Version // a version is never reused
		}
	}
	names := map[string]bool{}
	for _, t := range own {
		names[t.Name] = true
		if t.Name == m.Name {
			if t.RecipeHash == hash {
				out := c.st.renderTemplate(t)
				c.json(200, &out)
				return
			}
			if t.Version > maxV {
				maxV = t.Version
			}
		}
	}
	if q := c.csm.ceilings.Templates; q != nil && !names[m.Name] && len(names)+1 > *q {
		quotaExceeded("templates", "consumer", *q, len(names), 1)
	}
	now := c.s.now()
	t := &template{logs: map[string]string{}, failBuild: bytes.Contains(files[m.Recipe], []byte("# mock: build-fail"))}
	t.Template = cloud.Template{ID: fmt.Sprintf("tpl_%s@%d", m.Name, maxV+1), Name: m.Name, Version: maxV + 1, Kind: m.Kind,
		Origin: "consumer", Consumer: c.csm.id, RecipeHash: hash, Signer: keyID, SDK: m.SDK, SizeBytes: int64(len(pkg)),
		State: "building", Services: m.Services, CreatedAt: now}
	for _, nid := range sortedKeys(c.st.nodes) {
		if n := c.st.nodes[nid]; contains(c.csm.pools, n.pool) {
			t.Builds = append(t.Builds, cloud.TemplateBuild{Node: nid, State: "queued"})
		}
	}
	c.st.consumerT[c.csm.id] = append(own, t)
	c.st.runBuilds(c.csm, t)
	if keep := c.csm.ceilings.TemplateVersionsKept; keep != nil {
		c.st.pruneVersions(c.csm, m.Name, *keep)
	}
	out := c.st.renderTemplate(t)
	c.json(201, &out)
}

// runBuilds builds a template on its nodes (instantly in the mock driver; a recipe containing
// "# mock: build-fail" fails everywhere).
func (st *state) runBuilds(cs *consumer, t *template) {
	now := st.s.now()
	ready := 0
	for i := range t.Builds {
		b := &t.Builds[i]
		b.StartedAt, b.FinishedAt, b.BuildID = &now, &now, "bld_"+randHex(6)
		st.emit(cs.id, "", cloud.EventTemplateBuild, "template", t.ID, cloud.EventTemplateBuildData{Template: t.ID, Node: b.Node, State: "building"})
		if t.failBuild {
			b.State, b.Error = "failed", "recipe failed: mock build failure"
			t.logs[b.Node] = "building " + t.ID + " on " + b.Node + "\nERROR: mock build failure\n"
			st.emit(cs.id, "", cloud.EventTemplateBuild, "template", t.ID, cloud.EventTemplateBuildData{Template: t.ID, Node: b.Node, State: "failed", Error: b.Error})
			continue
		}
		b.State = "ready"
		ready++
		t.logs[b.Node] = "building " + t.ID + " on " + b.Node + "\nbuilt\n"
		st.emit(cs.id, "", cloud.EventTemplateBuild, "template", t.ID, cloud.EventTemplateBuildData{Template: t.ID, Node: b.Node, State: "ready"})
	}
	switch {
	case len(t.Builds) == 0 || ready == 0:
		t.State = "failed"
	case ready == len(t.Builds):
		t.State = "ready"
	default:
		t.State = "partial"
	}
}

func (st *state) templateInUse(t *template) bool {
	for _, m := range st.machines {
		if m.Template == t.ID && m.State != cloud.MachineDestroyed {
			return true
		}
	}
	for _, j := range st.jobs {
		if j.Template == t.ID && j.State != cloud.JobExited {
			return true
		}
	}
	return false
}

func (st *state) pruneVersions(cs *consumer, name string, keep int) {
	var same []*template
	for _, t := range st.consumerT[cs.id] {
		if t.Name == name {
			same = append(same, t)
		}
	}
	sort.Slice(same, func(i, j int) bool { return same[i].Version > same[j].Version })
	for i, t := range same {
		if i >= keep && !t.Pinned && !st.templateInUse(t) {
			st.removeTemplate(cs.id, t, false)
		}
	}
}

// templateGrace is how long a deleted template version can be restored.
func (st *state) templateGrace() time.Duration {
	switch g := st.s.opts.TemplateDeleteGrace; {
	case g < 0:
		return 0
	case g == 0:
		return 7 * 24 * time.Hour
	default:
		return g
	}
}

// removeTemplate moves a live version to the deleted ones (purged: not restorable).
func (st *state) removeTemplate(consumer string, t *template, purge bool) {
	var kept []*template
	for _, x := range st.consumerT[consumer] {
		if x != t {
			kept = append(kept, x)
		}
	}
	st.consumerT[consumer] = kept
	t.deletedAt, t.purged = st.s.now(), purge
	st.consumerDeleted[consumer] = append(st.consumerDeleted[consumer], t)
}

// deletedTemplate finds a deleted version of the consumer's (nil: none).
func (st *state) deletedTemplate(consumer, name string, version int) *template {
	for _, t := range st.consumerDeleted[consumer] {
		if t.Name == name && t.Version == version {
			return t
		}
	}
	return nil
}

func deleteTemplate(c *ctx) {
	purge := c.queryBool("purge")
	ref := strings.TrimPrefix(c.r.PathValue("template"), "tpl_")
	if name, version, err := cloud.ParseTemplateRef(ref); purge && err == nil && version > 0 {
		if t := c.st.deletedTemplate(c.csm.id, name, version); t != nil {
			t.purged = true
			c.noContent()
			return
		}
	}
	t := c.st.resolveTemplate(c.csm, c.r.PathValue("template"), false)
	if t.Origin == "builtin" {
		fail(403, cloud.CodeForbidden, "built-in templates cannot be deleted by consumers")
	}
	if t.Pinned {
		fail(409, cloud.CodeConflict, "template %s is pinned; unpin it first", t.ID)
	}
	if c.st.templateInUse(t) {
		fail(409, cloud.CodeConflict, "template %s is in use", t.ID)
	}
	c.st.removeTemplate(c.csm.id, t, purge)
	c.noContent()
}

// templateVersion reads the {template} of a call that names one version.
func (c *ctx) templateVersion() (string, int) {
	name, version, err := cloud.ParseTemplateRef(strings.TrimPrefix(c.r.PathValue("template"), "tpl_"))
	if err != nil {
		notFound("template " + c.r.PathValue("template"))
	}
	if version == 0 {
		invalid("template", "version_required", "name a template version (name@version)")
	}
	return name, version
}

func pinTemplate(c *ctx)   { setTemplatePin(c, true) }
func unpinTemplate(c *ctx) { setTemplatePin(c, false) }

func setTemplatePin(c *ctx, pin bool) {
	c.templateVersion()
	t := c.st.resolveTemplate(c.csm, c.r.PathValue("template"), false)
	if t.Origin == "builtin" {
		fail(403, cloud.CodeForbidden, "built-in templates cannot be pinned by consumers")
	}
	switch {
	case pin && !t.Pinned:
		now := c.s.now()
		t.Pinned, t.PinnedAt = true, &now
	case !pin && t.Pinned:
		t.Pinned, t.PinnedAt = false, nil
	}
	out := c.st.renderTemplate(t)
	c.json(200, &out)
}

func restoreTemplate(c *ctx) {
	name, version := c.templateVersion()
	for _, t := range c.st.consumerT[c.csm.id] {
		if t.Name == name && t.Version == version {
			out := c.st.renderTemplate(t)
			c.json(200, &out)
			return
		}
	}
	t := c.st.deletedTemplate(c.csm.id, name, version)
	if t == nil {
		notFound("template " + c.r.PathValue("template"))
	}
	if t.purged || !c.s.now().Before(t.deletedAt.Add(c.st.templateGrace())) {
		fail(410, cloud.CodeGone, "template %s was purged or deleted more than %s ago: it can no longer be restored", t.ID, c.st.templateGrace())
	}
	names := map[string]bool{}
	for _, x := range c.st.consumerT[c.csm.id] {
		names[x.Name] = true
	}
	if q := c.csm.ceilings.Templates; q != nil && !names[name] && len(names)+1 > *q {
		quotaExceeded("templates", "consumer", *q, len(names), 1)
	}
	var rest []*template
	for _, x := range c.st.consumerDeleted[c.csm.id] {
		if x != t {
			rest = append(rest, x)
		}
	}
	c.st.consumerDeleted[c.csm.id] = rest
	t.deletedAt = time.Time{}
	c.st.consumerT[c.csm.id] = append(c.st.consumerT[c.csm.id], t)
	sort.SliceStable(c.st.consumerT[c.csm.id], func(i, j int) bool {
		a, b := c.st.consumerT[c.csm.id][i], c.st.consumerT[c.csm.id][j]
		return a.Name < b.Name || (a.Name == b.Name && a.Version < b.Version)
	})
	out := c.st.renderTemplate(t)
	c.json(200, &out)
}

func getTemplateBuildLog(c *ctx) {
	t := c.st.resolveTemplate(c.csm, c.r.PathValue("template"), false)
	log, ok := t.logs[c.r.PathValue("node")]
	if !ok {
		notFound("build")
	}
	c.w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.w.WriteHeader(200)
	_, _ = io.WriteString(c.w, log)
}

// ---- events ----

func listEvents(c *ctx) {
	var after int64
	if v := c.query("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			invalid("after", "invalid", "after is a non-negative sequence number")
		}
		after = n
	}
	wait := c.queryInt("wait", 0, 0, 30)
	limit := c.queryInt("limit", 100, 1, 1000)
	types := c.r.URL.Query()["type"]
	project := ""
	if ref := c.query("project"); ref != "" {
		project = c.project(ref).ID
	}
	cs := c.csm
	deadline := time.After(time.Duration(wait) * time.Second)
	for {
		oldest := cs.seq - int64(len(cs.events)) + 1
		if after > 0 && after < oldest-1 {
			fail(410, cloud.CodeGone, "events after %d are no longer retained (oldest retained: %d)", after, oldest)
		}
		out := cloud.EventList{Data: []cloud.Event{}, NextAfter: after, LatestSeq: cs.seq}
		for _, ev := range cs.events {
			if ev.Seq <= after {
				continue
			}
			if len(out.Data) >= limit {
				out.HasMore = true
				break
			}
			out.NextAfter = ev.Seq
			if len(types) > 0 && !contains(types, string(ev.Type)) {
				continue
			}
			if project != "" && (ev.Project == nil || *ev.Project != project) {
				continue
			}
			if c.key.project != "" && ev.Project != nil && *ev.Project != c.key.project {
				continue
			}
			out.Data = append(out.Data, ev)
		}
		if len(out.Data) > 0 || wait == 0 {
			c.json(200, &out)
			return
		}
		after = out.NextAfter
		notify := cs.notify
		c.unlock()
		select {
		case <-notify:
			c.lock()
		case <-deadline:
			c.lock()
			out.LatestSeq = cs.seq
			c.json(200, &out)
			return
		case <-c.r.Context().Done():
			c.lock()
			return
		case <-c.s.closed:
			c.lock()
			return
		}
	}
}

// ---- webhooks ----

func (st *state) startWebhooks(cs *consumer) {
	if cs.whWake != nil {
		return
	}
	cs.whWake = make(chan struct{}, 1)
	wake := cs.whWake
	s := st.s
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		client := &http.Client{Timeout: 5 * time.Second}
		for {
			s.mu.Lock()
			if len(cs.whPending) == 0 || cs.webhookURL == nil || *cs.webhookURL == "" {
				s.mu.Unlock()
				select {
				case _, ok := <-wake:
					if !ok {
						return
					}
					continue
				case <-s.closed:
					return
				}
			}
			ev := cs.whPending[0]
			url := *cs.webhookURL
			secrets := []string{cs.webhookSecret}
			if cs.prevWebhookSecret != "" && s.now().Before(cs.prevWebhookUntil) {
				secrets = append(secrets, cs.prevWebhookSecret)
			}
			now := s.now()
			s.mu.Unlock()
			body, _ := json.Marshal(ev)
			ok := false
			for attempt := 1; attempt <= 8 && !ok; attempt++ {
				req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(cloud.HeaderSignature, cloud.SignPayload(now, body, secrets...))
				req.Header.Set(cloud.HeaderEventID, ev.ID)
				req.Header.Set(cloud.HeaderEventType, string(ev.Type))
				if resp, err := client.Do(req); err == nil {
					resp.Body.Close()
					ok = resp.StatusCode >= 200 && resp.StatusCode < 300
				}
				if !ok && attempt < 8 {
					select {
					case <-s.closed:
						return
					case <-time.After(time.Duration(attempt*attempt) * 20 * time.Millisecond):
					}
				}
			}
			s.mu.Lock()
			if len(cs.whPending) > 0 && cs.whPending[0].ID == ev.ID {
				cs.whPending = cs.whPending[1:]
			}
			s.mu.Unlock()
		}
	}()
}

// ---- usage ----

func parseTimeParam(c *ctx, name string) time.Time {
	v := c.query(name)
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		invalid(name, "required", "%s is a required RFC 3339 time", name)
	}
	return t.UTC()
}

func (st *state) usageRecords(consumerID string, from, to time.Time) []cloud.UsageRecord {
	var out []cloud.UsageRecord
	for _, r := range st.usage {
		if (consumerID == "" || r.Consumer == consumerID) && !r.PeriodStart.Before(from) && !r.PeriodEnd.After(to) {
			out = append(out, r)
		}
	}
	open := st.closedTo
	if !open.Before(from) && open.Before(to) {
		for _, r := range st.usageFor(open, open.Add(time.Hour), false) {
			if consumerID == "" || r.Consumer == consumerID {
				out = append(out, r)
			}
		}
	}
	return out
}

func groupUsage(recs []cloud.UsageRecord, groupBy string, allowed map[string]bool) []cloud.UsageRecord {
	if groupBy == "" {
		return recs
	}
	keys := strings.Split(groupBy, ",")
	for _, k := range keys {
		if !allowed[k] && !(allowed["label:"] && strings.HasPrefix(k, "label:")) {
			invalid("group_by", "invalid", "cannot group by %q", k)
		}
	}
	acc := map[string]*cloud.UsageRecord{}
	var order []string
	for _, r := range recs {
		g := map[string]string{}
		for _, k := range keys {
			switch {
			case k == "project":
				g[k] = r.Project
			case k == "consumer":
				g[k] = r.Consumer
			case k == "node":
				g[k] = r.Node
			case k == "kind":
				g[k] = r.Kind
			case k == "hour":
				g[k] = r.PeriodStart.Format(time.RFC3339)
			case k == "day":
				g[k] = r.PeriodStart.Format("2006-01-02")
			case strings.HasPrefix(k, "label:"):
				g[k] = r.Labels[strings.TrimPrefix(k, "label:")]
			}
		}
		b, _ := json.Marshal(g)
		id := string(b)
		a := acc[id]
		if a == nil {
			a = &cloud.UsageRecord{Group: g, PeriodStart: r.PeriodStart, PeriodEnd: r.PeriodEnd, Closed: true}
			acc[id] = a
			order = append(order, id)
		}
		if r.PeriodStart.Before(a.PeriodStart) {
			a.PeriodStart = r.PeriodStart
		}
		if r.PeriodEnd.After(a.PeriodEnd) {
			a.PeriodEnd = r.PeriodEnd
		}
		a.Closed = a.Closed && r.Closed
		a.RunningSeconds += r.RunningSeconds
		a.PausedSeconds += r.PausedSeconds
		a.VCPUSeconds += r.VCPUSeconds
		a.MemoryMiBSeconds += r.MemoryMiBSeconds
		a.DiskGiBHours += r.DiskGiBHours
		a.AddressHours += r.AddressHours
	}
	out := make([]cloud.UsageRecord, 0, len(order))
	for _, id := range order {
		out = append(out, *acc[id])
	}
	return out
}

func listUsage(c *ctx) {
	from, to := parseTimeParam(c, "from"), parseTimeParam(c, "to")
	if !to.After(from) {
		invalid("to", "invalid", "to must be after from")
	}
	project := ""
	if ref := c.query("project"); ref != "" {
		project = c.project(ref).ID
	}
	labels := c.labelFilter()
	var recs []cloud.UsageRecord
	for _, r := range c.st.usageRecords(c.csm.id, from, to) {
		if (project == "" || r.Project == project) && labelsMatch(r.Labels, labels) &&
			(c.key.project == "" || r.Project == c.key.project) {
			r.Consumer = ""
			recs = append(recs, r)
		}
	}
	recs = groupUsage(recs, c.query("group_by"), map[string]bool{"project": true, "kind": true, "hour": true, "day": true, "label:": true})
	if recs == nil {
		recs = []cloud.UsageRecord{}
	}
	if c.query("format") == "ndjson" {
		c.w.Header().Set("Content-Type", "application/x-ndjson")
		c.w.WriteHeader(200)
		enc := json.NewEncoder(c.w)
		for _, r := range recs {
			_ = enc.Encode(r)
		}
		return
	}
	page := paginate(c, recs)
	c.json(200, &page)
}

func exportUsage(c *ctx) {
	day, err := time.Parse("2006-01-02", c.query("day"))
	if err != nil {
		invalid("day", "required", "day is a required date (YYYY-MM-DD)")
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"project", "kind", "resource", "node", "period_start", "period_end", "running_seconds", "paused_seconds",
		"vcpu_seconds", "memory_mib_seconds", "disk_gib_hours", "address_hours", "labels"})
	for _, r := range c.st.usage {
		if r.Consumer != c.csm.id || r.PeriodStart.Before(day) || !r.PeriodStart.Before(day.Add(24*time.Hour)) {
			continue
		}
		if c.key.project != "" && r.Project != c.key.project {
			continue
		}
		lb, _ := json.Marshal(r.Labels)
		f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
		_ = w.Write([]string{r.Project, r.Kind, r.Resource.ID, r.Node, r.PeriodStart.Format(time.RFC3339), r.PeriodEnd.Format(time.RFC3339),
			f(r.RunningSeconds), f(r.PausedSeconds), f(r.VCPUSeconds), f(r.MemoryMiBSeconds), f(r.DiskGiBHours), f(r.AddressHours), string(lb)})
	}
	w.Flush()
	c.w.Header().Set("Content-Type", "text/csv")
	c.w.WriteHeader(200)
	_, _ = c.w.Write(buf.Bytes())
}
