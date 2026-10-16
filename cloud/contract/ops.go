package contract

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

func (s *suite) testNetwork(t *testing.T) {
	a := s.a
	m := s.machine(t, a, a.project.ID, nil)
	defer a.c.Machines.Delete(s.ctx, m.ID)
	eg, err := a.c.Machines.Egress(s.ctx, m.ID)
	must(t, err)
	after := s.latestSeq(t, a)
	put := cloud.EgressPut{EgressPolicy: cloud.EgressPolicy{Mode: cloud.EgressAllowlist, Presets: []string{"github"},
		Domains: []string{"example.com", "*.example.org"}, Rules: []cloud.EgressRule{{Proto: "tcp", Host: "db.example.net", Ports: "5432"}}},
		ChangeActor: cloud.ChangeActor{Actor: "user-1", Reason: "approved #12"}}
	ne, err := a.c.Machines.SetEgress(s.ctx, m.ID, put, cloud.IfMatch(eg.Version))
	must(t, err)
	if ne.Version <= eg.Version || ne.Change == nil || ne.Change.Actor != "user-1" || ne.Policy.Mode != cloud.EgressAllowlist {
		t.Fatalf("egress put: %+v", ne)
	}
	_, err = a.c.Machines.SetEgress(s.ctx, m.ID, put, cloud.IfMatch(eg.Version))
	wantCode(t, err, cloud.CodePreconditionFailed)
	s.waitEvent(t, a, after, func(ev cloud.Event) bool {
		var ch cloud.NetworkChange
		return ev.Type == cloud.EventNetworkChange && ev.DecodeData(&ch) == nil && ch.ID == ne.Change.ID && ch.State == "applied"
	})
	nw, err := a.c.Machines.Network(s.ctx, m.ID)
	must(t, err)
	if nw.Egress.Version != ne.Version || len(nw.Changes) == 0 || nw.Delivery.State == "" {
		t.Fatalf("network: %+v", nw)
	}
	// Validation, with errors per field.
	for _, bad := range []cloud.EgressPolicy{
		{Mode: cloud.EgressAllowlist, Domains: []string{"not a name"}},
		{Mode: cloud.EgressAllowlist, Presets: []string{"no-such-preset"}},
		{Mode: cloud.EgressInternet, Rules: []cloud.EgressRule{{Proto: "tcp", CIDR: "10.0.0.0/8", Ports: "443"}}},
		{Mode: cloud.EgressInternet, Rules: []cloud.EgressRule{{Proto: "tcp", Host: "smtp.example.com", Ports: "25"}}},
		{Mode: cloud.EgressNone, Domains: []string{"example.com"}},
		{Mode: "everything"},
	} {
		_, err := a.c.Machines.SetEgress(s.ctx, m.ID, cloud.EgressPut{EgressPolicy: bad})
		if e := wantCode(t, err, cloud.CodeInvalidPolicy); len(e.Errors) == 0 {
			t.Fatalf("invalid_policy without errors[] for %+v", bad)
		}
	}
	// Allowed modes and custom domains are quotas.
	_, err = a.c.Projects.SetQuotas(s.ctx, a.project.ID, cloud.Quotas{AllowedEgressModes: []cloud.EgressMode{cloud.EgressNone, cloud.EgressAllowlist}, CustomDomainsPerMachine: cloud.Int(1)})
	must(t, err)
	_, err = a.c.Machines.SetEgress(s.ctx, m.ID, cloud.EgressPut{EgressPolicy: cloud.EgressPolicy{Mode: cloud.EgressInternet}})
	wantCode(t, err, cloud.CodeInvalidPolicy)
	_, err = a.c.Machines.SetEgress(s.ctx, m.ID, cloud.EgressPut{EgressPolicy: cloud.EgressPolicy{Mode: cloud.EgressAllowlist, Domains: []string{"a.example.com", "b.example.com"}}})
	if e := wantCode(t, err, cloud.CodeQuotaExceeded); e.Quota.Name != "custom_domains_per_machine" {
		t.Fatalf("quota %s", e.Quota.Name)
	}
	_, err = a.c.Projects.SetQuotas(s.ctx, a.project.ID, cloud.Quotas{})
	must(t, err)

	// Public address: assign (idempotent), inbound rules, release.
	after = s.latestSeq(t, a)
	var meta cloud.ResponseMeta
	addr, err := a.c.Machines.AssignAddress(s.ctx, m.ID, cloud.ChangeActor{Actor: "user-1"}, cloud.WithResponse(&meta))
	must(t, err)
	if meta.StatusCode != 201 || addr.State != "active" || addr.Machine == nil || *addr.Machine != m.ID || addr.Node != *m.Node {
		t.Fatalf("address: %d %+v", meta.StatusCode, addr)
	}
	again, err := a.c.Machines.AssignAddress(s.ctx, m.ID, cloud.ChangeActor{}, cloud.WithResponse(&meta))
	must(t, err)
	if again.Address != addr.Address || meta.StatusCode != 200 {
		t.Fatal("a second assign returned another address")
	}
	s.waitEvent(t, a, after, eventFor(cloud.EventAddressAssigned, addr.Address))
	ib, err := a.c.Machines.SetInbound(s.ctx, m.ID, cloud.InboundPut{Rules: []cloud.InboundRule{{Proto: "tcp", Ports: "443"}, {Proto: "tcp", Ports: "8000-8010", Source: "2001:db8:ffff::/48"}}})
	must(t, err)
	if len(ib.Rules) != 2 || ib.Change == nil {
		t.Fatalf("inbound: %+v", ib)
	}
	_, err = a.c.Machines.SetInbound(s.ctx, m.ID, cloud.InboundPut{Rules: []cloud.InboundRule{{Proto: "tcp", Ports: "443", Source: "10.0.0.0/8"}}})
	wantCode(t, err, cloud.CodeInvalidPolicy)
	_, err = a.c.Machines.SetInbound(s.ctx, m.ID, cloud.InboundPut{Rules: []cloud.InboundRule{}}, cloud.IfMatch(ib.Version-1))
	wantCode(t, err, cloud.CodePreconditionFailed)
	rel, err := a.c.Machines.ReleaseAddress(s.ctx, m.ID)
	must(t, err)
	if rel.State != "released" || rel.ReusableAfter == nil || rel.ReusableAfter.Sub(*rel.ReleasedAt) < 29*24*time.Hour {
		t.Fatalf("released: %+v", rel)
	}
	s.waitEvent(t, a, after, eventFor(cloud.EventAddressReleased, addr.Address))
	_, err = a.c.Machines.SetInbound(s.ctx, m.ID, cloud.InboundPut{Rules: []cloud.InboundRule{}})
	wantCode(t, err, cloud.CodeConflict)
	// The next address is a new one; history keeps the released one.
	addr2, err := a.c.Machines.AssignAddress(s.ctx, m.ID, cloud.ChangeActor{})
	must(t, err)
	if addr2.Address == addr.Address {
		t.Fatal("a released address was reused")
	}
	hist, err := a.c.Addresses.Get(s.ctx, addr.Address)
	must(t, err)
	if hist.State != "released" || len(hist.History) == 0 {
		t.Fatalf("address history: %+v", hist)
	}
	all, err := a.c.Addresses.List(s.ctx, cloud.ListOptions{Project: a.project.ID, Limit: 200})
	must(t, err)
	found := 0
	for _, x := range all.Data {
		if x.Address == addr.Address || x.Address == addr2.Address {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("address list has %d of 2", found)
	}
	// The public_addresses quota.
	p := s.newProject(t, a, cloud.ProjectCreate{Quotas: &cloud.Quotas{PublicAddresses: cloud.Int(0)}})
	m2 := s.machine(t, a, p.ID, nil)
	_, err = a.c.Machines.AssignAddress(s.ctx, m2.ID, cloud.ChangeActor{})
	if e := wantCode(t, err, cloud.CodeQuotaExceeded); e.Quota.Name != "public_addresses" {
		t.Fatalf("quota %s", e.Quota.Name)
	}
	_, err = a.c.Machines.Delete(s.ctx, m2.ID)
	must(t, err)
}

func (s *suite) testPresets(t *testing.T) {
	a := s.a
	l, err := a.c.Presets.List(s.ctx, cloud.ListOptions{})
	must(t, err)
	if len(l.Data) == 0 || l.Data[0].Scope != "builtin" {
		t.Fatalf("built-in presets: %+v", l.Data)
	}
	gh, err := a.c.Presets.Get(s.ctx, l.Data[0].Name)
	must(t, err)
	if len(gh.Domains) == 0 {
		t.Fatal("a built-in preset without domains")
	}
	p := s.newProject(t, a, cloud.ProjectCreate{})
	v1, err := a.c.Presets.PutProject(s.ctx, p.ID, "internal-apis", cloud.PresetPut{Domains: []string{"api.example.com"}, Category: "apis"})
	must(t, err)
	if v1.Version != 1 || v1.Scope != "project" {
		t.Fatalf("preset v1: %+v", v1)
	}
	pl, err := a.c.Presets.ListProject(s.ctx, p.ID, cloud.ListOptions{})
	must(t, err)
	if len(pl.Data) != 1 || pl.Data[0].Name != "internal-apis" {
		t.Fatalf("project presets: %+v", pl.Data)
	}
	both, err := a.c.Presets.List(s.ctx, cloud.ListOptions{Project: p.ID, Limit: 200})
	must(t, err)
	if len(both.Data) != len(l.Data)+1 {
		t.Fatalf("built-in plus project presets: %d", len(both.Data))
	}
	_, err = a.c.Presets.PutProject(s.ctx, p.ID, "internal-apis", cloud.PresetPut{Domains: []string{"dns.google"}})
	wantCode(t, err, cloud.CodeInvalidPolicy)
	m := s.machine(t, a, p.ID, func(in *cloud.MachineCreate) {
		in.Egress = &cloud.EgressPolicy{Mode: cloud.EgressAllowlist, Presets: []string{"project:internal-apis"}}
	})
	after := s.latestSeq(t, a)
	v2, err := a.c.Presets.PutProject(s.ctx, p.ID, "internal-apis", cloud.PresetPut{Domains: []string{"api.example.com", "api2.example.com"}}, cloud.IfMatch(1))
	must(t, err)
	if v2.Version != 2 {
		t.Fatalf("preset v2: %d", v2.Version)
	}
	_, err = a.c.Presets.PutProject(s.ctx, p.ID, "internal-apis", cloud.PresetPut{Domains: []string{"x.example.com"}}, cloud.IfMatch(1))
	wantCode(t, err, cloud.CodePreconditionFailed)
	// The rollout reaches the machine that follows the preset.
	s.waitEvent(t, a, after, func(ev cloud.Event) bool { return ev.Type == cloud.EventNetworkChange && ev.Resource.ID == m.ID })
	old, err := a.c.Presets.GetProject(s.ctx, p.ID, "internal-apis@1")
	must(t, err)
	if old.Version != 1 || len(old.Domains) != 1 {
		t.Fatalf("pinned version: %+v", old)
	}
	err = a.c.Presets.DeleteProject(s.ctx, p.ID, "internal-apis")
	wantCode(t, err, cloud.CodeConflict)
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
	must(t, a.c.Presets.DeleteProject(s.ctx, p.ID, "internal-apis"))
	_, err = a.c.Presets.GetProject(s.ctx, p.ID, "internal-apis")
	wantCode(t, err, cloud.CodeNotFound)
}

func (s *suite) pkg(t *testing.T, name string, kind cloud.TemplateKind, recipe string) []byte {
	t.Helper()
	if s.env.RealRecipes {
		recipe = realRecipe(recipe)
	}
	b, err := cloud.BuildTemplatePackage(cloud.TemplateManifest{Name: name, Kind: kind, Recipe: "recipe.py", SDK: "e2b==2.52.0"},
		map[string][]byte{"recipe.py": []byte(recipe), "context/app.txt": []byte("app")})
	must(t, err)
	return b
}

// waitTemplate polls a template until no build is queued or running (a real node builds an
// template per profile, which takes minutes).
func (s *suite) waitTemplate(t *testing.T, tn *tenant, id string) *cloud.Template {
	t.Helper()
	deadline := time.Now().Add(15 * time.Minute)
	for {
		tp, err := tn.c.Templates.Get(s.ctx, id)
		must(t, err)
		if tp.State != "building" || time.Now().After(deadline) {
			return tp
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *suite) testTemplates(t *testing.T) {
	a, b := s.a, s.b
	pub := s.signer.Public().(ed25519.PublicKey)
	provisioned(t, s.prov.AddTemplateSigner(s.ctx, a.id, pub, []string{"runner-*", "tool"}))
	signerID := cloud.KeyID(pub)
	name := "runner-" + s.tag
	pkg := s.pkg(t, name, cloud.KindJob, "print('build')\n")
	after := s.latestSeq(t, a)
	var meta cloud.ResponseMeta
	tp, err := a.c.Templates.Upload(s.ctx, pkg, cloud.SignTemplatePackage(s.signer, pkg), cloud.WithResponse(&meta))
	must(t, err)
	if meta.StatusCode != 201 || tp.Version != 1 || tp.ID != "tpl_"+name+"@1" || tp.Origin != "consumer" || tp.Signer != signerID || len(tp.Builds) == 0 {
		t.Fatalf("upload: %d %+v", meta.StatusCode, tp)
	}
	if st := s.waitTemplate(t, a, tp.ID).State; st != "ready" {
		t.Fatalf("template %s: %s", tp.ID, st)
	}
	s.waitEvent(t, a, after, func(ev cloud.Event) bool {
		var d cloud.EventTemplateBuildData
		return ev.Type == cloud.EventTemplateBuild && ev.DecodeData(&d) == nil && d.Template == tp.ID && d.State == "ready"
	})
	// Identical package: the same version.
	same, err := a.c.Templates.Upload(s.ctx, pkg, cloud.SignTemplatePackage(s.signer, pkg), cloud.WithResponse(&meta))
	must(t, err)
	if same.ID != tp.ID || meta.StatusCode != 200 {
		t.Fatal("identical package created a new version")
	}
	pkg2 := s.pkg(t, name, cloud.KindJob, "print('build v2')\n")
	tp2, err := a.c.Templates.Upload(s.ctx, pkg2, cloud.SignTemplatePackage(s.signer, pkg2))
	must(t, err)
	if tp2.Version != 2 {
		t.Fatalf("second version %d", tp2.Version)
	}
	// Refusals.
	_, other, _ := ed25519.GenerateKey(nil)
	_, err = a.c.Templates.Upload(s.ctx, pkg, cloud.SignTemplatePackage(other, pkg))
	if e := wantCode(t, err, cloud.CodeInvalidTemplatePackage); e.Errors[0].Code != "unregistered_key" {
		t.Fatalf("unregistered key: %+v", e.Errors)
	}
	sig := cloud.SignTemplatePackage(s.signer, pkg2)
	_, err = a.c.Templates.Upload(s.ctx, pkg, sig)
	if e := wantCode(t, err, cloud.CodeInvalidTemplatePackage); e.Errors[0].Code != "bad_signature" {
		t.Fatalf("bad signature: %+v", e.Errors)
	}
	notAllowed := s.pkg(t, "other-"+s.tag, cloud.KindJob, "x")
	_, err = a.c.Templates.Upload(s.ctx, notAllowed, cloud.SignTemplatePackage(s.signer, notAllowed))
	if e := wantCode(t, err, cloud.CodeInvalidTemplatePackage); e.Errors[0].Code != "name_not_allowed" {
		t.Fatalf("name not allowed: %+v", e.Errors)
	}
	_, err = a.c.Templates.Upload(s.ctx, []byte("not a package"), cloud.SignTemplatePackage(s.signer, []byte("not a package")))
	wantCode(t, err, cloud.CodeInvalidTemplatePackage)
	// B cannot see or use A's template, and A's signer is not B's.
	_, err = b.c.Templates.Get(s.ctx, tp.ID)
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: b.project.ID, Template: tp.Ref(), Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Templates.Upload(s.ctx, pkg, cloud.SignTemplatePackage(s.signer, pkg))
	wantCode(t, err, cloud.CodeInvalidTemplatePackage)
	// A uses it; the build log is there; a version in use cannot be deleted.
	j := s.job(t, a, a.project.ID, []string{"sleep", "30"}, func(in *cloud.JobCreate) { in.Template = tp.Ref() })
	if j.Template != tp.ID {
		t.Fatalf("job template %s", j.Template)
	}
	log, err := a.c.Templates.BuildLog(s.ctx, tp.ID, tp.Builds[0].Node)
	must(t, err)
	if log == "" {
		t.Fatal("empty build log")
	}
	err = a.c.Templates.Delete(s.ctx, tp.ID)
	wantCode(t, err, cloud.CodeConflict)
	_, err = a.c.Jobs.Cancel(s.ctx, j.ID)
	must(t, err)
	s.waitJob(t, a, j.ID)
	must(t, a.c.Templates.Delete(s.ctx, tp.ID))
	_, err = a.c.Templates.Get(s.ctx, tp.ID)
	wantCode(t, err, cloud.CodeNotFound)
	// Pinning: a pinned version cannot be deleted or purged; unpinned, it can.
	// A deleted version is restored within the grace period; a purged one is gone.
	pinned, err := a.c.Templates.Pin(s.ctx, tp2.Ref())
	must(t, err)
	if !pinned.Pinned || pinned.PinnedAt == nil || pinned.ID != tp2.ID {
		t.Fatalf("pinned %+v", pinned)
	}
	if got, err := a.c.Templates.Get(s.ctx, tp2.ID); err != nil || !got.Pinned {
		t.Fatalf("get of a pinned version: %+v %v", got, err)
	}
	_, err = b.c.Templates.Pin(s.ctx, tp2.Ref())
	wantCode(t, err, cloud.CodeNotFound)
	_, err = a.c.Templates.Pin(s.ctx, name)
	wantCode(t, err, cloud.CodeInvalidRequest)
	wantCode(t, a.c.Templates.Delete(s.ctx, tp2.Ref()), cloud.CodeConflict)
	wantCode(t, a.c.Templates.Delete(s.ctx, tp2.Ref(), cloud.WithPurge()), cloud.CodeConflict)
	unpinned, err := a.c.Templates.Unpin(s.ctx, tp2.Ref())
	must(t, err)
	if unpinned.Pinned || unpinned.PinnedAt != nil {
		t.Fatalf("unpinned %+v", unpinned)
	}
	must(t, a.c.Templates.Delete(s.ctx, tp2.Ref()))
	_, err = a.c.Templates.Get(s.ctx, tp2.ID)
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Templates.Restore(s.ctx, tp2.Ref())
	wantCode(t, err, cloud.CodeNotFound)
	restored, err := a.c.Templates.Restore(s.ctx, tp2.Ref())
	must(t, err)
	if restored.ID != tp2.ID || restored.Pinned {
		t.Fatalf("restored %+v", restored)
	}
	if _, err := a.c.Templates.Get(s.ctx, tp2.ID); err != nil {
		t.Fatalf("get of a restored version: %v", err)
	}
	must(t, a.c.Templates.Delete(s.ctx, tp2.Ref(), cloud.WithPurge()))
	_, err = a.c.Templates.Restore(s.ctx, tp2.Ref())
	wantCode(t, err, cloud.CodeGone)
	// A template that fails to build everywhere: template_not_ready.
	broken := s.pkg(t, "tool", cloud.KindJob, "# mock: build-fail\n")
	bt, err := a.c.Templates.Upload(s.ctx, broken, cloud.SignTemplatePackage(s.signer, broken))
	must(t, err)
	if bt.State != "failed" {
		bt = s.waitTemplate(t, a, bt.ID)
	}
	if bt.State != "failed" {
		t.Fatalf("broken template state %s", bt.State)
	}
	_, err = a.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: bt.Ref(), Profile: s.jobProfile, Exec: cloud.JobExec{Argv: []string{"true"}}})
	wantCode(t, err, cloud.CodeTemplateNotReady)
	// Built-ins cannot be deleted by consumers.
	err = a.c.Templates.Delete(s.ctx, s.jobTemplate)
	wantCode(t, err, cloud.CodeForbidden)
}

// testProfileTemplates: a profile with a templates list may be used only by the templates it
// names; any other is refused 400 invalid_request with a field error on profile. It runs where the server has such a profile that does not
// allow the suite's built-in template of its kind (skipped otherwise).
func (s *suite) testProfileTemplates(t *testing.T) {
	a := s.a
	ran := false
	notAllowed := func(err error) {
		t.Helper()
		e := wantCode(t, err, cloud.CodeInvalidRequest)
		if len(e.Errors) == 0 || e.Errors[0].Field != "profile" {
			t.Fatalf("field errors %+v", e.Errors)
		}
	}
	for _, kind := range []cloud.TemplateKind{cloud.KindJob, cloud.KindMachine} {
		ref := s.jobTemplate
		if kind == cloud.KindMachine {
			ref = s.machineTemplate
		}
		name, _, err := cloud.ParseTemplateRef(strings.TrimPrefix(ref, "tpl_"))
		must(t, err)
		profs, err := a.c.Profiles.List(s.ctx, kind)
		must(t, err)
		for _, p := range profs {
			if len(p.Templates) == 0 {
				if !p.AllowsTemplate(name) {
					t.Fatalf("profile %s without a templates list refuses %s", p.Name, name)
				}
				continue
			}
			if p.AllowsTemplate(name) {
				continue
			}
			ran = true
			if kind == cloud.KindJob {
				_, err = a.c.Jobs.Create(s.ctx, cloud.JobCreate{Project: a.project.ID, Template: ref, Profile: p.Name, Exec: cloud.JobExec{Argv: []string{"true"}}})
				notAllowed(err)
				_, err = a.c.Sandboxes.Create(s.ctx, cloud.SandboxCreate{Project: a.project.ID, Template: ref, Profile: p.Name})
				notAllowed(err)
			} else {
				_, err = a.c.Machines.Create(s.ctx, cloud.MachineCreate{Project: a.project.ID, Template: ref, Profile: p.Name})
				notAllowed(err)
				// A machine of the built-in template cannot move to the profile either.
				m := s.machine(t, a, a.project.ID, nil)
				_, err = a.c.Machines.Update(s.ctx, m.ID, cloud.MachineUpdate{Profile: cloud.String(p.Name)})
				notAllowed(err)
				_, err = a.c.Machines.Delete(s.ctx, m.ID)
				must(t, err)
			}
		}
	}
	if !ran {
		t.Skip("no profile with a templates list that leaves out the suite's built-in templates")
	}
}

func (s *suite) testEvents(t *testing.T) {
	a := s.a
	start := s.latestSeq(t, a)
	// after > latest: empty, cursor unchanged.
	l, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: start + 1000})
	must(t, err)
	if len(l.Data) != 0 || l.NextAfter != start+1000 {
		t.Fatalf("after beyond latest: %d events, next %d", len(l.Data), l.NextAfter)
	}
	// A long poll returns as soon as an event arrives.
	type res struct {
		l   *cloud.EventList
		err error
		at  time.Time
	}
	ch := make(chan res, 1)
	go func() {
		l, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: start, Wait: 20, Types: []cloud.EventType{cloud.EventMachineState}})
		ch <- res{l, err, time.Now()}
	}()
	time.Sleep(300 * time.Millisecond)
	t0 := time.Now()
	m := s.machine(t, a, a.project.ID, nil)
	r := <-ch
	must(t, r.err)
	if len(r.l.Data) == 0 || r.at.Sub(t0) > 10*time.Second {
		t.Fatalf("long poll: %d events after %s", len(r.l.Data), r.at.Sub(t0))
	}
	// Sequence numbers are strictly increasing; a type filter still advances the cursor.
	var prev int64 = start
	all, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: start, Limit: 1000})
	must(t, err)
	for _, ev := range all.Data {
		if ev.Seq <= prev || !strings.HasPrefix(ev.ID, "evt_") {
			t.Fatalf("seq %d after %d (%s)", ev.Seq, prev, ev.ID)
		}
		prev = ev.Seq
	}
	if all.NextAfter != prev || all.LatestSeq < prev {
		t.Fatalf("next_after %d latest %d last %d", all.NextAfter, all.LatestSeq, prev)
	}
	filtered, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: start, Types: []cloud.EventType{"no.such.type"}})
	must(t, err)
	if len(filtered.Data) != 0 || filtered.NextAfter != all.NextAfter {
		t.Fatalf("filtered cursor %d, want %d", filtered.NextAfter, all.NextAfter)
	}
	// Limit and has_more; resuming from next_after gives the rest exactly once.
	if len(all.Data) >= 2 {
		p1, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: start, Limit: 1})
		must(t, err)
		if len(p1.Data) != 1 || !p1.HasMore || p1.NextAfter != p1.Data[0].Seq {
			t.Fatalf("limit 1: %+v", p1)
		}
		p2, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: p1.NextAfter, Limit: 1000})
		must(t, err)
		if len(p2.Data) != len(all.Data)-1 || p2.Data[0].Seq != all.Data[1].Seq {
			t.Fatal("resuming from next_after lost or repeated events")
		}
	}
	// Project filter.
	pf, err := a.c.Events.List(s.ctx, cloud.EventListOptions{After: start, Project: a.project.ID, Limit: 1000})
	must(t, err)
	for _, ev := range pf.Data {
		if ev.Project == nil || *ev.Project != a.project.ID {
			t.Fatal("project filter")
		}
	}
	// The SDK's cursor loop delivers in order and stops on the handler's error.
	var got []int64
	stop := context.Canceled
	err = a.c.Events.Run(s.ctx, start, func(_ context.Context, ev cloud.Event) error {
		got = append(got, ev.Seq)
		if len(got) == len(all.Data) {
			return stop
		}
		return nil
	}, nil)
	if err != stop || len(got) != len(all.Data) {
		t.Fatalf("Run: %v, %d events", err, len(got))
	}
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
}

func (s *suite) testWebhooks(t *testing.T) {
	if !s.env.WebhooksReachable {
		t.Skip("the server cannot reach a local receiver (Env.WebhooksReachable)")
	}
	tn := s.newTenant(t, "webhook")
	var mu sync.Mutex
	var secret string
	var got []*cloud.Event
	fail := true
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail { // the first attempt fails: Azaleva Cloud retries
			fail = false
			w.WriteHeader(500)
			return
		}
		cloud.WebhookHandler(func(ev *cloud.Event) error { got = append(got, ev); return nil }, secret).ServeHTTP(w, r)
	}))
	defer recv.Close()
	mu.Lock()
	sec, err := s.prov.SetWebhook(s.ctx, tn.id, recv.URL)
	secret = sec
	mu.Unlock()
	provisioned(t, err)
	m := s.machine(t, tn, tn.project.ID, nil)
	deadline := time.Now().Add(60 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("webhooks received: %d", len(got))
	}
	// Same body as the cursor, in order.
	l, err := tn.c.Events.List(s.ctx, cloud.EventListOptions{})
	must(t, err)
	forMachine := false
	for i := range got[:2] {
		if got[i].ID != l.Data[i].ID || got[i].Seq != l.Data[i].Seq || got[i].Type != l.Data[i].Type {
			t.Fatalf("webhook %d: %s/%d vs %s/%d", i, got[i].ID, got[i].Seq, l.Data[i].ID, l.Data[i].Seq)
		}
		forMachine = forMachine || got[i].Resource.ID == m.ID
	}
	if !forMachine {
		t.Fatal("no webhook for the machine")
	}
	if fail {
		t.Fatal("the failed first delivery was not retried")
	}
}

func (s *suite) testUsage(t *testing.T) {
	a := s.a
	now := time.Now()
	l, err := a.c.Usage.List(s.ctx, cloud.UsageQuery{From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	must(t, err)
	_ = l
	_, err = a.c.Usage.List(s.ctx, cloud.UsageQuery{From: now, To: now.Add(-time.Hour)})
	wantCode(t, err, cloud.CodeInvalidRequest)
	if s.env.Advance == nil {
		t.Skip("closing usage hours needs Env.Advance")
	}
	p := s.newProject(t, a, cloud.ProjectCreate{})
	m := s.machine(t, a, p.ID, func(in *cloud.MachineCreate) { in.Labels = cloud.Labels{"bill": "me"} })
	after := s.latestSeq(t, a)
	s.env.Advance(2 * time.Hour)
	s.waitEvent(t, a, after, func(ev cloud.Event) bool { return ev.Type == cloud.EventUsagePeriodClosed })
	from, to := time.Now().Add(-6*time.Hour), time.Now().Add(6*time.Hour)
	q := cloud.UsageQuery{From: from, To: to, Project: p.ID}
	r1, err := a.c.Usage.List(s.ctx, q)
	must(t, err)
	var closed []cloud.UsageRecord
	for _, r := range r1.Data {
		if r.Closed && r.Resource != nil && r.Resource.ID == m.ID {
			closed = append(closed, r)
		}
	}
	if len(closed) == 0 || closed[0].RunningSeconds <= 0 || closed[0].VCPUSeconds <= 0 || closed[0].Labels["bill"] != "me" {
		t.Fatalf("closed usage records: %+v", closed)
	}
	// A closed hour never changes, even when the resource changes later.
	_, err = a.c.Machines.Update(s.ctx, m.ID, cloud.MachineUpdate{Labels: cloud.Labels{"bill": "other"}})
	must(t, err)
	s.env.Advance(time.Hour)
	r2, err := a.c.Usage.List(s.ctx, q)
	must(t, err)
	for _, c1 := range closed {
		ok := false
		for _, c2 := range r2.Data {
			if c2.Closed && c2.Resource != nil && c2.Resource.ID == c1.Resource.ID && c2.PeriodStart.Equal(c1.PeriodStart) {
				ok = mustJSON(t, c1) == mustJSON(t, c2)
			}
		}
		if !ok {
			t.Fatalf("closed record for %s changed", c1.PeriodStart)
		}
	}
	// Aggregates and B's view.
	g, err := a.c.Usage.List(s.ctx, cloud.UsageQuery{From: from, To: to, Project: p.ID, GroupBy: []string{"kind"}})
	must(t, err)
	if len(g.Data) == 0 || g.Data[0].Group["kind"] == "" {
		t.Fatalf("grouped usage: %+v", g.Data)
	}
	rb, err := s.b.c.Usage.List(s.ctx, cloud.UsageQuery{From: from, To: to, Limit: 200})
	must(t, err)
	if strings.Contains(mustJSON(t, rb), m.ID) {
		t.Fatal("B sees A's usage")
	}
	csv, err := a.c.Usage.Export(s.ctx, closed[0].PeriodStart)
	must(t, err)
	if !strings.HasPrefix(string(csv), "project,kind,resource") || !strings.Contains(string(csv), m.ID) {
		t.Fatalf("export: %q", csv)
	}
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
}

func (s *suite) testExpiry(t *testing.T) {
	s.needAdvance(t)
	a := s.a
	lease := s.job(t, a, a.project.ID, []string{"sleep", "600"}, func(in *cloud.JobCreate) { in.LeaseSeconds = cloud.Int(30) })
	ttl := s.job(t, a, a.project.ID, []string{"sleep", "600"}, func(in *cloud.JobCreate) { in.TTLSeconds = 60 })
	sb, err := a.c.Sandboxes.Create(s.ctx, cloud.SandboxCreate{Project: a.project.ID, Template: s.jobTemplate, Profile: s.jobProfile, LeaseSeconds: cloud.Int(30)})
	must(t, err)
	time.Sleep(100 * time.Millisecond)
	s.env.Advance(45 * time.Second)
	if j := s.waitJob(t, a, lease.ID); outcome(j) != "killed/lease" {
		t.Fatalf("lease loss: %s", outcome(j))
	}
	sbx, err := a.c.Sandboxes.Get(s.ctx, sb.ID)
	must(t, err)
	if sbx.State != "destroyed" || sbx.StateReason == nil || *sbx.StateReason != "lease" {
		t.Fatalf("sandbox lease loss: %s", sbx.State)
	}
	s.env.Advance(30 * time.Second)
	if j := s.waitJob(t, a, ttl.ID); outcome(j) != "killed/ttl" {
		t.Fatalf("ttl: %s", outcome(j))
	}
	// Output is retained for an hour after exit, then gone.
	s.env.Advance(61 * time.Minute)
	r, err := a.c.Jobs.Output(s.ctx, ttl.ID, cloud.OutputOptions{})
	must(t, err)
	_, err = io.ReadAll(r)
	wantCode(t, err, cloud.CodeGone)
	// Events are retained for 7 days; an older cursor is gone.
	cur := s.latestSeq(t, a)
	s.machine(t, a, a.project.ID, nil) // new events after cur
	s.env.Advance(8 * 24 * time.Hour)
	s.machine(t, a, a.project.ID, nil)
	_, err = a.c.Events.List(s.ctx, cloud.EventListOptions{After: cur})
	wantCode(t, err, cloud.CodeGone)
}

func (s *suite) testReferences(t *testing.T) {
	s.needAdvance(t)
	a := s.a
	p := s.newProject(t, a, cloud.ProjectCreate{})
	kept := s.machine(t, a, p.ID, nil)
	lost := s.machine(t, a, p.ID, nil)
	r1, err := a.c.Projects.ReportReferences(s.ctx, p.ID, []string{kept.ID, "mch_unknown"})
	must(t, err)
	if r1.MachinesCount != 2 || len(r1.Unknown) != 1 || r1.Unknown[0] != "mch_unknown" {
		t.Fatalf("report: %+v", r1)
	}
	// Two reports less than an hour apart are not enough.
	_, err = a.c.Projects.ReportReferences(s.ctx, p.ID, []string{kept.ID})
	must(t, err)
	refs, err := a.c.Projects.References(s.ctx, p.ID)
	must(t, err)
	if len(refs.Unreferenced) != 0 {
		t.Fatalf("unreferenced too early: %v", refs.Unreferenced)
	}
	s.env.Advance(61 * time.Minute)
	_, err = a.c.Projects.ReportReferences(s.ctx, p.ID, []string{kept.ID})
	must(t, err)
	refs, err = a.c.Projects.References(s.ctx, p.ID)
	must(t, err)
	if len(refs.Reports) != 2 || len(refs.Unreferenced) != 1 || refs.Unreferenced[0] != lost.ID {
		t.Fatalf("references: %+v", refs)
	}
	if m, err := a.c.Machines.Get(s.ctx, kept.ID); err != nil || m.State == cloud.MachineDestroyed {
		t.Fatal("the referenced machine was touched")
	}
}

// realRecipe turns the suite's mock recipes into real ones (Env.RealRecipes): a mock recipe
// with the build-fail marker fails at evaluation; any other becomes a minimal job template on
// python:3.12-slim with the agent user (the same first steps as the built-in cloud-job, so
// the build's layer cache serves most of it), tagged with the mock recipe's text.
func realRecipe(mock string) string {
	if strings.Contains(mock, "# mock: build-fail") {
		return "# a recipe that cannot be evaluated\ndef template(ctx):\n    raise RuntimeError('this recipe fails on purpose')\n"
	}
	return "# " + strings.ReplaceAll(strings.TrimSpace(mock), "\n", " ") + "\n" + `KIND = "job"


def template(ctx):
    from e2b import Template

    return (
        Template(file_context_path=ctx)
        .from_image("python:3.12-slim")
        .set_user("root")
        .run_cmd("id agent >/dev/null 2>&1 || useradd --uid 10001 --user-group --create-home --home-dir /home/agent --shell /bin/bash agent;"
                 " [ \"$(id -u agent)\" = 10001 ] && [ \"$(id -g agent)\" = 10001 ]"
                 " && mkdir -p /workspace && chown agent:agent /workspace && chmod 0755 /workspace")
        .set_user("agent")
        .set_workdir("/workspace")
    )
`
}
