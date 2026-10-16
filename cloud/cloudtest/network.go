package cloudtest

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

var (
	dnsNameRE    = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	presetNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	portsRE      = regexp.MustCompile(`^([0-9]{1,5})(-([0-9]{1,5}))?$`)
	dohResolvers = []string{"dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
		"dns.quad9.net", "doh.opendns.com", "dns.adguard.com", "doh.cleanbrowsing.org", "dns.nextdns.io"}
	internalPrefixes = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
		"100.64.0.0/10", "0.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128", "::/128")
	reservedPorts = map[int]bool{25: true, 465: true, 587: true, 49982: true, 49983: true}
)

func mustPrefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

type policyErrs struct{ errs []cloud.FieldError }

func (p *policyErrs) add(field, code, format string, args ...any) {
	p.errs = append(p.errs, cloud.FieldError{Field: field, Code: code, Message: fmt.Sprintf(format, args...)})
}

func (p *policyErrs) raise() {
	if len(p.errs) == 0 {
		return
	}
	e := perr(400, cloud.CodeInvalidPolicy, p.errs[0].Message)
	e.Errors = p.errs
	panic(e)
}

func parsePorts(s string) (lo, hi int, ok bool) {
	m := portsRE.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	lo, _ = strconv.Atoi(m[1])
	hi = lo
	if m[3] != "" {
		hi, _ = strconv.Atoi(m[3])
	}
	return lo, hi, lo >= 1 && hi <= 65535 && lo <= hi
}

func internalPrefix(p netip.Prefix) bool {
	for _, in := range internalPrefixes {
		if in.Overlaps(p) {
			return true
		}
	}
	return false
}

func (st *state) presetExists(p *project, ref string) bool {
	name, ver, _ := strings.Cut(ref, "@")
	var versions []cloud.Preset
	if pn, ok := strings.CutPrefix(name, "project:"); ok {
		versions = p.presets[pn]
	} else {
		versions = st.presets[name]
	}
	if len(versions) == 0 {
		return false
	}
	if ver == "" {
		return true
	}
	n, err := strconv.Atoi(ver)
	return err == nil && n >= 1 && n <= len(versions)
}

// validateEgress checks a policy against the profile's egress cap, the quotas and the rules of
// what may be opened, the way the node's host firewall would refuse it.
func (st *state) validateEgress(p *project, prof cloud.Profile, in *cloud.EgressPolicy, field string) cloud.EgressPolicy {
	var pol cloud.EgressPolicy
	if in == nil {
		pol = cloud.EgressPolicy{Mode: cloud.EgressNone}
		if prof.Egress != nil {
			pol.Mode = prof.Egress.Default
		}
	} else {
		pol = *in
	}
	var pe policyErrs
	rank := map[cloud.EgressMode]int{cloud.EgressNone: 0, cloud.EgressAllowlist: 1, cloud.EgressInternet: 2}
	r, ok := rank[pol.Mode]
	switch {
	case !ok:
		pe.add(field+".mode", "invalid", "mode is none, allowlist or internet")
	case prof.Egress != nil && r > rank[prof.Egress.Max]:
		pe.add(field+".mode", "not_allowed", "profile %s allows egress up to %s", prof.Name, prof.Egress.Max)
	}
	cs := st.consumers[p.consumer]
	for _, allowed := range [][]cloud.EgressMode{p.Quotas.AllowedEgressModes, cs.ceilings.AllowedEgressModes} {
		if allowed != nil && ok && !containsMode(allowed, pol.Mode) {
			pe.add(field+".mode", "not_allowed", "egress mode %s is not allowed for this project", pol.Mode)
		}
	}
	if pol.Mode == cloud.EgressNone && (len(pol.Presets)+len(pol.Domains)+len(pol.Rules) > 0) {
		pe.add(field, "invalid", "mode none takes no presets, domains or rules")
	}
	if pol.Mode == cloud.EgressInternet && len(pol.Domains)+len(pol.Presets) > 0 {
		pe.add(field, "invalid", "mode internet takes no presets or domains")
	}
	for i, ref := range pol.Presets {
		if !st.presetExists(p, ref) {
			pe.add(fmt.Sprintf("%s.presets[%d]", field, i), "unknown_preset", "unknown preset %q", ref)
		}
	}
	for i, d := range pol.Domains {
		f := fmt.Sprintf("%s.domains[%d]", field, i)
		dl := strings.ToLower(strings.TrimSuffix(d, "."))
		if _, err := netip.ParseAddr(strings.Trim(dl, "[]")); err == nil {
			pe.add(f, "ip_literal", "%q is an IP address; use rules for addresses", d)
			continue
		}
		if !dnsNameRE.MatchString(dl) {
			pe.add(f, "invalid", "%q is not a valid DNS name", d)
			continue
		}
		for _, doh := range dohResolvers {
			if dl == doh || strings.HasSuffix(dl, "."+doh) || strings.TrimPrefix(dl, "*.") == doh {
				pe.add(f, "doh_resolver", "%q is a DNS-over-HTTPS resolver", d)
			}
		}
	}
	for i, rule := range pol.Rules {
		f := fmt.Sprintf("%s.rules[%d]", field, i)
		if rule.Proto != "tcp" && rule.Proto != "udp" {
			pe.add(f+".proto", "invalid", "proto is tcp or udp")
		}
		if (rule.Host == "") == (rule.CIDR == "") {
			pe.add(f, "invalid", "a rule has exactly one of host or cidr")
		}
		if rule.CIDR != "" {
			pfx, err := netip.ParsePrefix(rule.CIDR)
			if err != nil {
				if a, err2 := netip.ParseAddr(rule.CIDR); err2 == nil {
					pfx = netip.PrefixFrom(a, a.BitLen())
				} else {
					pe.add(f+".cidr", "invalid", "%q is not a CIDR", rule.CIDR)
				}
			}
			if pfx.IsValid() && internalPrefix(pfx) {
				pe.add(f+".cidr", "internal_range", "%s overlaps an internal range", rule.CIDR)
			}
		}
		if rule.Host != "" && !dnsNameRE.MatchString(strings.ToLower(rule.Host)) {
			pe.add(f+".host", "invalid", "%q is not a valid DNS name", rule.Host)
		}
		lo, hi, okp := parsePorts(rule.Ports)
		if !okp {
			pe.add(f+".ports", "invalid", "ports is a port or a range like 8000-8100")
		} else {
			for port := range reservedPorts {
				if port >= lo && port <= hi {
					pe.add(f+".ports", "reserved_port", "port %d may not be opened", port)
				}
			}
		}
	}
	pe.raise()
	custom := len(pol.Domains)
	for _, q := range []*int{p.Quotas.CustomDomainsPerMachine, cs.ceilings.CustomDomainsPerMachine} {
		if q != nil && custom > *q {
			quotaExceeded("custom_domains_per_machine", "project", *q, 0, custom)
		}
	}
	if pol.Presets == nil {
		pol.Presets = []string{}
	}
	if pol.Domains == nil {
		pol.Domains = []string{}
	}
	if pol.Rules == nil {
		pol.Rules = []cloud.EgressRule{}
	}
	return pol
}

func (st *state) validateInbound(p *project, rules []cloud.InboundRule) {
	var pe policyErrs
	ports := 0
	for i, r := range rules {
		f := fmt.Sprintf("rules[%d]", i)
		if r.Proto != "tcp" && r.Proto != "udp" {
			pe.add(f+".proto", "invalid", "proto is tcp or udp")
		}
		lo, hi, ok := parsePorts(r.Ports)
		if !ok {
			pe.add(f+".ports", "invalid", "ports is a port or a range")
		} else {
			ports += hi - lo + 1
			if lo <= 49983 && hi >= 49982 {
				pe.add(f+".ports", "reserved_port", "ports 49982–49983 are reserved")
			}
		}
		if r.Source != "" {
			pfx, err := netip.ParsePrefix(r.Source)
			if err != nil || !pfx.Addr().Is6() || pfx.Addr().Is4In6() {
				pe.add(f+".source", "invalid", "source is an IPv6 CIDR")
			}
		}
	}
	pe.raise()
	cs := st.consumers[p.consumer]
	for _, q := range []*int{p.Quotas.InboundPortsPerMachine, cs.ceilings.InboundPortsPerMachine} {
		if q != nil && ports > *q {
			quotaExceeded("inbound_ports_per_machine", "project", *q, 0, ports)
		}
	}
}

// ---- changes ----

func (st *state) recordChange(m *machine, kind string, actor cloud.ChangeActor, version int64) *cloud.NetworkChange {
	ch := cloud.NetworkChange{ID: newID("chg"), Machine: m.ID, Kind: kind, State: "queued", Actor: actor.Actor, Reason: actor.Reason,
		Version: version, CreatedAt: st.s.now()}
	m.changes = append(m.changes, ch)
	idx := len(m.changes) - 1
	st.emit(m.consumer, m.Project, cloud.EventNetworkChange, "machine", m.ID, ch)
	st.later(3*time.Millisecond, func() {
		c := &m.changes[idx]
		if c.State != "queued" {
			return
		}
		now := st.s.now()
		c.State, c.AppliedAt = "applied", &now
		st.emit(m.consumer, m.Project, cloud.EventNetworkChange, "machine", m.ID, *c)
	})
	return &m.changes[idx]
}

func getMachineEgress(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	out := c.st.machineEgress(m)
	c.json(200, &out)
}

func (st *state) machineEgress(m *machine) cloud.MachineEgress {
	out := cloud.MachineEgress{Machine: m.ID, Policy: m.Egress, Version: m.EgressVersion}
	for i := len(m.changes) - 1; i >= 0; i-- {
		if m.changes[i].Kind == "egress" || m.changes[i].Kind == "preset" {
			ch := m.changes[i]
			out.Change = &ch
			break
		}
	}
	return out
}

func putMachineEgress(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.EgressPut
	c.decode(&in)
	c.checkIfMatch(m.EgressVersion)
	if m.State == cloud.MachineDestroyed {
		fail(409, cloud.CodeConflict, "the machine is destroyed")
	}
	p := c.st.projects[m.Project]
	pol := c.st.validateEgress(p, c.st.profiles[m.Profile], &in.EgressPolicy, "")
	m.Egress = pol
	m.EgressVersion++
	m.Version++
	ch := c.st.recordChange(m, "egress", in.ChangeActor, m.EgressVersion)
	out := cloud.MachineEgress{Machine: m.ID, Policy: m.Egress, Version: m.EgressVersion, Change: ch}
	c.json(200, &out)
}

func (st *state) allocAddress(m *machine, actor cloud.ChangeActor) *address {
	n := st.nodes[deref(m.Node)]
	addr := fmt.Sprintf("%s%x", n.block, n.nextAddr)
	n.nextAddr++ // never reused
	now := st.s.now()
	a := &address{consumer: m.consumer}
	mid := m.ID
	a.Address = cloud.Address{Address: addr, Project: m.Project, Machine: &mid, Node: n.id, State: "active", AssignedAt: now,
		History: []cloud.AddressAssignment{{Machine: m.ID, AssignedAt: now, Actor: actor.Actor}}}
	st.addresses[addr] = a
	m.Address = &addr
	m.Version++
	st.segStart(m.consumer, m.Project, n.id, "machine", addr, "address", 0, 0, 0, m.Labels)
	st.emit(m.consumer, m.Project, cloud.EventAddressAssigned, "address", addr, a.Address)
	st.recordChange(m, "address", actor, 0)
	return a
}

func (st *state) releaseAddr(a *address, m *machine) {
	now := st.s.now()
	a.State, a.ReleasedAt, a.ReusableAfter = "released", &now, ptrTime(now.Add(30*24*time.Hour))
	a.Machine = nil
	if n := len(a.History); n > 0 && a.History[n-1].ReleasedAt == nil {
		a.History[n-1].ReleasedAt = &now
	}
	st.segEnd(a.Address.Address, "address")
	if m != nil {
		m.Address = nil
		if len(m.Inbound) > 0 {
			m.Inbound = []cloud.InboundRule{}
			m.inbound++
		}
		m.Version++
	}
	st.emit(a.consumer, a.Project, cloud.EventAddressReleased, "address", a.Address.Address, a.Address)
}

func assignAddress(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.ChangeActor
	c.decode(&in)
	if m.State == cloud.MachineDestroyed {
		fail(409, cloud.CodeConflict, "the machine is destroyed")
	}
	if m.Address != nil {
		out := c.st.addresses[*m.Address].Address
		c.json(200, &out)
		return
	}
	c.st.requireNodeUp(m)
	c.st.reserve(c.st.projects[m.Project], map[string]int{"public_addresses": 1})
	a := c.st.allocAddress(m, in)
	out := a.Address
	c.json(201, &out)
}

func releaseAddress(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	if m.Address == nil {
		notFound("address")
	}
	a := c.st.addresses[*m.Address]
	c.st.releaseAddr(a, m)
	c.st.recordChange(m, "address", cloud.ChangeActor{}, 0)
	out := a.Address
	c.json(200, &out)
}

func putMachineInbound(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.InboundPut
	c.decode(&in)
	c.checkIfMatch(m.inbound)
	if m.Address == nil {
		fail(409, cloud.CodeConflict, "the machine has no public address")
	}
	if in.Rules == nil {
		invalid("rules", "required", "rules is required ([] to close everything)")
	}
	c.st.validateInbound(c.st.projects[m.Project], in.Rules)
	m.Inbound = in.Rules
	m.inbound++
	m.Version++
	ch := c.st.recordChange(m, "inbound", in.ChangeActor, m.inbound)
	c.json(200, &cloud.MachineInbound{Machine: m.ID, Rules: m.Inbound, Version: m.inbound, Change: ch})
}

func getMachineNetwork(c *ctx) {
	out := c.st.machineNetwork(c.machine(c.r.PathValue("machine")))
	c.json(200, &out)
}

func (st *state) machineNetwork(m *machine) cloud.MachineNetwork {
	out := cloud.MachineNetwork{Machine: m.ID, Egress: st.machineEgress(m),
		Inbound: cloud.MachineInbound{Machine: m.ID, Rules: m.Inbound, Version: m.inbound}, Binding: "not_applicable"}
	if m.Address != nil {
		a := st.addresses[*m.Address].Address
		out.Address = &a
	}
	if m.Egress.Mode == cloud.EgressAllowlist {
		out.Binding = "unbound"
		if machineRunning(m.State) {
			out.Binding = "bound"
		}
	}
	out.Delivery.State, out.Delivery.Generation = "applied", int64(len(m.changes))
	for i := len(m.changes) - 1; i >= 0 && len(out.Changes) < 20; i-- {
		ch := m.changes[i]
		out.Changes = append(out.Changes, ch)
		if i == len(m.changes)-1 {
			out.Delivery.State, out.Delivery.AppliedAt = ch.State, ch.AppliedAt
		}
	}
	out.EffectiveRules = []string{fmt.Sprintf("egress %s presets=%v domains=%v", m.Egress.Mode, m.Egress.Presets, m.Egress.Domains)}
	for _, r := range m.Inbound {
		out.EffectiveRules = append(out.EffectiveRules, fmt.Sprintf("inbound %s %s from %s", r.Proto, r.Ports, firstNonEmpty(r.Source, "::/0")))
	}
	out.Decisions = []cloud.EgressDecision{}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (c *ctx) address(addr string) *address {
	a := c.st.addresses[addr]
	if a == nil {
		if ap, err := netip.ParseAddr(addr); err == nil {
			a = c.st.addresses[ap.String()]
		}
	}
	if a == nil || a.consumer != c.csm.id || (c.key.project != "" && c.key.project != a.Project) {
		notFound("address")
	}
	return a
}

func listAddresses(c *ctx) {
	f := c.listFilter()
	var items []cloud.Address
	for _, k := range sortedKeys(c.st.addresses) {
		a := c.st.addresses[k]
		if a.consumer == c.csm.id && f.match(a.Project, a.State, a.Node, nil) {
			items = append(items, a.Address)
		}
	}
	page := paginate(c, items)
	c.json(200, &page)
}

func getAddress(c *ctx) {
	out := c.address(c.r.PathValue("address")).Address
	c.json(200, &out)
}

// ---- presets ----

func latest(vs []cloud.Preset) cloud.Preset { return vs[len(vs)-1] }

func pickVersion(vs []cloud.Preset, ver string) (cloud.Preset, bool) {
	if len(vs) == 0 {
		return cloud.Preset{}, false
	}
	if ver == "" {
		return latest(vs), true
	}
	n, err := strconv.Atoi(ver)
	if err != nil || n < 1 || n > len(vs) {
		return cloud.Preset{}, false
	}
	return vs[n-1], true
}

func listPresets(c *ctx) {
	var items []cloud.Preset
	for _, n := range sortedKeys(c.st.presets) {
		items = append(items, latest(c.st.presets[n]))
	}
	if ref := c.query("project"); ref != "" {
		p := c.project(ref)
		for _, n := range sortedKeys(p.presets) {
			if vs := p.presets[n]; len(vs) > 0 {
				items = append(items, latest(vs))
			}
		}
	}
	page := paginate(c, items)
	c.json(200, &page)
}

func getPreset(c *ctx) {
	name, ver, _ := strings.Cut(c.r.PathValue("preset"), "@")
	pr, ok := pickVersion(c.st.presets[name], ver)
	if !ok {
		notFound("preset")
	}
	c.json(200, &pr)
}

func listProjectPresets(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	var items []cloud.Preset
	for _, n := range sortedKeys(p.presets) {
		if vs := p.presets[n]; len(vs) > 0 {
			items = append(items, latest(vs))
		}
	}
	page := paginate(c, items)
	c.json(200, &page)
}

func getProjectPreset(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	name, ver, _ := strings.Cut(c.r.PathValue("preset"), "@")
	pr, ok := pickVersion(p.presets[name], ver)
	if !ok {
		notFound("preset")
	}
	c.json(200, &pr)
}

func putProjectPreset(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	name := c.r.PathValue("preset")
	if !presetNameRE.MatchString(name) {
		invalid("preset", "invalid", "preset names match [a-z][a-z0-9-]{0,62}")
	}
	var in cloud.PresetPut
	c.decode(&in)
	cur := int64(len(p.presets[name]))
	if h := c.r.Header.Get("If-Match"); h != "" && h != strconvQuote(cur) {
		fail(412, cloud.CodePreconditionFailed, "If-Match %s does not match the preset's version %d", h, cur)
	}
	if in.Domains == nil {
		invalid("domains", "required", "domains is required")
	}
	// Validated like an allowlist policy (with the most permissive cap).
	c.st.validateEgress(p, cloud.Profile{Name: "preset"}, &cloud.EgressPolicy{Mode: cloud.EgressAllowlist, Domains: in.Domains, Rules: in.Rules}, "")
	if in.Rules == nil {
		in.Rules = []cloud.EgressRule{}
	}
	pr := cloud.Preset{Name: name, Version: int(cur) + 1, Scope: "project", Project: p.ID, Category: in.Category, Description: in.Description,
		Domains: in.Domains, Rules: in.Rules, CreatedAt: c.s.now()}
	p.presets[name] = append(p.presets[name], pr)
	for _, id := range sortedKeys(c.st.machines) {
		m := c.st.machines[id]
		if m.Project == p.ID && m.State != cloud.MachineDestroyed && contains(m.Egress.Presets, "project:"+name) {
			c.st.recordChange(m, "preset", cloud.ChangeActor{Actor: "preset:" + name, Reason: fmt.Sprintf("preset %s version %d", name, pr.Version)}, m.EgressVersion)
		}
	}
	c.json(200, &pr)
}

func strconvQuote(v int64) string { return strconv.Quote(strconv.FormatInt(v, 10)) }

func deleteProjectPreset(c *ctx) {
	p := c.project(c.r.PathValue("project"))
	name := c.r.PathValue("preset")
	if len(p.presets[name]) == 0 {
		notFound("preset")
	}
	c.checkIfMatch(int64(len(p.presets[name])))
	for _, m := range c.st.machines {
		if m.Project != p.ID || m.State == cloud.MachineDestroyed {
			continue
		}
		for _, ref := range m.Egress.Presets {
			if n, _, _ := strings.Cut(ref, "@"); n == "project:"+name {
				fail(409, cloud.CodeConflict, "machine %s uses preset %s", m.ID, name)
			}
		}
	}
	delete(p.presets, name)
	c.noContent()
}
