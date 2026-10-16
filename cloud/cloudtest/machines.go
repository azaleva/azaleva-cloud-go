package cloudtest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

func (c *ctx) machine(id string) *machine {
	m := c.st.machines[id]
	if m == nil || m.consumer != c.csm.id || (c.key.project != "" && c.key.project != m.Project) {
		notFound("machine")
	}
	return m
}

// setMachineState records a transition, its usage segment and the machine.state event.
func (st *state) setMachineState(m *machine, state, reason string) {
	prev := m.State
	if prev == state {
		return
	}
	now := st.s.now()
	m.State = state
	if reason != "" {
		m.StateReason = ptrStr(reason)
	} else {
		m.StateReason = nil
	}
	m.Version++
	m.UpdatedAt = now
	pr := st.profiles[m.EffectiveProfile]
	st.segEnd(m.ID, "running")
	st.segEnd(m.ID, "paused")
	switch {
	case state == cloud.MachineReady:
		if !machineRunning(prev) || m.RunningSince == nil {
			m.RunningSince = &now
		}
		st.segStart(m.consumer, m.Project, deref(m.Node), "machine", m.ID, "running", pr.VCPU, pr.MemoryMiB, pr.DiskMiB, m.Labels)
	case state == cloud.MachinePaused || state == cloud.MachineStopped:
		m.RunningSince = nil
		st.segStart(m.consumer, m.Project, deref(m.Node), "machine", m.ID, "paused", 0, 0, pr.DiskMiB, m.Labels)
	case machineRunning(state):
		st.segStart(m.consumer, m.Project, deref(m.Node), "machine", m.ID, "running", pr.VCPU, pr.MemoryMiB, pr.DiskMiB, m.Labels)
	default:
		m.RunningSince = nil
	}
	if !machineRunning(state) {
		st.killExecs(&m.instance, "machine_stopped")
		for _, t := range m.terminals {
			st.closeTerminal(t, "machine_stopped", nil)
		}
	}
	st.emit(m.consumer, m.Project, cloud.EventMachineState, "machine", m.ID,
		cloud.EventStateData{State: state, Previous: prev, Reason: reason, Node: deref(m.Node), Labels: m.Labels})
}

func createMachine(c *ctx) {
	var in cloud.MachineCreate
	c.decode(&in)
	p := c.project(in.Project)
	prof := c.st.profileForCreate(c.csm, in.Profile, cloud.KindMachine)
	validateLabels("labels", in.Labels)
	if in.Mode == "" {
		in.Mode = cloud.OnDemand
		if prof.DefaultMode != "" {
			in.Mode = prof.DefaultMode
		}
	}
	if in.Mode != cloud.OnDemand && in.Mode != cloud.AlwaysOn {
		invalid("mode", "invalid", "mode is on_demand or always_on")
	}
	if !modeAllowed(prof, in.Mode) {
		invalid("mode", "not_allowed", "profile %s does not allow mode %s", prof.Name, in.Mode)
	}
	if len(in.Hostname) > 63 {
		invalid("hostname", "too_long", "hostname is at most 63 characters")
	}
	if len(in.Inbound) > 0 && !in.Address {
		invalid("inbound", "requires_address", "inbound rules need an address")
	}
	egress := c.st.validateEgress(p, prof, in.Egress, "egress")
	c.st.validateInbound(p, in.Inbound)
	tpl := c.st.templateForCreate(c.csm, in.Template, cloud.KindMachine)
	checkProfileAllows(prof, tpl.Name)
	delta := map[string]int{"machines": 1, "running_vcpu": prof.VCPU, "running_memory_mib": prof.MemoryMiB}
	if in.Mode == cloud.AlwaysOn {
		delta["always_on_machines"], delta["always_on_memory_mib"] = 1, prof.MemoryMiB
	}
	if in.Address {
		delta["public_addresses"] = 1
	}
	c.st.reserve(p, delta)
	nodeID := c.st.place(p.Pool, prof, false, tpl, "")
	now := c.s.now()
	m := &machine{instance: newInstance(c.csm.id), terminals: map[string]*terminal{}, inbound: 1}
	host := in.Hostname
	if host == "" {
		host = prof.Hostname
	}
	m.Machine = cloud.Machine{ID: newID("mch"), Project: p.ID, Template: tpl.ID, Profile: prof.Name, EffectiveProfile: prof.Name,
		Mode: in.Mode, Hold: in.Hold, Node: &nodeID, State: cloud.MachineCreating, Hostname: host, Egress: egress, EgressVersion: 1,
		Inbound: nonNilRules(in.Inbound), Gateway: in.Gateway, Labels: nonNilLabels(in.Labels), CreatedAt: now, UpdatedAt: now, Version: 1}
	c.st.machines[m.ID] = m
	if in.Address {
		c.st.allocAddress(m, cloud.ChangeActor{})
	}
	pr := prof
	c.st.segStart(m.consumer, m.Project, nodeID, "machine", m.ID, "running", pr.VCPU, pr.MemoryMiB, pr.DiskMiB, m.Labels)
	c.st.emit(m.consumer, m.Project, cloud.EventMachineState, "machine", m.ID, cloud.EventStateData{State: cloud.MachineCreating, Node: nodeID, Labels: m.Labels})
	out := m.Machine
	c.json(202, &out)
	c.st.later(5*time.Millisecond, func() {
		if m.State == cloud.MachineCreating {
			c.st.setMachineState(m, cloud.MachineReady, "")
		}
	})
}

func nonNilRules(r []cloud.InboundRule) []cloud.InboundRule {
	if r == nil {
		return []cloud.InboundRule{}
	}
	return r
}

func modeAllowed(p cloud.Profile, m cloud.MachineMode) bool {
	if m == cloud.OnDemand {
		return true
	}
	for _, x := range p.Modes {
		if x == m {
			return true
		}
	}
	return false
}

func listMachines(c *ctx) {
	f := c.listFilter()
	var items []cloud.Machine
	for _, m := range c.st.machines {
		if m.consumer == c.csm.id && f.match(m.Project, m.State, deref(m.Node), m.Labels) {
			items = append(items, c.st.renderMachine(m))
		}
	}
	sortByCreated(items, func(x cloud.Machine) time.Time { return x.CreatedAt }, func(x cloud.Machine) string { return x.ID })
	page := paginate(c, items)
	c.json(200, &page)
}

// restartPolicy is what a restart keeps: the profile's restart, else by mode (always_on: the
// whole disk).
func (st *state) restartPolicy(m *machine) string {
	if p := st.profiles[m.Profile]; p.Restart != "" {
		return p.Restart
	}
	if m.Mode == cloud.AlwaysOn {
		return cloud.RestartKeepDisk
	}
	return cloud.RestartFreshTemplate
}

func (st *state) renderMachine(m *machine) cloud.Machine {
	out := m.Machine
	out.Restart = st.restartPolicy(m)
	var run, paused float64
	now := st.s.now()
	for _, sg := range st.segments {
		if sg.id != m.ID {
			continue
		}
		end := now
		if sg.end != nil {
			end = *sg.end
		}
		switch sg.state {
		case "running":
			run += end.Sub(sg.start).Seconds()
		case "paused":
			paused += end.Sub(sg.start).Seconds()
		}
	}
	out.Usage = &struct {
		RunningSeconds int64 `json:"running_seconds"`
		PausedSeconds  int64 `json:"paused_seconds"`
	}{int64(run), int64(paused)}
	return out
}

func getMachine(c *ctx) {
	out := c.st.renderMachine(c.machine(c.r.PathValue("machine")))
	c.json(200, &out)
}

func updateMachine(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.MachineUpdate
	c.decode(&in)
	c.checkIfMatch(m.Version)
	if in.Profile == nil && in.Mode == nil && in.Hold == nil && in.Labels == nil {
		invalid("", "required", "nothing to update")
	}
	if m.State == cloud.MachineDestroyed {
		fail(409, cloud.CodeConflict, "the machine is destroyed")
	}
	p := c.st.projects[m.Project]
	prof := c.st.profiles[m.Profile]
	if in.Profile != nil {
		prof = c.st.profileForCreate(c.csm, *in.Profile, cloud.KindMachine)
		checkProfileAllows(prof, m.Template)
	}
	mode := m.Mode
	if in.Mode != nil {
		mode = *in.Mode
		if mode != cloud.OnDemand && mode != cloud.AlwaysOn {
			invalid("mode", "invalid", "mode is on_demand or always_on")
		}
	}
	if !modeAllowed(prof, mode) {
		invalid("mode", "not_allowed", "profile %s does not allow mode %s", prof.Name, mode)
	}
	if mode == cloud.AlwaysOn && m.Mode != cloud.AlwaysOn {
		c.st.reserve(p, map[string]int{"always_on_machines": 1, "always_on_memory_mib": prof.MemoryMiB})
	}
	if in.Labels != nil {
		validateLabels("labels", in.Labels)
		m.Labels = in.Labels
	}
	if in.Hold != nil {
		m.Hold = *in.Hold
	}
	m.Profile, m.Mode = prof.Name, mode
	m.Version++
	m.UpdatedAt = c.s.now()
	if mode == cloud.AlwaysOn && (m.State == cloud.MachineStopped || m.State == cloud.MachinePaused) {
		c.st.startMachine(m)
	}
	out := c.st.renderMachine(m)
	c.json(200, &out)
}

func deleteMachine(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	c.checkIfMatch(m.Version)
	c.st.destroyMachine(m, "deleted")
	out := c.st.renderMachine(m)
	c.json(202, &out)
}

func (st *state) destroyMachine(m *machine, reason string) {
	if m.State == cloud.MachineDestroyed {
		return
	}
	for _, a := range st.addresses {
		if a.State == "active" && a.Machine != nil && *a.Machine == m.ID {
			st.releaseAddr(a, m)
		}
	}
	st.setMachineState(m, cloud.MachineDestroyed, reason)
	st.segEnd(m.ID, "")
}

func (st *state) startMachine(m *machine) {
	if m.Node != nil {
		if n := st.nodes[*m.Node]; n != nil && !n.connected {
			e := perr(409, cloud.CodeNodeUnavailable, "the machine's node "+*m.Node+" is unavailable")
			e.RetryAfter = 30
			panic(e)
		}
	}
	switch m.State {
	case cloud.MachineReady, cloud.MachineStarting, cloud.MachineCreating, cloud.MachineRestarting, cloud.MachineMigrating:
		return
	case cloud.MachineDestroyed:
		fail(409, cloud.CodeConflict, "the machine is destroyed")
	}
	p := st.projects[m.Project]
	prof := st.profiles[m.Profile]
	st.reserve(p, map[string]int{"running_vcpu": prof.VCPU, "running_memory_mib": prof.MemoryMiB})
	m.EffectiveProfile = m.Profile
	st.setMachineState(m, cloud.MachineStarting, "")
	st.later(5*time.Millisecond, func() {
		if m.State == cloud.MachineStarting {
			st.setMachineState(m, cloud.MachineReady, "")
		}
	})
}

// resetMachine rebuilds the machine from its template, /workspace only, once confirmed.
func resetMachine(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.MachineReset
	c.decode(&in)
	if !in.ConfirmDiskReset {
		invalid("confirm_disk_reset", "required", "a reset keeps /workspace only; confirm it with confirm_disk_reset: true")
	}
	c.st.doMachineAction(m, "reset", "", "reset")
	out := c.st.renderMachine(m)
	c.json(202, &out)
}

func machineAction(action string) handler {
	return func(c *ctx) {
		m := c.machine(c.r.PathValue("machine"))
		var in struct {
			Node string `json:"node"`
		}
		if action == "migrate" {
			c.decode(&in)
		}
		c.st.doMachineAction(m, action, in.Node, "")
		out := c.st.renderMachine(m)
		c.json(202, &out)
	}
}

func (st *state) doMachineAction(m *machine, action, target, reason string) {
	if m.State == cloud.MachineDestroyed {
		fail(409, cloud.CodeConflict, "the machine is destroyed")
	}
	switch action {
	case "start":
		st.startMachine(m)
	case "stop":
		switch m.State {
		case cloud.MachineStopped:
		case cloud.MachineCreating, cloud.MachineStarting, cloud.MachineRestarting, cloud.MachineMigrating:
			e := perr(409, cloud.CodeBusy, "the machine is "+m.State)
			e.RetryAfter = 1
			panic(e)
		default:
			st.setMachineState(m, cloud.MachineStopped, reason)
		}
	case "restart", "reset":
		st.requireNodeUp(m)
		if m.State != cloud.MachineReady && m.State != cloud.MachineStopped && m.State != cloud.MachinePaused && m.State != cloud.MachineError {
			e := perr(409, cloud.CodeBusy, "the machine is "+m.State)
			e.RetryAfter = 1
			panic(e)
		}
		if !machineRunning(m.State) {
			prof := st.profiles[m.Profile]
			st.reserve(st.projects[m.Project], map[string]int{"running_vcpu": prof.VCPU, "running_memory_mib": prof.MemoryMiB})
		}
		m.EffectiveProfile = m.Profile
		st.setMachineState(m, cloud.MachineRestarting, reason)
		if action == "restart" && st.restartPolicy(m) == cloud.RestartKeepDisk {
			// The whole disk is kept (a cold boot).
			st.later(5*time.Millisecond, func() {
				if m.State == cloud.MachineRestarting {
					st.setMachineState(m, cloud.MachineReady, "")
				}
			})
			break
		}
		for k := range m.fs { // the template is recreated; only /workspace is carried over
			if !(k == "/workspace" || strings.HasPrefix(k, "/workspace/")) {
				delete(m.fs, k)
			}
		}
		base := newInstance(m.consumer)
		for k, v := range base.fs {
			if m.fs[k] == nil {
				m.fs[k] = v
			}
		}
		m.treeDigs = map[string]string{}
		st.later(5*time.Millisecond, func() {
			if m.State == cloud.MachineRestarting {
				st.setMachineState(m, cloud.MachineReady, "")
			}
		})
	case "migrate":
		st.requireNodeUp(m)
		p := st.projects[m.Project]
		prof := st.profiles[m.EffectiveProfile]
		var dst string
		if target != "" {
			n := st.nodes[target]
			if n == nil || n.pool != p.Pool {
				invalid("node", "invalid", "node %s is not in the project's pool", target)
			}
			if target == deref(m.Node) {
				invalid("node", "invalid", "the machine already runs on %s", target)
			}
			if !n.connected {
				fail(409, cloud.CodeNotAvailableOnNode, "node %s is not schedulable", target)
			}
			dst = target
		} else {
			var tpl *template
			for _, t := range st.allTemplates() {
				if t.ID == m.Template {
					tpl = t
				}
			}
			dst = st.place(p.Pool, prof, false, tpl, deref(m.Node))
		}
		var oldAddr *address
		for _, a := range st.addresses {
			if a.State == "active" && a.Machine != nil && *a.Machine == m.ID {
				oldAddr = a
			}
		}
		st.setMachineState(m, cloud.MachineMigrating, reason)
		m.Node = &dst
		if oldAddr != nil {
			st.releaseAddr(oldAddr, m)
			st.allocAddress(m, cloud.ChangeActor{Actor: "agent-cloud", Reason: "migrate"})
		}
		st.later(5*time.Millisecond, func() {
			if m.State == cloud.MachineMigrating {
				st.setMachineState(m, cloud.MachineReady, "")
			}
		})
	default:
		invalid("action", "invalid", "unknown action %s", action)
	}
}

func (st *state) requireNodeUp(m *machine) {
	if n := st.nodes[deref(m.Node)]; n != nil && !n.connected {
		e := perr(409, cloud.CodeNodeUnavailable, "the machine's node "+n.id+" is unavailable")
		e.RetryAfter = 30
		panic(e)
	}
}

func getMachineMetrics(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	if m.State != cloud.MachineReady {
		fail(409, cloud.CodeConflict, "the machine is %s", m.State)
	}
	pr := c.st.profiles[m.EffectiveProfile]
	used := 0
	for _, e := range m.fs {
		used += len(e.data)
	}
	c.json(200, &cloud.MachineMetrics{Machine: m.ID, CPUPercent: 1.5, MemoryUsedMiB: pr.MemoryMiB / 4, MemoryTotalMiB: pr.MemoryMiB,
		DiskUsedMiB: 512 + used>>20, DiskTotalMiB: pr.DiskMiB, SampledAt: c.s.now()})
}

// ---- terminals ----

func createTerminal(c *ctx) {
	var in cloud.TerminalCreate
	c.decode(&in)
	m := c.machine(c.r.PathValue("machine"))
	c.st.requireRunning(m)
	user := c.userParam("machine", in.User)
	t := c.st.openTerminal(m, in, user)
	out := t.Terminal
	c.json(201, &out)
}

func (st *state) openTerminal(m *machine, in cloud.TerminalCreate, user string) *terminal {
	if in.Rows == 0 {
		in.Rows = 24
	}
	if in.Cols == 0 {
		in.Cols = 80
	}
	if in.Rows < 1 || in.Rows > 500 || in.Cols < 1 || in.Cols > 1000 {
		invalid("rows", "out_of_range", "rows 1–500, cols 1–1000")
	}
	if in.IdleTimeoutSeconds == 0 {
		in.IdleTimeoutSeconds = 1800
	}
	if in.MaxSeconds == 0 {
		in.MaxSeconds = 28800
	}
	if in.IdleTimeoutSeconds < 30 || in.IdleTimeoutSeconds > 86400 || in.MaxSeconds < 60 || in.MaxSeconds > 86400 {
		invalid("idle_timeout_seconds", "out_of_range", "idle_timeout_seconds 30–86400, max_seconds 60–86400")
	}
	open := 0
	for _, t := range m.terminals {
		if t.State == "open" {
			open++
		}
	}
	if limit := st.profiles[m.EffectiveProfile].MaxTerminals; open >= limit {
		e := perr(409, cloud.CodeBusy, fmt.Sprintf("the machine already has %d open terminals", limit))
		e.RetryAfter = 5
		panic(e)
	}
	now := st.s.now()
	t := &terminal{consumer: m.consumer, notify: make(chan struct{}), lastActivity: now}
	t.Terminal = cloud.Terminal{ID: newID("trm"), Machine: m.ID, Actor: in.Actor, User: user, Rows: in.Rows, Cols: in.Cols, State: "open",
		IdleTimeoutSeconds: in.IdleTimeoutSeconds, MaxSeconds: in.MaxSeconds, CreatedAt: now}
	prompt := "$ "
	if user == "root" {
		prompt = "# "
	}
	t.buf = []byte(user + "@" + m.Hostname + ":~" + prompt)
	m.terminals[t.ID] = t
	st.terminals[t.ID] = t
	return t
}

func (st *state) closeTerminal(t *terminal, reason string, exit *int) {
	if t.State != "open" {
		return
	}
	now := st.s.now()
	t.State, t.CloseReason, t.ExitCode, t.ClosedAt = "closed", ptrStr(reason), exit, &now
	t.wake()
	m := st.machines[t.Machine]
	st.emit(t.consumer, m.Project, cloud.EventTerminalClosed, "terminal", t.ID,
		cloud.EventTerminalClosedData{Terminal: t.ID, Machine: t.Machine, Reason: reason, Actor: t.Actor})
}

func (c *ctx) terminal() (*machine, *terminal) {
	m := c.machine(c.r.PathValue("machine"))
	t := m.terminals[c.r.PathValue("terminal")]
	if t == nil {
		notFound("terminal")
	}
	return m, t
}

func listTerminals(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var items []cloud.Terminal
	for _, id := range sortedKeys(m.terminals) {
		if t := m.terminals[id]; t.State == "open" {
			items = append(items, t.Terminal)
		}
	}
	page := paginate(c, items)
	c.json(200, &page)
}

func getTerminal(c *ctx) {
	_, t := c.terminal()
	out := t.Terminal
	c.json(200, &out)
}

func closeTerminalH(c *ctx) {
	_, t := c.terminal()
	c.st.closeTerminal(t, "closed", nil)
	out := t.Terminal
	c.json(200, &out)
}

func terminalInput(c *ctx) {
	_, t := c.terminal()
	c.st.terminalInput(c, t)
}

func (st *state) terminalInput(c *ctx, t *terminal) {
	var in struct {
		DataB64 string `json:"data_b64"`
	}
	c.decode(&in)
	data, err := base64.StdEncoding.DecodeString(in.DataB64)
	if err != nil || len(data) > 64<<10 {
		invalid("data_b64", "invalid", "data_b64 is base64, at most 64 KiB")
	}
	if t.State != "open" {
		fail(410, cloud.CodeGone, "the terminal is closed")
	}
	t.lastActivity = st.s.now()
	// The mock PTY echoes input; "exit" followed by a newline ends the shell.
	echo := strings.ReplaceAll(string(data), "\r", "\r\n")
	t.buf = append(t.buf, echo...)
	t.wake()
	if strings.Contains(string(data), "exit\r") || strings.Contains(string(data), "exit\n") {
		zero := 0
		st.closeTerminal(t, "exit", &zero)
	}
	c.noContent()
}

func terminalResize(c *ctx) {
	_, t := c.terminal()
	c.st.terminalResize(c, t)
}

func (st *state) terminalResize(c *ctx, t *terminal) {
	var in struct {
		Rows int `json:"rows"`
		Cols int `json:"cols"`
	}
	c.decode(&in)
	if in.Rows < 1 || in.Rows > 500 || in.Cols < 1 || in.Cols > 1000 {
		invalid("rows", "out_of_range", "rows 1–500, cols 1–1000")
	}
	if t.State != "open" {
		fail(410, cloud.CodeGone, "the terminal is closed")
	}
	t.Rows, t.Cols = in.Rows, in.Cols
	out := t.Terminal
	c.json(200, &out)
}

func streamTerminal(c *ctx) {
	_, t := c.terminal()
	c.serveTerminalStream(t)
}

// serveTerminalStream writes the terminal's output as SSE from offset after until it closes.
func (c *ctx) serveTerminalStream(t *terminal) {
	after := int64(0)
	if v := c.query("after"); v != "" {
		fmt.Sscan(v, &after)
	} else if v := c.r.Header.Get("Last-Event-ID"); v != "" {
		fmt.Sscan(v, &after)
	}
	if t.State != "open" && after >= int64(len(t.buf)) {
		fail(410, cloud.CodeGone, "the terminal is closed")
	}
	h := c.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	c.w.WriteHeader(http.StatusOK)
	flusher, _ := c.w.(http.Flusher)
	off := after
	for {
		if off < int64(len(t.buf)) {
			chunk := t.buf[off:]
			b, _ := json.Marshal(map[string]any{"offset": off, "data_b64": base64.StdEncoding.EncodeToString(chunk)})
			off = int64(len(t.buf))
			if _, err := fmt.Fprintf(c.w, "id: %d\nevent: output\ndata: %s\n\n", off, b); err != nil {
				return
			}
		}
		if t.State != "open" {
			b, _ := json.Marshal(map[string]any{"reason": deref(t.CloseReason), "exit_code": t.ExitCode})
			fmt.Fprintf(c.w, "event: closed\ndata: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		wait := t.notify
		c.unlock()
		select {
		case <-wait:
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
