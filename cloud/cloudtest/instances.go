package cloudtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// ---- the instance file system ----

func isRootUser(u string) bool { return u == "root" }

func otherCan(mode string, bit int) bool {
	if mode == "" {
		return false
	}
	d := mode[len(mode)-1] - '0'
	return int(d)&bit != 0
}

func (in *instance) underTree(p string) bool {
	for root := range in.treeDigs {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

func writableArea(p string) bool {
	for _, a := range []string{"/workspace", "/home/agent", "/tmp"} {
		if p == a || strings.HasPrefix(p, a+"/") {
			return true
		}
	}
	return false
}

// readFor returns a file's content as user would read it, or an error message.
func (in *instance) readFor(p, user string) ([]byte, string) {
	e := in.fs[path.Clean(p)]
	if e == nil {
		return nil, "No such file or directory"
	}
	if e.dir {
		return nil, "Is a directory"
	}
	if !isRootUser(user) && e.owner == "root" && !otherCan(e.mode, 4) {
		return nil, "Permission denied"
	}
	return e.data, ""
}

// writeFor writes a file as user, or returns an error message.
func (in *instance) writeFor(p string, data []byte, user string) string {
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		return "path must be absolute"
	}
	if e := in.fs[p]; e != nil && e.dir {
		return "Is a directory"
	}
	if !isRootUser(user) {
		if !writableArea(p) || in.underTree(p) {
			return "Permission denied"
		}
		if e := in.fs[p]; e != nil && e.owner == "root" {
			return "Permission denied"
		}
	} else if in.underTree(p) {
		return "Read-only file system"
	}
	owner := "agent"
	if isRootUser(user) {
		owner = "root"
	}
	mode := "0644"
	if e := in.fs[p]; e != nil {
		mode = e.mode
	}
	in.fs[p] = &fsEntry{data: append([]byte(nil), data...), mode: mode, owner: owner, mtime: time.Now().UTC()}
	return ""
}

func (in *instance) isDir(p string) bool {
	if e := in.fs[p]; e != nil {
		return e.dir
	}
	prefix := strings.TrimSuffix(p, "/") + "/"
	for k := range in.fs {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return p == "/"
}

func (in *instance) list(dir string) []cloud.FileEntry {
	dir = path.Clean(dir)
	seen := map[string]cloud.FileEntry{}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for k, e := range in.fs {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		name, deeper, _ := strings.Cut(rest, "/")
		full := prefix + name
		if deeper != "" {
			if _, ok := seen[name]; !ok {
				seen[name] = cloud.FileEntry{Name: name, Path: full, Type: "dir", Mode: "0755", Owner: "root", ModifiedAt: e.mtime}
			}
			continue
		}
		fe := cloud.FileEntry{Name: name, Path: full, Type: "file", Size: int64(len(e.data)), Mode: e.mode, Owner: e.owner, ModifiedAt: e.mtime}
		if e.dir {
			fe.Type, fe.Size = "dir", 0
		}
		if e.symlink != "" {
			fe.Type, fe.Target = "symlink", e.symlink
		}
		seen[name] = fe
	}
	out := make([]cloud.FileEntry, 0, len(seen))
	for _, n := range sortedKeys(seen) {
		out = append(out, seen[n])
	}
	return out
}

// ---- targets (a sandbox or a machine) ----

type target struct {
	kind, id, project, profile, hostname string
	inst                                 *instance
	m                                    *machine
	sb                                   *sandbox
}

// target resolves the {sandbox} or {machine} of the path for the calling consumer and requires
// it to be running (a paused machine is resumed on access, as on a real installation).
func (c *ctx) target(kind string) target {
	if kind == "sandbox" {
		sb := c.sandbox(c.r.PathValue("sandbox"))
		if sb.job != nil {
			notFound("sandbox") // a job's sandbox is reached through the job
		}
		if sb.State != "ready" {
			fail(409, cloud.CodeConflict, "the sandbox is %s", sb.State)
		}
		return target{kind: kind, id: sb.ID, project: sb.Project, profile: sb.Profile, hostname: "sandbox", inst: &sb.instance, sb: sb}
	}
	m := c.machine(c.r.PathValue("machine"))
	c.st.requireRunning(m)
	return target{kind: kind, id: m.ID, project: m.Project, profile: m.EffectiveProfile, hostname: m.Hostname, inst: &m.instance, m: m}
}

func (st *state) requireRunning(m *machine) {
	if m.Node != nil {
		if n := st.nodes[*m.Node]; n != nil && !n.connected {
			fail(409, cloud.CodeNodeUnavailable, "the machine's node %s is unavailable", *m.Node)
		}
	}
	switch m.State {
	case cloud.MachineReady:
	case cloud.MachinePaused:
		st.setMachineState(m, cloud.MachineReady, "resumed")
	case cloud.MachineCreating, cloud.MachineStarting, cloud.MachineRestarting, cloud.MachineMigrating:
		e := perr(409, cloud.CodeBusy, "the machine is "+m.State)
		e.RetryAfter = 1
		panic(e)
	default:
		fail(409, cloud.CodeConflict, "the machine is %s", m.State)
	}
}

func (c *ctx) userParam(kind, user string) string {
	switch user {
	case "", "agent":
		return "agent"
	case "root":
		if kind == "machine" && !c.key.hasScope(string(cloud.ScopeMachinesRoot)) {
			e := perr(403, cloud.CodeScopeMissing, "user root needs the machines:root scope")
			e.Scope = string(cloud.ScopeMachinesRoot)
			panic(e)
		}
		return "root"
	}
	invalid("user", "invalid", "user is agent or root")
	return ""
}

// ---- execs ----

func execCreate(kind string) handler {
	return func(c *ctx) {
		var in cloud.ExecRequest
		c.decode(&in)
		t := c.target(kind)
		user := c.userParam(kind, in.User)
		if (len(in.Argv) == 0) == (in.Shell == "") {
			invalid("argv", "required", "exactly one of argv or shell")
		}
		if in.TimeoutSeconds == 0 {
			in.TimeoutSeconds = 60
		}
		if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 86400 || (!in.Async && in.TimeoutSeconds > 300) {
			invalid("timeout_seconds", "out_of_range", "timeout_seconds is 1–300 (1–86400 with async)")
		}
		if in.OutputCapBytes == 0 {
			in.OutputCapBytes = 1 << 20
		}
		if in.OutputCapBytes < 1 || in.OutputCapBytes > 16<<20 {
			invalid("output_cap_bytes", "out_of_range", "output_cap_bytes is 1 to 16 MiB")
		}
		if len(in.Stdin) > 2<<20 {
			invalid("stdin_b64", "too_long", "stdin is at most 2 MiB")
		}
		limit := c.st.profiles[t.profile].MaxConcurrentExecs
		running := 0
		for _, e := range t.inst.execs {
			if e.State == "running" {
				running++
			}
		}
		if running >= limit {
			e := perr(409, cloud.CodeBusy, "the "+kind+" already runs "+strconv.Itoa(limit)+" execs")
			e.RetryAfter = 1
			panic(e)
		}
		now := c.s.now()
		ex := &execState{out: newJournal(), cancel: make(chan struct{})}
		ex.Exec = cloud.Exec{ID: newID("exe"), Argv: in.Argv, Shell: in.Shell, User: user, Cwd: in.Cwd, State: "running", Actor: in.Actor, StartedAt: now}
		ex.Target.Kind, ex.Target.ID = kind, t.id
		t.inst.execs[ex.ID] = ex
		t.inst.order = append(t.inst.order, ex.ID)
		pe := &procEnv{stdin: in.Stdin, env: in.Env, user: user, readFile: t.inst.readFor, write: t.inst.writeFor, hostname: t.hostname}
		capBytes := in.OutputCapBytes
		c.st.runProgram(parseProgram(in.Argv, in.Shell), pe, ex.cancel, time.Now().Add(time.Duration(in.TimeoutSeconds)*time.Second),
			func(r step) bool {
				if ex.State != "running" {
					return true
				}
				for _, s := range []struct {
					b   []byte
					dst *[]byte
				}{{r.stdout, &ex.out.stdout}, {r.stderr, &ex.out.stderr}} {
					room := capBytes - len(*s.dst)
					b := s.b
					if len(b) > room {
						b, ex.Truncated = b[:room], true
					}
					*s.dst = append(*s.dst, b...)
				}
				ex.StdoutBytes, ex.StderrBytes = int64(len(ex.out.stdout)), int64(len(ex.out.stderr))
				ex.out.wake()
				return false
			},
			func(exit int, reason string) {
				switch {
				case ex.State != "running":
				case reason != "":
					c.st.finishExec(ex, cloud.OutcomeKilled, reason, nil)
				case exit == 0:
					c.st.finishExec(ex, cloud.OutcomeSucceeded, "", &exit)
				default:
					c.st.finishExec(ex, cloud.OutcomeFailed, "", &exit)
				}
			})
		if in.Async {
			out := ex.Exec
			c.json(202, &out)
			return
		}
		for ex.State == "running" {
			wait := ex.out.notify
			c.unlock()
			select {
			case <-wait:
			case <-c.r.Context().Done():
			case <-c.s.closed:
			}
			c.lock()
			if c.r.Context().Err() != nil {
				return
			}
		}
		out := c.st.renderExec(ex)
		c.json(200, &out)
	}
}

func (st *state) finishExec(ex *execState, outcome, reason string, exit *int) {
	if ex.State != "running" {
		return
	}
	now := st.s.now()
	ex.State, ex.Outcome, ex.ExitCode, ex.ExitedAt = "exited", &outcome, exit, &now
	if reason != "" {
		ex.OutcomeReason = &reason
	}
	ex.out.done = true
	ex.out.retainedUntil = ptrTime(now.Add(outputRetention))
	select {
	case <-ex.cancel:
	default:
		close(ex.cancel)
	}
	ex.out.wake()
}

func (st *state) killExecs(in *instance, reason string) {
	for _, id := range in.order {
		st.finishExec(in.execs[id], cloud.OutcomeKilled, reason, nil)
	}
}

func (st *state) renderExec(ex *execState) cloud.Exec {
	out := ex.Exec
	if ex.State == "exited" && !ex.out.expired {
		out.Stdout, out.Stderr = ex.out.stdout, ex.out.stderr
		if out.Stdout == nil {
			out.Stdout = []byte{}
		}
	}
	return out
}

func (c *ctx) exec(kind string) (target, *execState) {
	var inst *instance
	var t target
	if kind == "sandbox" {
		sb := c.sandbox(c.r.PathValue("sandbox"))
		inst, t = &sb.instance, target{kind: kind, id: sb.ID, inst: &sb.instance, sb: sb}
	} else {
		m := c.machine(c.r.PathValue("machine"))
		inst, t = &m.instance, target{kind: kind, id: m.ID, inst: &m.instance, m: m}
	}
	ex := inst.execs[c.r.PathValue("exec")]
	if ex == nil {
		notFound("exec")
	}
	return t, ex
}

func execList(kind string) handler {
	return func(c *ctx) {
		var inst *instance
		if kind == "sandbox" {
			inst = &c.sandbox(c.r.PathValue("sandbox")).instance
		} else {
			inst = &c.machine(c.r.PathValue("machine")).instance
		}
		states := c.r.URL.Query()["state"]
		now := c.s.now()
		var items []cloud.Exec
		for i := len(inst.order) - 1; i >= 0; i-- {
			ex := inst.execs[inst.order[i]]
			if ex.ExitedAt != nil && now.Sub(*ex.ExitedAt) > time.Hour {
				continue
			}
			if stateMatch(ex.State, states) {
				e := ex.Exec // the list omits output
				items = append(items, e)
			}
		}
		page := paginate(c, items)
		c.json(200, &page)
	}
}

func execGet(kind string) handler {
	return func(c *ctx) {
		_, ex := c.exec(kind)
		out := c.st.renderExec(ex)
		c.json(200, &out)
	}
}

func execOutput(kind string) handler {
	return func(c *ctx) {
		_, ex := c.exec(kind)
		if ex.out.retainedUntil != nil && c.s.now().After(*ex.out.retainedUntil) {
			ex.out.expired = true
		}
		c.streamOutput(ex.out)
	}
}

func execCancel(kind string) handler {
	return func(c *ctx) {
		_, ex := c.exec(kind)
		c.st.finishExec(ex, cloud.OutcomeKilled, "cancel", nil)
		out := c.st.renderExec(ex)
		c.json(202, &out)
	}
}

// ---- files ----

func (c *ctx) filePath() string {
	p := c.query("path")
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") {
		invalid("path", "invalid", "path must be absolute")
	}
	return path.Clean(p)
}

func filesList(kind string) handler {
	return func(c *ctx) {
		t := c.target(kind)
		c.userParam(kind, c.query("user"))
		p := c.filePath()
		if !t.inst.isDir(p) {
			if t.inst.fs[p] != nil {
				fail(409, cloud.CodeConflict, "%s is not a directory", p)
			}
			notFound(p)
		}
		c.json(200, &cloud.FileList{Path: p, Entries: t.inst.list(p)})
	}
}

func filesDelete(kind string) handler {
	return func(c *ctx) {
		t := c.target(kind)
		user := c.userParam(kind, c.query("user"))
		p := c.filePath()
		recursive := c.queryBool("recursive")
		if t.inst.underTree(p) || (!isRootUser(user) && !writableArea(p)) {
			fail(403, cloud.CodeForbidden, "permission denied: %s", p)
		}
		if p == "/workspace" || p == "/home/agent" || p == "/tmp" {
			fail(403, cloud.CodeForbidden, "permission denied: %s", p)
		}
		if t.inst.isDir(p) {
			if !recursive {
				fail(409, cloud.CodeConflict, "%s is a directory (use recursive=true)", p)
			}
			for k := range t.inst.fs {
				if k == p || strings.HasPrefix(k, p+"/") {
					delete(t.inst.fs, k)
				}
			}
		} else if t.inst.fs[p] == nil {
			notFound(p)
		} else {
			delete(t.inst.fs, p)
		}
		c.noContent()
	}
}

func filesRead(kind string) handler {
	return func(c *ctx) {
		t := c.target(kind)
		user := c.userParam(kind, c.query("user"))
		p := c.filePath()
		e := t.inst.fs[p]
		if e == nil {
			if t.inst.isDir(p) {
				fail(409, cloud.CodeConflict, "%s is a directory", p)
			}
			notFound(p)
		}
		data, msg := t.inst.readFor(p, user)
		if msg != "" {
			if msg == "Permission denied" {
				fail(403, cloud.CodeForbidden, "permission denied: %s", p)
			}
			fail(409, cloud.CodeConflict, "%s: %s", p, msg)
		}
		c.w.Header().Set("Content-Type", "application/octet-stream")
		c.w.Header().Set("Cloud-File-Mode", e.mode)
		c.w.WriteHeader(200)
		_, _ = c.w.Write(data)
	}
}

func filesWrite(kind string) handler {
	return func(c *ctx) {
		t := c.target(kind)
		user := c.userParam(kind, c.query("user"))
		p := c.filePath()
		mode := c.query("mode")
		if mode == "" {
			mode = "0644"
		}
		if !modeRE.MatchString(mode) {
			invalid("mode", "invalid", "mode is octal, e.g. 0644")
		}
		data, err := io.ReadAll(io.LimitReader(c.r.Body, 64<<20+1))
		if err != nil {
			fail(400, cloud.CodeInvalidRequest, "read body: %v", err)
		}
		if len(data) > 64<<20 {
			invalid("body", "too_long", "files are at most 64 MiB")
		}
		if msg := t.inst.writeFor(p, data, user); msg != "" {
			if msg == "Is a directory" {
				fail(409, cloud.CodeConflict, "%s is a directory", p)
			}
			fail(403, cloud.CodeForbidden, "%s: %s", p, msg)
		}
		e := t.inst.fs[p]
		e.mode = mode
		c.json(200, &cloud.FileEntry{Name: path.Base(p), Path: p, Type: "file", Size: int64(len(e.data)), Mode: e.mode, Owner: e.owner, ModifiedAt: e.mtime})
	}
}

func filesTree(kind string) handler {
	return func(c *ctx) {
		var in cloud.FileTree
		c.decode(&in)
		t := c.target(kind)
		root := path.Clean(in.Root)
		if !strings.HasPrefix(in.Root, "/") || root == "/" {
			invalid("root", "invalid", "root must be an absolute directory other than /")
		}
		for _, bad := range []string{"/workspace", "/home", "/tmp"} {
			if root == bad || strings.HasPrefix(root, bad+"/") {
				invalid("root", "not_allowed", "root must not be under /workspace, /home or /tmp")
			}
		}
		if len(in.Files) > 4096 {
			invalid("files", "too_many", "at most 4096 files")
		}
		total := 0
		type ent struct {
			p, mode, link string
			data          []byte
		}
		var ents []ent
		for i, f := range in.Files {
			fld := "files[" + strconv.Itoa(i) + "]"
			rel := path.Clean(f.Path)
			if f.Path == "" || strings.HasPrefix(f.Path, "/") || rel == ".." || strings.HasPrefix(rel, "../") || rel == "." {
				invalid(fld+".path", "invalid", "paths are relative to root, without ..")
			}
			mode := f.Mode
			if mode == "" {
				mode = "0444"
			}
			if !modeRE.MatchString(mode) {
				invalid(fld+".mode", "invalid", "mode is octal")
			}
			n, _ := strconv.ParseUint(mode, 8, 32)
			mode = "0" + strconv.FormatUint(n&^0o222, 8) // write bits removed
			if len(mode) < 4 {
				mode = strings.Repeat("0", 4-len(mode)) + mode
			}
			if f.Symlink != "" && len(f.Content) > 0 {
				invalid(fld, "invalid", "a file has content or symlink, not both")
			}
			total += len(f.Content)
			ents = append(ents, ent{p: root + "/" + rel, mode: mode, link: f.Symlink, data: f.Content})
		}
		if total > 32<<20 {
			invalid("files", "too_long", "a tree is at most 32 MiB")
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].p < ents[j].p })
		h := sha256.New()
		for _, e := range ents {
			h.Write([]byte(e.p + "\x00" + e.mode + "\x00" + e.link + "\x00"))
			h.Write(e.data)
			h.Write([]byte{0})
		}
		digest := hex.EncodeToString(h.Sum(nil))
		if im := c.r.Header.Get("If-Match"); im != "" && im != strconv.Quote(t.inst.treeDigs[root]) {
			fail(412, cloud.CodePreconditionFailed, "If-Match does not match the tree's current digest")
		}
		changed := t.inst.treeDigs[root] != digest
		if changed {
			for k := range t.inst.fs {
				if k == root || strings.HasPrefix(k, root+"/") {
					delete(t.inst.fs, k)
				}
			}
			now := time.Now().UTC()
			t.inst.fs[root] = &fsEntry{dir: true, mode: "0555", owner: "root", mtime: now}
			for _, e := range ents {
				t.inst.fs[e.p] = &fsEntry{data: e.data, mode: e.mode, owner: "root", symlink: e.link, mtime: now}
			}
			t.inst.treeDigs[root] = digest
		}
		c.w.Header().Set("ETag", strconv.Quote(digest))
		c.json(200, &cloud.FileTreeResult{Root: root, Digest: digest, Files: len(ents), Bytes: int64(total), Changed: changed})
	}
}

func filesArchive(kind string) handler {
	return func(c *ctx) {
		var in cloud.ArchiveRequest
		c.decode(&in)
		t := c.target(kind)
		user := c.userParam(kind, in.User)
		if in.Format != "" && in.Format != "tar.gz" {
			invalid("format", "invalid", "format is tar.gz")
		}
		if !strings.HasPrefix(in.Path, "/") {
			invalid("path", "invalid", "path must be absolute")
		}
		dir := path.Clean(in.Path)
		if !t.inst.isDir(dir) {
			notFound(dir)
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		prefix := strings.TrimSuffix(dir, "/") + "/"
		for _, k := range sortedKeys(t.inst.fs) {
			e := t.inst.fs[k]
			if !strings.HasPrefix(k, prefix) || e.dir {
				continue
			}
			data, msg := t.inst.readFor(k, user)
			if msg != "" {
				continue
			}
			mode, _ := strconv.ParseInt(e.mode, 8, 64)
			_ = tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(k, prefix), Mode: mode, Size: int64(len(data)), ModTime: e.mtime, Typeflag: tar.TypeReg})
			_, _ = tw.Write(data)
		}
		_ = tw.Close()
		_ = gz.Close()
		c.w.Header().Set("Content-Type", "application/gzip")
		c.w.WriteHeader(http.StatusOK)
		_, _ = c.w.Write(buf.Bytes())
	}
}
