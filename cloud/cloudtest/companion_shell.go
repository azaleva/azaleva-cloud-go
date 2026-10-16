package cloudtest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Processes (/execute) and terminals (/api/terminals) of the fake agent-companion. Both run a
// small shell (acShell) on a pseudo-terminal model (acPTY): what a consumer sends is echoed,
// "\r" ends a line, output lines end in "\r\n", ^C interrupts and ^D on an empty line is
// end of input, as on agent-companion's PTYs. The shell knows the common builtins and file
// commands (echo, printf, pwd, cd, cat, read, sleep, exit, ls, mkdir, touch, rm, env, …),
// quoting, $VAR, $? and $((arithmetic)), ";", "&&", "||" and "> file"; any other command
// is "not found", as a real shell would answer it.

// ---- the pseudo-terminal ----

type acPTY struct {
	// signals: ^C interrupts (a terminal's bash has job control; a process's sh has no
	// controlling terminal, so there ^C is only echoed, as with agent-companion).
	signals bool
	mu      sync.Mutex
	cond    *sync.Cond
	line    []byte
	lines   []string
	eof     int
	intr    bool
	closed  bool
	out     func([]byte)
	rows    int
	cols    int
}

func newACPTY(out func([]byte)) *acPTY {
	p := &acPTY{out: out, rows: 24, cols: 80}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// write is program output (ONLCR: "\n" becomes "\r\n").
func (p *acPTY) write(b []byte) {
	if len(b) == 0 {
		return
	}
	var o bytes.Buffer
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			o.WriteByte('\r')
		}
		o.WriteByte(c)
	}
	p.out(o.Bytes())
}

// input is what the caller types (canonical mode with echo).
func (p *acPTY) input(data []byte) {
	p.mu.Lock()
	var echo bytes.Buffer
	for _, c := range data {
		if c == '\r' {
			c = '\n'
		}
		switch c {
		case 0x03:
			echo.WriteString("^C")
			if p.signals {
				p.line, p.intr = nil, true
			} else {
				p.line = append(p.line, c)
			}
		case 0x04:
			if len(p.line) == 0 {
				p.eof++
			} else {
				p.lines, p.line = append(p.lines, string(p.line)), nil
			}
		case 0x7f, 0x08:
			if n := len(p.line); n > 0 {
				i := n - 1
				for i > 0 && p.line[i]&0xC0 == 0x80 {
					i--
				}
				p.line = p.line[:i]
				echo.WriteString("\b \b")
			}
		case '\n':
			echo.WriteString("\r\n")
			p.lines, p.line = append(p.lines, string(p.line)+"\n"), nil
		default:
			p.line = append(p.line, c)
			echo.WriteByte(c)
		}
	}
	if echo.Len() > 0 { // the echo comes before anything the program prints in answer
		p.out(echo.Bytes())
	}
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *acPTY) resize(rows, cols int) {
	p.mu.Lock()
	p.rows, p.cols = rows, cols
	p.mu.Unlock()
}

func (p *acPTY) close() {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

// takeIntr reports (and clears) a pending ^C.
func (p *acPTY) takeIntr() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.intr
	p.intr = false
	return i
}

// readLine waits for a line ("" and eof at end of input; intr after ^C or a kill).
func (p *acPTY) readLine() (line string, eof, intr bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		switch {
		case p.closed:
			return "", true, true
		case p.intr:
			p.intr = false
			return "", false, true
		case len(p.lines) > 0:
			line, p.lines = p.lines[0], p.lines[1:]
			return line, false, false
		case p.eof > 0:
			p.eof--
			return "", true, false
		}
		p.cond.Wait()
	}
}

// sleep waits d unless interrupted (true) or the PTY is closed.
func (p *acPTY) sleep(d time.Duration) (intr bool) {
	t := time.AfterFunc(d, func() { p.mu.Lock(); p.cond.Broadcast(); p.mu.Unlock() })
	defer t.Stop()
	end := time.Now().Add(d)
	p.mu.Lock()
	defer p.mu.Unlock()
	for time.Now().Before(end) {
		if p.closed || p.intr {
			p.intr = false
			return true
		}
		p.cond.Wait()
	}
	return false
}

// ---- processes ----

type acProc struct {
	id, command, logPath string
	owner                acOwner
	pid                  int
	pty                  *acPTY

	mu       sync.Mutex
	output   []string
	status   string
	exitCode *int
	finished time.Time
	killSig  int
	done     chan struct{}
}

func (p *acProc) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitCode == nil
}

func (p *acProc) info() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	var code any
	if p.exitCode != nil {
		code = *p.exitCode
	}
	return map[string]any{"id": p.id, "command": p.command, "status": p.status, "exit_code": code, "log_path": p.logPath}
}

func (p *acProc) wait(d time.Duration) {
	select {
	case <-p.done:
	case <-time.After(d):
	}
}

func (s *acServer) newPID() int {
	s.nextPID += 7
	return 1000 + s.nextPID
}

func (s *acServer) env(cwd string) map[string]string {
	return map[string]string{"HOME": acUserHome, "USER": "agent", "LOGNAME": "agent", "SHELL": "/bin/bash", "PWD": cwd,
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "AGENT_COMPANION_API_KEY": s.key,
		"AGENT_COMPANION_CORS_ALLOWED_ORIGINS": "*"}
}

func (s *acServer) processes(owner acOwner, p, method string, q acQuery, b map[string]any) (any, error) {
	s.mu.Lock()
	kept := s.procs[:0]
	for _, pr := range s.procs { // finished processes are forgotten after five minutes
		pr.mu.Lock()
		old := pr.exitCode != nil && time.Since(pr.finished) > 5*time.Minute
		pr.mu.Unlock()
		if !old {
			kept = append(kept, pr)
		}
	}
	s.procs = kept
	if p == "/execute" && method == http.MethodGet {
		out := []any{}
		for _, pr := range s.procs {
			if pr.owner == owner {
				out = append(out, pr.info())
			}
		}
		s.mu.Unlock()
		return out, nil
	}
	var pr *acProc
	if p == "/execute" {
		cwd := s.cwd(owner)
		if c := acText(b, "cwd"); c != "" {
			cwd = s.fs.resolve(c, cwd)
		}
		env := s.env(cwd)
		if m, ok := b["env"].(map[string]any); ok {
			for k, v := range m {
				if v, ok := v.(string); ok {
					env[k] = v
				}
			}
		}
		id := time.Now().Format("20060102-150405") + "-" + randHex(3)
		pr = &acProc{id: id, command: acText(b, "command"), owner: owner, pid: s.newPID(), status: "running",
			logPath: acLogDir + "/processes/" + id + ".jsonl", done: make(chan struct{})}
		pr.pty = newACPTY(func(out []byte) {
			pr.mu.Lock()
			pr.output = append(pr.output, string(out))
			pr.mu.Unlock()
		})
		s.procs = append(s.procs, pr)
		sh := &acShell{s: s, pty: pr.pty, cwd: cwd, vars: env, pid: pr.pid}
		go func() {
			code := sh.run(pr.command)
			pr.mu.Lock()
			if pr.killSig != 0 {
				code = -pr.killSig
			}
			pr.exitCode, pr.finished = &code, time.Now()
			if pr.status != "killed" {
				pr.status = "done"
			}
			pr.mu.Unlock()
			pr.pty.close()
			close(pr.done)
		}()
	} else {
		id := strings.Split(p, "/")[2]
		for _, x := range s.procs {
			if x.id == id && x.owner == owner {
				pr = x
			}
		}
	}
	s.mu.Unlock()
	if pr == nil {
		return nil, acDetail(404, "Process not found")
	}
	if method == http.MethodDelete {
		if pr.running() {
			pr.mu.Lock()
			pr.status, pr.killSig = "killed", 15
			if q.flag("force", false) {
				pr.killSig = 9
			}
			pr.mu.Unlock()
			pr.pty.close()
			pr.wait(300 * time.Second)
		}
		return map[string]any{"status": "killed"}, nil
	}
	if strings.HasSuffix(p, "/input") {
		if !pr.running() {
			return nil, acDetail(400, "Process has already exited")
		}
		pr.pty.input([]byte(acUnescape(acText(b, "input"))))
		return map[string]any{"status": "ok"}, nil
	}
	if w := q.num("wait", 0); w > 0 {
		pr.wait(time.Duration(w * float64(time.Second)))
	}
	v := pr.info()
	pr.mu.Lock()
	entries := pr.output
	pr.mu.Unlock()
	offset := int(q.num("offset", 0))
	out := []any{}
	for i := offset; i < len(entries); i++ {
		out = append(out, map[string]string{"type": "output", "data": entries[i]})
	}
	available := len(out)
	if t, ok := q.get("tail"); ok {
		if n, err := strconv.Atoi(t); err == nil && n >= 0 && len(out) > n {
			out = out[len(out)-n:]
		}
	}
	v["output"], v["next_offset"], v["truncated"] = out, len(entries), available > len(out)
	return v, nil
}

// acUnescape reads backslash escapes in process input (\n, \t, \x1b, \u…, octal), as
// agent-companion does.
func acUnescape(s string) string {
	var out strings.Builder
	r := []rune(s)
	for i := 0; i < len(r); i++ {
		if r[i] != '\\' {
			out.WriteRune(r[i])
			continue
		}
		i++
		if i >= len(r) {
			out.WriteByte('\\')
			break
		}
		switch c := r[i]; c {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case 'a':
			out.WriteByte('\a')
		case 'v':
			out.WriteByte('\v')
		case '\\', '\'', '"':
			out.WriteRune(c)
		case 'x', 'u', 'U':
			n := map[rune]int{'x': 2, 'u': 4, 'U': 8}[c]
			end := min(i+1+n, len(r))
			if v, err := strconv.ParseUint(string(r[i+1:end]), 16, 32); err == nil {
				out.WriteRune(rune(v))
			}
			i = end - 1
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i + 1
			for j < len(r) && j < i+3 && r[j] >= '0' && r[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint(string(r[i:j]), 8, 32)
			out.WriteRune(rune(v))
			i = j - 1
		default:
			out.WriteByte('\\')
			out.WriteRune(c)
		}
	}
	return out.String()
}

// ---- terminals ----

type acTerm struct {
	id, created string
	owner       acOwner
	pid         int
	pty         *acPTY

	mu        sync.Mutex
	connected bool
	pending   [][]byte // output before the WebSocket connected (the PTY's buffer)
	ring      []byte   // the last 64 KiB of output since it connected
	sink      chan []byte
	lagged    chan struct{}
	exited    bool
	stopped   bool
}

func (t *acTerm) running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.exited && !t.stopped
}

func (t *acTerm) info() map[string]any {
	return map[string]any{"id": t.id, "created_at": t.created, "pid": t.pid}
}

func (t *acTerm) emit(b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.connected {
		t.pending = append(t.pending, bytes.Clone(b))
		return
	}
	t.ring = append(t.ring, b...)
	if n := len(t.ring) - 65536; n > 0 {
		t.ring = t.ring[n:]
	}
	select {
	case t.sink <- bytes.Clone(b):
	default:
		select {
		case <-t.lagged:
		default:
			close(t.lagged)
		}
	}
}

func (s *acServer) destroy(t *acTerm) {
	s.mu.Lock()
	s.terms = slicesDeleteFunc(s.terms, func(x *acTerm) bool { return x == t })
	s.mu.Unlock()
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
	t.pty.close()
}

func slicesDeleteFunc[T any](s []T, del func(T) bool) []T {
	out := s[:0]
	for _, x := range s {
		if !del(x) {
			out = append(out, x)
		}
	}
	return out
}

func (s *acServer) prompt(cwd string) string {
	if cwd == acUserHome || strings.HasPrefix(cwd, acUserHome+"/") {
		cwd = "~" + strings.TrimPrefix(cwd, acUserHome)
	}
	return "agent@" + acHostname + ":" + cwd + "$ "
}

func (s *acServer) terminals(owner acOwner, p, method string, b map[string]any) (any, error) {
	s.mu.Lock()
	running := s.terms[:0]
	for _, t := range s.terms {
		if t.running() {
			running = append(running, t)
		}
	}
	s.terms = running
	if p == "/api/terminals" {
		defer s.mu.Unlock()
		if method == http.MethodGet {
			out := []any{}
			for _, t := range s.terms {
				if t.owner == owner {
					out = append(out, t.info())
				}
			}
			return out, nil
		}
		if len(s.terms) >= acMaxTerms {
			return nil, acTermErr(429, fmt.Sprintf("Maximum number of terminal sessions (%d) reached", acMaxTerms))
		}
		t := &acTerm{id: randHex(4), created: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), owner: owner,
			pid: s.newPID(), sink: make(chan []byte, 1024), lagged: make(chan struct{})}
		t.pty = newACPTY(t.emit)
		t.pty.signals = true
		cwd := s.cwd(owner)
		s.terms = append(s.terms, t)
		sh := &acShell{s: s, pty: t.pty, cwd: cwd, vars: s.env(cwd), pid: t.pid, interactive: true}
		sh.vars["TERM"] = "xterm-256color"
		go func() {
			sh.interact()
			t.mu.Lock()
			t.exited = true
			t.mu.Unlock()
		}()
		return t.info(), nil
	}
	if strings.HasPrefix(p, "/api/terminals/user/") {
		var t *acTerm
		for i := len(s.terms) - 1; i >= 0; i-- {
			x := s.terms[i]
			x.mu.Lock()
			ok := x.owner == owner && x.connected
			x.mu.Unlock()
			if ok {
				t = x
				break
			}
		}
		s.mu.Unlock()
		if t == nil {
			return nil, acDetail(404, "No connected user shell")
		}
		if strings.HasSuffix(p, "/output") {
			t.mu.Lock()
			defer t.mu.Unlock()
			return map[string]any{"output": strings.ToValidUTF8(string(t.ring), "�")}, nil
		}
		t.pty.input([]byte(acText(b, "input")))
		return map[string]any{"status": "ok"}, nil
	}
	id := strings.TrimPrefix(p, "/api/terminals/")
	var t *acTerm
	for _, x := range s.terms {
		if x.id == id && x.owner == owner {
			t = x
		}
	}
	s.mu.Unlock()
	if t == nil {
		return nil, acTermErr(404, "Session not found")
	}
	if method == http.MethodDelete {
		s.destroy(t)
		return map[string]any{"status": "deleted"}, nil
	}
	return t.info(), nil
}

// terminalSocket is agent-companion's terminal WebSocket: the upgrade is always accepted; an
// unknown or ended terminal closes 4004; the first message must be a text message
// {"type":"auth","token":<key>} within 10 s (else 4001); a terminal of another owner closes
// 4004, a second connection 4009. Then binary frames are input, text frames resize messages
// ({"type":"resize","rows","cols"}), and output comes in binary frames, starting with what the
// terminal printed before the connection. The terminal ends with its WebSocket.
func (s *acServer) terminalSocket(w http.ResponseWriter, r *http.Request, owner acOwner, id string, hasSession bool) error {
	switch {
	case !headerHasToken(r.Header, "Connection", "upgrade"):
		return acDetail(400, "Connection header did not include 'upgrade'")
	case r.Header.Get("Sec-WebSocket-Version") != "13":
		return acDetail(400, "`Sec-WebSocket-Version` header did not include '13'")
	case r.Header.Get("Sec-WebSocket-Key") == "":
		return acDetail(400, "`Sec-WebSocket-Key` header missing")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return acDetail(500, "no hijack")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil
	}
	defer conn.Close()
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: " +
		WebSocketAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"); err != nil || rw.Flush() != nil {
		return nil
	}
	closeWith := func(code uint16, reason string) {
		_ = WriteWebSocketFrame(conn, true, 0x8, append(binary.BigEndian.AppendUint16(nil, code), reason...), false)
	}
	s.mu.Lock()
	var t *acTerm
	for _, x := range s.terms {
		if x.id == id {
			t = x
		}
	}
	s.mu.Unlock()
	if t == nil {
		closeWith(4004, "Session not found")
		return nil
	}
	if !t.running() {
		closeWith(4004, "Session has ended")
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	fin, op, payload, err := ReadWebSocketFrame(rw.Reader)
	var auth map[string]any
	if err != nil || !fin || op != 0x1 || json.Unmarshal(payload, &auth) != nil || auth == nil {
		closeWith(4001, "Auth timeout or invalid payload")
		return nil
	}
	_ = conn.SetReadDeadline(time.Time{})
	if tok, _ := auth["token"].(string); auth["type"] != "auth" || tok != s.key {
		closeWith(4001, "Invalid API key")
		return nil
	}
	if !hasSession {
		owner.session, _ = auth["chat_id"].(string)
	}
	if owner != t.owner {
		closeWith(4004, "Session not found")
		return nil
	}
	t.mu.Lock()
	if t.connected {
		t.mu.Unlock()
		closeWith(4009, "Session already connected")
		return nil
	}
	t.connected = true
	initial := bytes.Join(t.pending, nil)
	t.pending = nil
	t.ring = append(t.ring, initial...)
	t.mu.Unlock()
	defer s.destroy(t)
	if len(initial) > 0 && WriteWebSocketFrame(conn, true, 0x2, initial, false) != nil {
		return nil
	}
	type frame struct {
		op      byte
		payload []byte
	}
	frames := make(chan frame, 16)
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		defer close(frames)
		last := byte(0x2)
		for {
			fin, op, payload, err := ReadWebSocketFrame(rw.Reader)
			if err != nil {
				return
			}
			if op == 0x0 { // a continuation of the last data frame
				op = last
			} else if op < 0x8 {
				last = op
			}
			_ = fin
			select {
			case frames <- frame{op, payload}:
			case <-quit:
				return
			}
		}
	}()
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return nil
			}
			switch f.op {
			case 0x2:
				t.pty.input(f.payload)
			case 0x1:
				var m struct {
					Type       string
					Rows, Cols *int
				}
				if json.Unmarshal(f.payload, &m) == nil && m.Type == "resize" {
					rows, cols := 24, 80
					if m.Rows != nil {
						rows = min(*m.Rows, 65535)
					}
					if m.Cols != nil {
						cols = min(*m.Cols, 65535)
					}
					t.pty.resize(rows, cols)
				}
			case 0x9:
				if WriteWebSocketFrame(conn, true, 0xA, f.payload, false) != nil {
					return nil
				}
			case 0x8:
				_ = WriteWebSocketFrame(conn, true, 0x8, f.payload, false)
				return nil
			}
		case b := <-t.sink:
			if WriteWebSocketFrame(conn, true, 0x2, b, false) != nil {
				return nil
			}
		case <-t.lagged:
			closeWith(1013, "Client cannot keep up with terminal output")
			return nil
		}
	}
}

// ---- the shell ----

type acShell struct {
	s           *acServer
	pty         *acPTY
	cwd         string
	vars        map[string]string
	status      int
	pid         int
	interactive bool // bash in a terminal (else sh -c of a process)
	exited      *int
}

// run runs a process's command line and returns its exit code (-2 after ^C).
func (sh *acShell) run(line string) int {
	sh.runLine(line)
	if sh.exited != nil {
		return *sh.exited
	}
	if sh.status == 130 {
		return -2
	}
	return sh.status
}

// interact is the terminal's shell: a prompt, a line, until exit or ^D.
func (sh *acShell) interact() {
	for {
		sh.pty.write([]byte("\x1b[?2004h" + sh.s.prompt(sh.cwd)))
		line, eof, intr := sh.pty.readLine()
		if !intr || eof {
			sh.pty.write([]byte("\x1b[?2004l\r"))
		}
		switch {
		case eof && intr: // the terminal was closed
			return
		case eof:
			sh.pty.write([]byte("exit\n"))
			return
		case intr:
			sh.pty.write([]byte("\n"))
			continue
		}
		sh.runLine(line)
		if sh.exited != nil {
			return
		}
		if sh.status == 130 { // after ^C the shell starts a new line
			sh.pty.write([]byte("\n"))
		}
	}
}

func (sh *acShell) errPrefix() string {
	if sh.interactive {
		return "bash: "
	}
	return "/bin/sh: 1: "
}

type acTok struct {
	op   string // ";", "&&", "||", "|", ">", ">>", "<", "&" or "" for a word
	word string // the raw word (quotes kept)
}

func acLex(line string) ([]acTok, error) {
	var toks []acTok
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			toks = append(toks, acTok{word: cur.String()})
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("Syntax error: Unterminated quoted string")
			}
			cur.WriteString(line[i : i+j+2])
			i += j + 1
			inWord = true
		case c == '"':
			j := i + 1
			for ; j < len(line) && line[j] != '"'; j++ {
				if line[j] == '\\' {
					j++
				}
			}
			if j >= len(line) {
				return nil, fmt.Errorf("Syntax error: Unterminated quoted string")
			}
			cur.WriteString(line[i : j+1])
			i = j
			inWord = true
		case c == '\\' && i+1 < len(line):
			cur.WriteString(line[i : i+2])
			i++
			inWord = true
		case c == '$' && strings.HasPrefix(line[i:], "$(("):
			j := strings.Index(line[i:], "))")
			if j < 0 {
				return nil, fmt.Errorf("Syntax error: Missing '))'")
			}
			cur.WriteString(line[i : i+j+2])
			i += j + 1
			inWord = true
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		case c == '#' && !inWord:
			flush()
			return toks, nil
		case strings.ContainsRune(";&|<>", rune(c)):
			flush()
			op := string(c)
			if i+1 < len(line) && (line[i:i+2] == "&&" || line[i:i+2] == "||" || line[i:i+2] == ">>") {
				op = line[i : i+2]
				i++
			}
			toks = append(toks, acTok{op: op})
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return toks, nil
}

func (sh *acShell) runLine(line string) {
	toks, err := acLex(line)
	if err != nil {
		sh.pty.write([]byte(sh.errPrefix() + err.Error() + "\n"))
		sh.status = 2
		return
	}
	var cmd []acTok
	next := ""
	runIt := func() bool {
		if len(cmd) > 0 && sh.exited == nil && (next == "" || next == ";" || (next == "&&") == (sh.status == 0)) {
			sh.runCommand(cmd)
			if sh.pty.takeIntr() || sh.status == 130 {
				sh.status = 130
				return false
			}
		}
		return sh.exited == nil
	}
	for _, t := range toks {
		switch t.op {
		case ";", "&&", "||", "&":
			if !runIt() {
				return
			}
			cmd, next = nil, t.op
			if t.op == "&" {
				next = ";"
			}
		default:
			cmd = append(cmd, t)
		}
	}
	runIt()
}

// expand performs quote removal and $ expansions; ok is false for an unquoted word that
// expanded to nothing (dropped, as a shell drops it).
func (sh *acShell) expand(raw string) (string, bool) {
	var b strings.Builder
	quoted := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(raw[i+1:], '\'')
			b.WriteString(raw[i+1 : i+1+j])
			i += j + 1
			quoted = true
		case c == '"':
			quoted = true
			for i++; i < len(raw) && raw[i] != '"'; i++ {
				switch {
				case raw[i] == '\\' && i+1 < len(raw) && strings.IndexByte("$`\"\\\n", raw[i+1]) >= 0:
					b.WriteByte(raw[i+1])
					i++
				case raw[i] == '$':
					v, n := sh.dollar(raw[i:])
					b.WriteString(v)
					i += n - 1
				default:
					b.WriteByte(raw[i])
				}
			}
		case c == '\\' && i+1 < len(raw):
			b.WriteByte(raw[i+1])
			i++
			quoted = true
		case c == '$':
			v, n := sh.dollar(raw[i:])
			b.WriteString(v)
			i += n - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), quoted || b.Len() > 0
}

// dollar expands the expansion at the start of s and returns its value and length.
func (sh *acShell) dollar(s string) (string, int) {
	if strings.HasPrefix(s, "$((") {
		end := strings.Index(s, "))")
		if end < 0 {
			return s, len(s)
		}
		v, err := sh.arith(s[3:end])
		if err != nil {
			return "", end + 2
		}
		return strconv.FormatInt(v, 10), end + 2
	}
	if len(s) < 2 {
		return "$", 1
	}
	switch s[1] {
	case '?':
		return strconv.Itoa(sh.status), 2
	case '$':
		return strconv.Itoa(sh.pid), 2
	case '{':
		end := strings.IndexByte(s, '}')
		if end < 0 {
			return s, len(s)
		}
		return sh.vars[s[2:end]], end + 1
	}
	n := 1
	for n < len(s) && (s[n] == '_' || unicode.IsLetter(rune(s[n])) || (n > 1 && unicode.IsDigit(rune(s[n])))) {
		n++
	}
	if n == 1 {
		return "$", 1
	}
	return sh.vars[s[1:n]], n
}

// arith evaluates integer arithmetic (+ - * / % and parentheses, variables).
func (sh *acShell) arith(expr string) (int64, error) {
	p := &acArith{s: strings.ReplaceAll(expr, " ", ""), vars: sh.vars}
	v := p.sum()
	if p.err != nil || p.i != len(p.s) {
		return 0, fmt.Errorf("arithmetic expression: %q", expr)
	}
	return v, nil
}

type acArith struct {
	s    string
	i    int
	vars map[string]string
	err  error
}

func (p *acArith) sum() int64 {
	v := p.product()
	for p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
		op := p.s[p.i]
		p.i++
		if r := p.product(); op == '+' {
			v += r
		} else {
			v -= r
		}
	}
	return v
}

func (p *acArith) product() int64 {
	v := p.unary()
	for p.i < len(p.s) && strings.IndexByte("*/%", p.s[p.i]) >= 0 {
		op := p.s[p.i]
		p.i++
		r := p.unary()
		switch {
		case op == '*':
			v *= r
		case r == 0:
			p.err = fmt.Errorf("division by 0")
		case op == '/':
			v /= r
		default:
			v %= r
		}
	}
	return v
}

func (p *acArith) unary() int64 {
	if p.i < len(p.s) && p.s[p.i] == '-' {
		p.i++
		return -p.unary()
	}
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		v := p.sum()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			p.err = fmt.Errorf("missing )")
			return 0
		}
		p.i++
		return v
	}
	start := p.i
	for p.i < len(p.s) && (p.s[p.i] == '_' || unicode.IsLetter(rune(p.s[p.i])) || unicode.IsDigit(rune(p.s[p.i]))) {
		p.i++
	}
	tok := p.s[start:p.i]
	if tok == "" {
		p.err = fmt.Errorf("syntax error")
		return 0
	}
	if v, err := strconv.ParseInt(tok, 10, 64); err == nil {
		return v
	}
	if unicode.IsDigit(rune(tok[0])) {
		p.err = fmt.Errorf("value too great for base")
		return 0
	}
	v, _ := strconv.ParseInt(p.vars[tok], 10, 64)
	return v
}

// runCommand runs one simple command (words and redirections).
func (sh *acShell) runCommand(toks []acTok) {
	var args []string
	var outFile, inFile string
	appendOut := false
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.op {
		case "":
			if w, ok := sh.expand(t.word); ok {
				args = append(args, w)
			}
		case ">", ">>", "<":
			if i+1 >= len(toks) || toks[i+1].op != "" {
				sh.pty.write([]byte(sh.errPrefix() + "Syntax error: newline unexpected\n"))
				sh.status = 2
				return
			}
			target, _ := sh.expand(toks[i+1].word)
			i++
			if t.op == "<" {
				inFile = target
			} else {
				outFile, appendOut = target, t.op == ">>"
			}
		case "|":
			sh.pty.write([]byte(sh.errPrefix() + "pipes are not supported by cloudtest's fake agent-companion\n"))
			sh.status = 2
			return
		}
	}
	// Leading assignments.
	for len(args) > 0 {
		k, v, ok := strings.Cut(args[0], "=")
		if !ok || k == "" || !acName(k) {
			break
		}
		sh.vars[k] = v
		args = args[1:]
	}
	if len(args) == 0 {
		sh.status = 0
		return
	}
	var buf bytes.Buffer
	out := func(s string) {
		if outFile != "" {
			buf.WriteString(s)
		} else {
			sh.pty.write([]byte(s))
		}
	}
	errOut := func(s string) { sh.pty.write([]byte(s)) }
	var input []string
	haveInput := false
	if inFile != "" {
		sh.s.mu.Lock()
		data, err := sh.s.fs.read(sh.s.fs.resolve(inFile, sh.cwd))
		sh.s.mu.Unlock()
		if err != nil {
			errOut(sh.errPrefix() + "cannot open " + inFile + ": No such file\n")
			sh.status = 2
			return
		}
		input, haveInput = acLines(string(data)), true
	}
	readLine := func() (string, bool, bool) {
		if haveInput {
			if len(input) == 0 {
				return "", true, false
			}
			l := input[0]
			input = input[1:]
			return l, false, false
		}
		return sh.pty.readLine()
	}
	sh.status = sh.builtin(args, out, errOut, readLine)
	if outFile != "" {
		sh.s.mu.Lock()
		p := sh.s.fs.resolve(outFile, sh.cwd)
		data := buf.Bytes()
		if appendOut {
			if old, err := sh.s.fs.read(p); err == nil {
				data = append(bytes.Clone(old), data...)
			}
		}
		err := sh.s.fs.write(p, data)
		sh.s.mu.Unlock()
		if err != nil {
			errOut(sh.errPrefix() + "cannot create " + outFile + ": " + acErrText(err) + "\n")
			sh.status = 2
		}
	}
}

func acName(k string) bool {
	for i, c := range k {
		if !(c == '_' || unicode.IsLetter(c) || (i > 0 && unicode.IsDigit(c))) {
			return false
		}
	}
	return true
}

// acErrText is an fs error as a command prints it ("Permission denied").
func acErrText(err error) string {
	if e, ok := err.(*acErr); ok {
		if m, ok := e.body.(map[string]any); ok {
			s, _ := m["detail"].(string)
			s, _, _ = strings.Cut(s, " (os error")
			return s
		}
	}
	return err.Error()
}

func (sh *acShell) builtin(args []string, out, errOut func(string), readLine func() (string, bool, bool)) int {
	fs := sh.s.fs
	lock := func() func() { sh.s.mu.Lock(); return sh.s.mu.Unlock }
	name, rest := args[0], args[1:]
	switch name {
	case "true", ":":
		return 0
	case "false":
		return 1
	case "exit":
		code := sh.status
		if len(rest) > 0 {
			code, _ = strconv.Atoi(rest[0])
		}
		code &= 0xff
		if sh.interactive {
			out("exit\n")
		}
		sh.exited = &code
		return code
	case "echo":
		nl := true
		if len(rest) > 0 && rest[0] == "-n" {
			nl, rest = false, rest[1:]
		}
		s := strings.Join(rest, " ")
		if !sh.interactive { // dash's echo reads backslash escapes
			if i := strings.Index(s, `\c`); i >= 0 {
				s, nl = s[:i], false
			}
			s = strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\\`, `\`).Replace(s)
		}
		if nl {
			s += "\n"
		}
		out(s)
		return 0
	case "printf":
		if len(rest) == 0 {
			errOut("printf: usage: printf format [arguments]\n")
			return 2
		}
		out(acPrintf(rest[0], rest[1:]))
		return 0
	case "pwd":
		out(sh.cwd + "\n")
		return 0
	case "cd":
		dir := sh.vars["HOME"]
		if len(rest) > 0 {
			dir = rest[0]
		}
		defer lock()()
		p := fs.resolve(dir, sh.cwd)
		if !fs.isDir(p) {
			if sh.interactive {
				errOut("bash: cd: " + dir + ": No such file or directory\n")
				return 1
			}
			errOut("/bin/sh: 1: cd: can't cd to " + dir + "\n")
			return 2
		}
		sh.cwd, sh.vars["PWD"] = p, p
		return 0
	case "cat":
		if len(rest) == 0 {
			for {
				l, eof, intr := readLine()
				if intr {
					return 130
				}
				if eof {
					return 0
				}
				out(l)
			}
		}
		code := 0
		for _, f := range rest {
			unlock := lock()
			p := fs.resolve(f, sh.cwd)
			data, err := fs.read(p)
			isDir := fs.isDir(p)
			unlock()
			switch {
			case isDir:
				errOut("cat: " + f + ": Is a directory\n")
				code = 1
			case err != nil:
				errOut("cat: " + f + ": No such file or directory\n")
				code = 1
			default:
				out(string(data))
			}
		}
		return code
	case "read":
		vars := []string{}
		for _, a := range rest {
			if !strings.HasPrefix(a, "-") {
				vars = append(vars, a)
			}
		}
		if len(vars) == 0 {
			vars = []string{"REPLY"}
		}
		l, eof, intr := readLine()
		if intr {
			return 130
		}
		fields := strings.Fields(strings.TrimRight(l, "\n"))
		for i, v := range vars {
			switch {
			case i == len(vars)-1 && i < len(fields):
				sh.vars[v] = strings.Join(fields[i:], " ")
			case i < len(fields):
				sh.vars[v] = fields[i]
			default:
				sh.vars[v] = ""
			}
		}
		if eof {
			return 1
		}
		return 0
	case "sleep":
		if len(rest) == 0 {
			errOut("sleep: missing operand\n")
			return 1
		}
		d, err := strconv.ParseFloat(strings.TrimSuffix(rest[0], "s"), 64)
		if err != nil || d < 0 {
			errOut("sleep: invalid time interval '" + rest[0] + "'\n")
			return 1
		}
		if sh.pty.sleep(time.Duration(d * float64(time.Second))) {
			return 130
		}
		return 0
	case "whoami":
		out("agent\n")
		return 0
	case "hostname":
		out(acHostname + "\n")
		return 0
	case "id":
		out("uid=10001(agent) gid=10001(agent) groups=10001(agent)\n")
		return 0
	case "uname":
		if len(rest) > 0 && rest[0] == "-a" {
			out("Linux " + acHostname + " 6.1.0 #1 SMP x86_64 GNU/Linux\n")
		} else {
			out("Linux\n")
		}
		return 0
	case "env", "printenv":
		if len(rest) > 0 {
			v, ok := sh.vars[rest[0]]
			if !ok {
				return 1
			}
			out(v + "\n")
			return 0
		}
		keys := make([]string, 0, len(sh.vars))
		for k := range sh.vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out(k + "=" + sh.vars[k] + "\n")
		}
		return 0
	case "export":
		for _, a := range rest {
			if k, v, ok := strings.Cut(a, "="); ok {
				sh.vars[k] = v
			}
		}
		return 0
	case "unset":
		for _, a := range rest {
			delete(sh.vars, a)
		}
		return 0
	case "stty":
		if len(rest) == 1 && rest[0] == "size" {
			sh.pty.mu.Lock()
			rows, cols := sh.pty.rows, sh.pty.cols
			sh.pty.mu.Unlock()
			out(fmt.Sprintf("%d %d\n", rows, cols))
		}
		return 0
	case "ls":
		all := false
		var paths []string
		for _, a := range rest {
			if strings.HasPrefix(a, "-") {
				all = all || strings.Contains(a, "a")
			} else {
				paths = append(paths, a)
			}
		}
		if len(paths) == 0 {
			paths = []string{"."}
		}
		defer lock()()
		code := 0
		for _, a := range paths {
			p := fs.resolve(a, sh.cwd)
			switch {
			case fs.isDir(p):
				for _, n := range fs.children(p) {
					if all || !strings.HasPrefix(n, ".") {
						out(n + "\n")
					}
				}
			case fs.isFile(p):
				out(a + "\n")
			default:
				errOut("ls: cannot access '" + a + "': No such file or directory\n")
				code = 2
			}
		}
		return code
	case "mkdir", "touch", "rm":
		parents, recursive, force := false, false, false
		var paths []string
		for _, a := range rest {
			if strings.HasPrefix(a, "-") {
				parents = parents || strings.Contains(a, "p")
				recursive = recursive || strings.ContainsAny(a, "rR")
				force = force || strings.Contains(a, "f")
			} else {
				paths = append(paths, a)
			}
		}
		if len(paths) == 0 {
			errOut(name + ": missing operand\n")
			return 1
		}
		defer lock()()
		code := 0
		for _, a := range paths {
			p := fs.resolve(a, sh.cwd)
			var err error
			switch name {
			case "mkdir":
				switch {
				case fs.exists(p) && !parents:
					errOut("mkdir: cannot create directory '" + a + "': File exists\n")
					code = 1
					continue
				case !parents && !fs.isDir(acParent(p)):
					errOut("mkdir: cannot create directory '" + a + "': No such file or directory\n")
					code = 1
					continue
				}
				err = fs.mkdir(p)
			case "touch":
				if fs.isFile(p) {
					fs.nodes[p].mod = time.Now()
					continue
				}
				if !fs.isDir(p) {
					if !fs.isDir(acParent(p)) {
						errOut("touch: cannot touch '" + a + "': No such file or directory\n")
						code = 1
						continue
					}
					err = fs.write(p, nil)
				}
			case "rm":
				switch {
				case !fs.exists(p):
					if !force {
						errOut("rm: cannot remove '" + a + "': No such file or directory\n")
						code = 1
					}
					continue
				case fs.isDir(p) && !recursive:
					errOut("rm: cannot remove '" + a + "': Is a directory\n")
					code = 1
					continue
				}
				err = fs.remove(p)
			}
			if err != nil {
				errOut(fmt.Sprintf("%s: cannot %s '%s': %s\n", name, map[string]string{"mkdir": "create directory", "touch": "touch", "rm": "remove"}[name], a, acErrText(err)))
				code = 1
			}
		}
		return code
	}
	if sh.interactive {
		errOut("bash: " + name + ": command not found\n")
	} else {
		errOut("/bin/sh: 1: " + name + ": not found\n")
	}
	return 127
}

func acParent(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "/"
}

// acPrintf is printf(1) for %s, %d, %% and the backslash escapes; the format is reused while
// arguments remain.
func acPrintf(format string, args []string) string {
	format = strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\\`, `\`, `\r`, "\r").Replace(format)
	var b strings.Builder
	for first := true; first || len(args) > 0; first = false {
		used := false
		for i := 0; i < len(format); i++ {
			if format[i] != '%' || i+1 >= len(format) {
				b.WriteByte(format[i])
				continue
			}
			i++
			arg := ""
			if format[i] != '%' && len(args) > 0 {
				arg, args, used = args[0], args[1:], true
			}
			switch format[i] {
			case '%':
				b.WriteByte('%')
			case 'd', 'i':
				n, _ := strconv.ParseInt(arg, 10, 64)
				b.WriteString(strconv.FormatInt(n, 10))
			default:
				b.WriteString(arg)
			}
		}
		if !used {
			break
		}
	}
	return b.String()
}
