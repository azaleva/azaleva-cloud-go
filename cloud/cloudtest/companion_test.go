package cloudtest

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestFakeCompanion checks the fake agent-companion against agent-companion 0.14.0's API.
// With CLOUDTEST_COMPANION_BIN (the pinned agent-companion binary) the same checks
// run against the real binary too, started as Azaleva Cloud's unit starts it, so the fake and
// the real one are held to one description.
func TestFakeCompanion(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		srv := httptest.NewServer(FakeCompanion("k-fake"))
		defer srv.Close()
		companionConformance(t, srv.URL, "k-fake")
	})
	bin := os.Getenv("CLOUDTEST_COMPANION_BIN")
	if bin == "" {
		return
	}
	t.Run("real", func(t *testing.T) {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("CLOUDTEST_COMPANION_BIN: %v", err)
		}
		home, state := t.TempDir(), t.TempDir()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		cmd := exec.Command(bin, "run", "--host", "127.0.0.1", "--port", fmt.Sprint(port))
		cmd.Dir = home
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + state, "USER=agent", "SHELL=/bin/bash",
			"XDG_CONFIG_HOME=" + state, "XDG_STATE_HOME=" + state, "AGENT_COMPANION_API_KEY=k-real",
			"AGENT_COMPANION_ENABLE_NOTEBOOKS=false", "AGENT_COMPANION_ENABLE_SYSTEM_PROMPT=false",
			"AGENT_COMPANION_MULTI_USER=false", "AGENT_COMPANION_MAX_SESSIONS=4"}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		base := fmt.Sprintf("http://127.0.0.1:%d", port)
		for end := time.Now().Add(10 * time.Second); ; {
			if resp, err := http.Get(base + "/health"); err == nil {
				resp.Body.Close()
				break
			}
			if time.Now().After(end) {
				t.Fatal("agent-companion did not start")
			}
			time.Sleep(50 * time.Millisecond)
		}
		companionConformance(t, base, "k-real")
	})
}

type acClient struct {
	t        *testing.T
	base     string
	key      string
	user, ss string
}

func (c acClient) as(user, session string) acClient { c.user, c.ss = user, session; return c }

func (c acClient) do(method, path string, body any, extra ...string) (int, http.Header, []byte) {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	if c.user != "" {
		req.Header.Set("X-User-Id", c.user)
	}
	if c.ss != "" {
		req.Header.Set("X-Session-Id", c.ss)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// json sends a request and decodes a JSON answer of the wanted status.
func (c acClient) json(method, path string, body any, status int) map[string]any {
	c.t.Helper()
	st, _, b := c.do(method, path, body)
	var v map[string]any
	if st != status || json.Unmarshal(b, &v) != nil {
		c.t.Fatalf("%s %s: %d %s, want %d", method, path, st, b, status)
	}
	return v
}

func (c acClient) list(method, path string) []any {
	c.t.Helper()
	st, _, b := c.do(method, path, nil)
	var v []any
	if st != 200 || json.Unmarshal(b, &v) != nil {
		c.t.Fatalf("%s %s: %d %s", method, path, st, b)
	}
	return v
}

func (c acClient) detail(method, path string, body any, status int, detail string) {
	c.t.Helper()
	st, _, b := c.do(method, path, body)
	if want, _ := json.Marshal(map[string]string{"detail": detail}); st != status || !bytes.Equal(bytes.TrimSpace(b), want) {
		c.t.Fatalf("%s %s: %d %s, want %d %s", method, path, st, b, status, want)
	}
}

func keys(m map[string]any) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return strings.Join(sortStrings(ks), ",")
}

func sortStrings(s []string) []string {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}

func outputOf(v map[string]any) string {
	var b strings.Builder
	out, _ := v["output"].([]any)
	for _, e := range out {
		m, _ := e.(map[string]any)
		if m["type"] != "output" {
			return "<entry type " + fmt.Sprint(m["type"]) + ">"
		}
		b.WriteString(m["data"].(string))
	}
	return b.String()
}

func companionConformance(t *testing.T, base, key string) {
	anon := acClient{t: t, base: base}
	c := acClient{t: t, base: base, key: key, user: "u1", ss: "s1"}

	// Discovery and authentication.
	if v := anon.json("GET", "/health", nil, 200); v["status"] != "ok" {
		t.Fatalf("health %v", v)
	}
	cfg := anon.json("GET", "/api/config", nil, 200)
	if f, _ := cfg["features"].(map[string]any); f["terminal"] != true || f["notebooks"] != false || f["system"] != false {
		t.Fatalf("config %v", cfg)
	}
	if info, _ := anon.json("GET", "/openapi.json", nil, 200)["info"].(map[string]any); info["version"] != CompanionVersion {
		t.Fatalf("openapi info %v (cloudtest.CompanionVersion %s)", info, CompanionVersion)
	}
	anon.detail("GET", "/files/cwd", nil, 401, "Invalid API key")
	acClient{t: t, base: base, key: "wrong"}.detail("GET", "/files/cwd", nil, 401, "Invalid API key")
	anon.detail("GET", "/no-such-route", nil, 404, "Not Found")
	c.detail("GET", "/no-such-route", nil, 404, "Not Found")
	c.detail("GET", "/notebooks/x", nil, 404, "Not Found")
	c.detail("POST", "/notebooks", map[string]string{"path": "/x.ipynb"}, 404, "Not Found")
	c.detail("GET", "/system", nil, 404, "Not Found")
	if st, h, _ := anon.do("PUT", "/files/cwd", nil); st != 405 || h.Get("Allow") != "GET, POST" {
		t.Fatalf("PUT /files/cwd: %d %v", st, h)
	}
	if st, h, _ := c.do("GET", "/files/cwd/?x=1", nil); st != 307 || h.Get("Location") != "/files/cwd?x=1" {
		t.Fatalf("GET /files/cwd/: %d %v", st, h)
	}

	// Working directories.
	cwd := c.json("GET", "/files/cwd", nil, 200)
	home, _ := cwd["home"].(string)
	root, _ := cwd["root"].(map[string]any)
	if keys(cwd) != "cwd,home,root" || cwd["cwd"] != home || home == "" || root["path"] != home || root["label"] != "Home" {
		t.Fatalf("GET /files/cwd: %v", cwd)
	}
	dir := home + "/proj"
	if v := c.json("POST", "/files/mkdir", map[string]string{"path": "proj/sub"}, 200); v["path"] != dir+"/sub" {
		t.Fatalf("mkdir %v", v)
	}
	c.detail("POST", "/files/cwd", map[string]string{"path": dir + "/missing"}, 404, "Directory not found")
	if v := c.json("POST", "/files/cwd", map[string]string{"path": "proj"}, 200); keys(v) != "cwd" || v["cwd"] != dir {
		t.Fatalf("POST /files/cwd: %v", v)
	}
	if v := c.json("GET", "/files/cwd", nil, 200); v["cwd"] != dir || v["home"] != home {
		t.Fatalf("GET /files/cwd after POST: %v", v)
	}
	if v := c.as("u2", "s1").json("GET", "/files/cwd", nil, 200); v["cwd"] != dir { // keyed on X-Session-Id alone
		t.Fatalf("another user of the session: %v", v)
	}
	if v := c.as("u1", "s2").json("GET", "/files/cwd", nil, 200); v["cwd"] != home {
		t.Fatalf("another session: %v", v)
	}
	invalid := func(method, path string, body any, typ, loc string) {
		t.Helper()
		st, _, b := c.do(method, path, body)
		var v struct {
			Detail []struct {
				Type, Msg string
				Loc       []any
				Input     any
			}
		}
		if st != 422 || json.Unmarshal(b, &v) != nil || len(v.Detail) != 1 || v.Detail[0].Type != typ || fmt.Sprint(v.Detail[0].Loc) != loc {
			t.Fatalf("%s %s: %d %s, want 422 %s at %s", method, path, st, b, typ, loc)
		}
	}
	invalid("POST", "/files/cwd", map[string]string{}, "missing", "[body path]")
	invalid("POST", "/files/cwd", "{not json", "json_invalid", "[body 1]")
	invalid("POST", "/files/cwd", nil, "missing", "[body]")
	invalid("GET", "/files/read", nil, "missing", "[query path]")
	invalid("GET", "/files/grep?query=x&max_results=0", nil, "greater_than_equal", "[query max_results]")
	invalid("POST", "/files/write", map[string]any{"path": 1, "content": "x"}, "string_type", "[body path]")

	// Files: relative paths are the session's working directory's (scoped routes).
	if v := c.json("POST", "/files/write", map[string]string{"path": "a.txt", "content": "one\r\ntwo\nthree"}, 200); keys(v) != "path,size" || v["path"] != dir+"/a.txt" || v["size"] != 14.0 {
		t.Fatalf("write %v", v)
	}
	if v := c.json("GET", "/files/read?path=a.txt&start_line=2&end_line=2", nil, 200); keys(v) != "content,path,total_lines" || v["content"] != "two\n" || v["total_lines"] != 3.0 {
		t.Fatalf("read %v", v)
	}
	if v := c.as("u1", "").json("GET", "/files/read?path=proj/a.txt", nil, 200); v["content"] != "one\ntwo\nthree" {
		t.Fatalf("read without a session (relative to the home) %v", v)
	}
	c.detail("GET", "/files/read?path=nope.txt", nil, 404, "File not found")
	if v := c.json("GET", "/files/display?path=a.txt", nil, 200); v["exists"] != true || v["path"] != dir+"/a.txt" {
		t.Fatalf("display %v", v)
	}
	ls := c.json("GET", "/files/list", nil, 200)
	entries, _ := ls["entries"].([]any)
	if ls["dir"] != dir || ls["writable"] != true || len(entries) != 2 {
		t.Fatalf("list %v", ls)
	}
	if e := entries[0].(map[string]any); keys(e) != "modified,name,size,type,writable" || e["name"] != "a.txt" || e["type"] != "file" || e["size"] != 14.0 {
		t.Fatalf("list entry %v", e)
	}
	c.detail("GET", "/files/list?directory=nope", nil, 404, "Directory not found")
	// /files/view and /files/serve are not scoped: relative paths are the home's.
	st, h, b := c.do("GET", "/files/view?path=proj/a.txt", nil)
	if st != 200 || string(b) != "one\r\ntwo\nthree" || h.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("view %d %v %q", st, h, b)
	}
	if st, _, b := c.do("GET", "/files/serve"+dir+"/a.txt", nil); st != 200 || string(b) != "one\r\ntwo\nthree" {
		t.Fatalf("serve %d %q", st, b)
	}
	if v := c.json("POST", "/files/replace", map[string]any{"path": "a.txt", "replacements": []any{map[string]any{"target": "two", "replacement": "2"}}}, 200); v["size"] != 11.0 {
		t.Fatalf("replace %v", v)
	}
	c.detail("POST", "/files/replace", map[string]any{"path": "a.txt", "replacements": []any{map[string]any{"target": "zzz", "replacement": "2"}}}, 400, "Target string not found: 'zzz'")
	if v := c.json("POST", "/files/move", map[string]string{"source": "proj/a.txt", "destination": "proj/b.txt"}, 200); v["source"] != dir+"/a.txt" || v["destination"] != dir+"/b.txt" {
		t.Fatalf("move %v", v)
	}
	c.detail("POST", "/files/move", map[string]string{"source": "proj/a.txt", "destination": "proj/c.txt"}, 404, "Source path not found")
	c.json("POST", "/files/write", map[string]string{"path": "c.txt", "content": "x"}, 200)
	c.detail("POST", "/files/move", map[string]string{"source": "proj/b.txt", "destination": "proj/c.txt"}, 409, "Destination already exists")
	if v := c.json("GET", "/files/grep?query=thr", nil, 200); fmt.Sprint(v["matches"]) != fmt.Sprintf("[map[content:three file:%s/b.txt line:3]]", dir) || v["truncated"] != false {
		t.Fatalf("grep %v", v)
	}
	if v := c.json("GET", "/files/glob?pattern=*.txt", nil, 200); len(v["matches"].([]any)) != 2 || v["pattern"] != "*.txt" {
		t.Fatalf("glob %v", v)
	}
	if v := c.json("GET", "/files/search?query=b", nil, 200); len(v["results"].([]any)) != 2 { // b.txt, sub
		t.Fatalf("search %v", v)
	}
	if v := c.json("GET", "/files/matches?query=three", nil, 200); keys(v) != "next_offset,results" || len(v["results"].([]any)) != 1 {
		t.Fatalf("matches %v", v)
	}
	c.detail("GET", "/files/matches?query=%20", nil, 400, "Query must not be blank")
	if strings.HasPrefix(home, "/workspace") || os.Getuid() != 0 { // the agent user cannot write /etc
		c.detail("POST", "/files/write", map[string]string{"path": "/etc/cloudtest", "content": "x"}, 403, "Permission denied (os error 13)")
	}
	// Upload and download.
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	fw, _ := mw.CreateFormFile("file", "up.bin")
	_, _ = fw.Write([]byte{0xff, 0xfe, 0, 1})
	mw.Close()
	st, _, b = c.do("POST", "/files/upload?directory=proj/sub", mp.String(), "Content-Type", mw.FormDataContentType())
	if st != 200 || string(b) != fmt.Sprintf(`{"path":"%s/sub/up.bin","size":4}`, dir) {
		t.Fatalf("upload %d %s", st, b)
	}
	c.detail("GET", "/files/read?path=sub/up.bin", nil, 415, "Unsupported binary file type: application/octet-stream (4 bytes)")
	st, h, b = c.do("POST", "/files/archive", map[string]any{"paths": []string{"proj/sub"}})
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if st != 200 || err != nil || len(zr.File) != 1 || zr.File[0].Name != "sub/up.bin" || h.Get("Content-Disposition") != `attachment; filename="sub.zip"` {
		t.Fatalf("archive %d %v %v", st, h, err)
	}
	if v := c.json("DELETE", "/files/delete?path=proj/c.txt", nil, 200); v["type"] != "file" {
		t.Fatalf("delete %v", v)
	}
	c.detail("DELETE", "/files/delete?path=proj/c.txt", nil, 404, "Path not found")

	// Processes: (X-User-Id, X-Session-Id) own them; output comes from a PTY ("\r\n").
	p := c.json("POST", "/execute?wait=10", map[string]string{"command": "echo hi-$((6*7)) && pwd"}, 200)
	if keys(p) != "command,exit_code,id,log_path,next_offset,output,status,truncated" || p["status"] != "done" || p["exit_code"] != 0.0 ||
		outputOf(p) != "hi-42\r\n"+dir+"\r\n" {
		t.Fatalf("execute %v", p)
	}
	id := p["id"].(string)
	if !strings.HasSuffix(p["log_path"].(string), "/agent-companion/logs/processes/"+id+".jsonl") {
		t.Fatalf("log_path %v", p["log_path"])
	}
	if v := c.json("GET", "/execute/"+id+"/status?offset=1", nil, 200); len(v["output"].([]any)) != int(p["next_offset"].(float64))-1 {
		t.Fatalf("status offset %v", v)
	}
	c.as("u2", "s1").detail("GET", "/execute/"+id+"/status", nil, 404, "Process not found")
	c.as("u1", "s2").detail("GET", "/execute/"+id+"/status", nil, 404, "Process not found")
	if l := c.list("GET", "/execute"); len(l) != 1 || l[0].(map[string]any)["id"] != id {
		t.Fatalf("list %v", l)
	}
	if v := c.json("POST", "/execute?wait=10", map[string]string{"command": "nosuchcommand; exit 3"}, 200); v["exit_code"] != 3.0 ||
		outputOf(v) != "/bin/sh: 1: nosuchcommand: not found\r\n" {
		t.Fatalf("exit 3 %v %q", v, outputOf(v))
	}
	p = c.json("POST", "/execute", map[string]any{"command": "read x; echo got-$x-$FOO", "env": map[string]string{"FOO": "bar"}}, 200)
	id = p["id"].(string)
	if v := c.json("POST", "/execute/"+id+"/input", map[string]string{"input": `abc\n`}, 200); v["status"] != "ok" {
		t.Fatalf("input %v", v)
	}
	if v := c.json("GET", "/execute/"+id+"/status?wait=10", nil, 200); v["status"] != "done" || outputOf(v) != "abc\r\ngot-abc-bar\r\n" {
		t.Fatalf("input answer %v %q", v, outputOf(v))
	}
	c.detail("POST", "/execute/"+id+"/input", map[string]string{"input": "x"}, 400, "Process has already exited")
	p = c.json("POST", "/execute", map[string]string{"command": "sleep 30"}, 200)
	id = p["id"].(string)
	c.json("POST", "/execute/"+id+"/input", map[string]string{"input": `\x03`}, 200) // no controlling terminal: echoed only
	time.Sleep(300 * time.Millisecond)
	if v := c.json("GET", "/execute/"+id+"/status", nil, 200); v["status"] != "running" || outputOf(v) != "^C" {
		t.Fatalf("^C %v", v)
	}
	if v := c.json("DELETE", "/execute/"+id, nil, 200); keys(v) != "status" || v["status"] != "killed" {
		t.Fatalf("kill %v", v)
	}
	if v := c.json("GET", "/execute/"+id+"/status", nil, 200); v["status"] != "killed" || v["exit_code"] != -15.0 {
		t.Fatalf("killed %v", v)
	}
	c.detail("DELETE", "/execute/nope", nil, 404, "Process not found")

	// Terminals.
	term := c.json("POST", "/api/terminals", nil, 200)
	tid, _ := term["id"].(string)
	if keys(term) != "created_at,id,pid" || len(tid) != 8 || term["pid"].(float64) <= 0 {
		t.Fatalf("terminal %v", term)
	}
	if v := c.json("GET", "/api/terminals/"+tid, nil, 200); v["id"] != tid {
		t.Fatalf("get terminal %v", v)
	}
	for _, o := range []acClient{c.as("u2", "s1"), c.as("u1", "s2")} {
		if st, _, b := o.do("GET", "/api/terminals/"+tid, nil); st != 404 || string(b) != `{"error":"Session not found"}` {
			t.Fatalf("a foreign terminal: %d %s", st, b)
		}
	}
	if l := c.list("GET", "/api/terminals"); len(l) != 1 {
		t.Fatalf("terminals %v", l)
	}
	c.detail("GET", "/api/terminals/user/output", nil, 404, "No connected user shell")
	auth := fmt.Sprintf(`{"type":"auth","token":%q}`, key)
	closed := func(ws *acWS, want uint16, reason string) {
		t.Helper()
		op, p := ws.read(t)
		if op != 0x8 || len(p) < 2 || binary.BigEndian.Uint16(p) != want || string(p[2:]) != reason {
			t.Fatalf("close: op %x %q, want %d %q", op, p, want, reason)
		}
		ws.conn.Close()
	}
	ws := dialACWS(t, base, "/api/terminals/nope", "u1", "s1")
	ws.write(t, 0x1, auth)
	closed(ws, 4004, "Session not found")
	ws = dialACWS(t, base, "/api/terminals/"+tid, "u2", "s1")
	ws.write(t, 0x1, auth)
	closed(ws, 4004, "Session not found")
	ws = dialACWS(t, base, "/api/terminals/"+tid, "u1", "s1")
	ws.write(t, 0x1, `{"type":"auth","token":"wrong"}`)
	closed(ws, 4001, "Invalid API key")
	ws = dialACWS(t, base, "/api/terminals/"+tid, "u1", "s1")
	ws.write(t, 0x2, "hello")
	closed(ws, 4001, "Auth timeout or invalid payload")
	ws = dialACWS(t, base, "/api/terminals/"+tid, "u1", "s1")
	ws.write(t, 0x1, auth)
	ws.until(t, "$ ")
	ws.write(t, 0x1, `{"type":"resize","rows":30,"cols":100}`)
	ws.write(t, 0x2, "echo x-$((40+2)); stty size\r")
	if out := ws.until(t, "30 100\r\n"); !strings.Contains(out, "x-42\r\n") {
		t.Fatalf("terminal output %q", out)
	}
	ws.until(t, "$ ")
	// ^C interrupts the foreground command. A builtin (read) rather than a child (sleep): a ^C
	// that reaches bash between its fork and the child taking the terminal is lost (bash
	// ignores SIGINT while it waits), so the test would wait out the child.
	ws.write(t, 0x2, "read x\r")
	ws.until(t, "\r\n")
	ws.write(t, 0x2, "\x03")
	// The echo and the next prompt may come in one frame.
	if out := ws.until(t, "^C"); !strings.Contains(out[strings.Index(out, "^C"):], "$ ") {
		ws.until(t, "$ ")
	}
	second := dialACWS(t, base, "/api/terminals/"+tid, "u1", "s1")
	second.write(t, 0x1, auth)
	closed(second, 4009, "Session already connected")
	if v := c.json("GET", "/api/terminals/user/output", nil, 200); !strings.Contains(v["output"].(string), "x-42") {
		t.Fatalf("user output %v", v)
	}
	ws.write(t, 0x9, "pi")
	if op, p := ws.read(t); op != 0xA || string(p) != "pi" {
		t.Fatalf("pong %x %q", op, p)
	}
	ws.write(t, 0x2, "exit\r")
	ws.until(t, "exit\r\n")
	waitGone := func(id string) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); ; {
			if st, _, _ := c.do("GET", "/api/terminals/"+id, nil); st == 404 {
				return
			}
			if time.Now().After(end) {
				t.Fatalf("terminal %s still there", id)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitGone(tid) // the shell exited
	ws.conn.Close()
	// A terminal ends with its WebSocket; DELETE ends one.
	tid = c.json("POST", "/api/terminals", nil, 200)["id"].(string)
	ws = dialACWS(t, base, "/api/terminals/"+tid, "u1", "s1")
	ws.write(t, 0x1, auth)
	ws.until(t, "$ ")
	ws.write(t, 0x8, "\x03\xe8")
	ws.conn.Close()
	waitGone(tid)
	tid = c.json("POST", "/api/terminals", nil, 200)["id"].(string)
	if v := c.json("DELETE", "/api/terminals/"+tid, nil, 200); v["status"] != "deleted" {
		t.Fatalf("delete terminal %v", v)
	}
	ws = dialACWS(t, base, "/api/terminals/"+tid, "u1", "s1")
	closed(ws, 4004, "Session not found")
	// Four terminals at most (AGENT_COMPANION_MAX_SESSIONS in Azaleva Cloud's unit).
	var ids []string
	for range acMaxTerms {
		ids = append(ids, c.json("POST", "/api/terminals", nil, 200)["id"].(string))
	}
	if st, _, b := c.do("POST", "/api/terminals", nil); st != 429 || string(b) != `{"error":"Maximum number of terminal sessions (4) reached"}` {
		t.Fatalf("a fifth terminal: %d %s", st, b)
	}
	for _, id := range ids {
		c.json("DELETE", "/api/terminals/"+id, nil, 200)
	}
}

// ---- a minimal WebSocket client ----

type acWS struct {
	conn net.Conn
	br   *bufio.Reader
	seen strings.Builder
}

func dialACWS(t *testing.T, base, path, user, session string) *acWS {
	t.Helper()
	u, _ := url.Parse(base)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte(randHex(8))[:16])
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: %s\r\nX-User-Id: %s\r\nX-Session-Id: %s\r\n\r\n", path, u.Host, key, user, session)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != WebSocketAccept(key) {
		t.Fatalf("upgrade %s: %v %v", path, resp, err)
	}
	return &acWS{conn: conn, br: br}
}

func (w *acWS) write(t *testing.T, op byte, payload string) {
	t.Helper()
	if err := WriteWebSocketFrame(w.conn, true, op, []byte(payload), true); err != nil {
		t.Fatal(err)
	}
}

func (w *acWS) read(t *testing.T) (byte, []byte) {
	t.Helper()
	_ = w.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, op, p, err := ReadWebSocketFrame(w.br)
	if err != nil {
		t.Fatalf("websocket read: %v (after %q)", err, w.seen.String())
	}
	return op, p
}

// until reads binary output frames until the output since the last call contains s.
func (w *acWS) until(t *testing.T, s string) string {
	t.Helper()
	var out strings.Builder
	for !strings.Contains(out.String(), s) {
		op, p := w.read(t)
		if op != 0x2 {
			t.Fatalf("a frame of op %x %q while waiting for %q (after %q)", op, p, s, out.String())
		}
		out.Write(p)
		w.seen.Write(p)
	}
	return out.String()
}
