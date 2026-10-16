package cloudtest

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// The fake machine's file system: in memory, the agent user's view (writable: /workspace,
// /home/agent, /tmp; elsewhere "Permission denied", as for the agent user on a real machine).

type acNode struct {
	dir  bool
	data []byte
	mod  time.Time
}

type acFS struct{ nodes map[string]*acNode }

func newACFS() *acFS {
	f := &acFS{nodes: map[string]*acNode{}}
	now := time.Now()
	for _, d := range []string{"/", "/etc", "/home", acUserHome, "/opt", "/opt/agent-companion", "/tmp", "/usr", acHome} {
		f.nodes[d] = &acNode{dir: true, mod: now}
	}
	f.nodes["/etc/hostname"] = &acNode{data: []byte(acHostname + "\n"), mod: now}
	return f
}

// acNormalize resolves "." and ".." lexically, as agent-companion does.
func acNormalize(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

// resolve makes p absolute against cwd ("" : the home).
func (f *acFS) resolve(p, cwd string) string {
	if strings.HasPrefix(p, "/") {
		return acNormalize(p)
	}
	if cwd == "" {
		cwd = acHome
	}
	return acNormalize(path.Join(cwd, p))
}

func (f *acFS) isDir(p string) bool  { n := f.nodes[p]; return n != nil && n.dir }
func (f *acFS) isFile(p string) bool { n := f.nodes[p]; return n != nil && !n.dir }
func (f *acFS) exists(p string) bool { return f.nodes[p] != nil }

// writable: what the agent user may change.
func (f *acFS) writable(p string) bool {
	for _, root := range []string{acHome, acUserHome, "/tmp"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

var (
	errACNotFound = acDetail(400, "No such file or directory (os error 2)")
	errACDenied   = acDetail(403, "Permission denied (os error 13)")
	errACIsDir    = acDetail(400, "Is a directory (os error 21)")
	errACNotDir   = acDetail(400, "Not a directory (os error 20)")
	errACExists   = acDetail(400, "File exists (os error 17)")
)

func (f *acFS) read(p string) ([]byte, error) {
	n := f.nodes[p]
	switch {
	case n == nil:
		return nil, errACNotFound
	case n.dir:
		return nil, errACIsDir
	}
	return n.data, nil
}

// text reads a file as UTF-8 text with CRLF and CR made LF (415 for other bytes).
func (f *acFS) text(p string) (string, error) {
	b, err := f.read(p)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", acDetail(415, "Invalid UTF-8")
	}
	return strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\r", "\n"), nil
}

func (f *acFS) mkdir(p string) error {
	if f.isDir(p) {
		return nil
	}
	if f.isFile(p) {
		return errACExists
	}
	if parent := path.Dir(p); parent != p {
		if err := f.mkdir(parent); err != nil {
			return err
		}
	}
	if !f.writable(p) {
		return errACDenied
	}
	f.nodes[p] = &acNode{dir: true, mod: time.Now()}
	return nil
}

func (f *acFS) write(p string, data []byte) error {
	if err := f.mkdir(path.Dir(p)); err != nil {
		return err
	}
	if f.isDir(p) {
		return errACIsDir
	}
	if !f.writable(p) {
		return errACDenied
	}
	f.nodes[p] = &acNode{data: bytes.Clone(data), mod: time.Now()}
	return nil
}

func (f *acFS) remove(p string) error {
	if !f.writable(p) {
		return errACDenied
	}
	for k := range f.nodes {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f.nodes, k)
		}
	}
	return nil
}

func (f *acFS) rename(src, dst string) error {
	if !f.writable(src) || !f.writable(dst) {
		return errACDenied
	}
	moved := map[string]*acNode{}
	for k, n := range f.nodes {
		if k == src || strings.HasPrefix(k, src+"/") {
			moved[dst+strings.TrimPrefix(k, src)] = n
			delete(f.nodes, k)
		}
	}
	for k, n := range moved {
		f.nodes[k] = n
	}
	return nil
}

// children are a directory's entry names, sorted.
func (f *acFS) children(dir string) []string {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var out []string
	for k := range f.nodes {
		if k != "/" && strings.HasPrefix(k, prefix) && !strings.Contains(k[len(prefix):], "/") {
			out = append(out, k[len(prefix):])
		}
	}
	sort.Strings(out)
	return out
}

func acJoin(dir, name string) string { return strings.TrimSuffix(dir, "/") + "/" + name }

// stat is agent-companion's {type, size, modified}.
func (f *acFS) stat(p string) map[string]any {
	n := f.nodes[p]
	if n == nil {
		return nil
	}
	typ, size := "file", len(n.data)
	if n.dir {
		typ, size = "directory", 4096
	}
	return map[string]any{"type": typ, "size": size, "modified": float64(n.mod.UnixNano()) / 1e9}
}

type acWalked struct{ path, kind string }

// walk lists a tree as agent-companion does: each directory's entries in name order, then
// its subdirectories.
func (f *acFS) walk(root string, hidden bool) []acWalked {
	var out []acWalked
	var rec func(string)
	rec = func(dir string) {
		var dirs []string
		for _, name := range f.children(dir) {
			if !hidden && strings.HasPrefix(name, ".") {
				continue
			}
			p := acJoin(dir, name)
			kind := "file"
			if f.isDir(p) {
				kind = "directory"
				dirs = append(dirs, p)
			}
			out = append(out, acWalked{p, kind})
		}
		for _, d := range dirs {
			rec(d)
		}
	}
	if f.isDir(root) {
		rec(root)
	}
	return out
}

// acLines splits text after each line break (the break kept), as Python's splitlines(True).
func acLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		end := -1
		switch r {
		case '\n', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u0085', ' ', ' ':
			end = i + n
		case '\r':
			end = i + n
			if end < len(s) && s[end] == '\n' {
				end++
			}
		}
		if end >= 0 {
			out = append(out, s[start:end])
			start, i = end, end
			continue
		}
		i += n
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// acMime guesses a type from a file name.
func acMime(p string) string {
	ext := strings.ToLower(path.Ext(p))
	if t, ok := map[string]string{".txt": "text/plain", ".md": "text/markdown", ".py": "text/x-python", ".sh": "application/x-sh",
		".json": "application/json", ".html": "text/html", ".htm": "text/html", ".css": "text/css", ".js": "text/javascript",
		".csv": "text/csv", ".xml": "text/xml", ".yaml": "text/x-yaml", ".yml": "text/x-yaml", ".png": "image/png",
		".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
		".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip", ".tar": "application/x-tar"}[ext]; ok {
		return t
	}
	return "application/octet-stream"
}

func (s *acServer) cwd(owner acOwner) string {
	if d, ok := s.cwds[owner.session]; ok {
		return d
	}
	return acHome
}

// files serves the /files routes and /skills (under s.mu).
func (s *acServer) files(w http.ResponseWriter, owner acOwner, route, method string, q acQuery, b map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.fs
	cwd := s.cwd(owner)
	relative := ""
	if owner.session != "" {
		relative = cwd
	}
	scoped := false
	switch route {
	case "/files/list", "/files/read", "/files/display", "/files/write", "/files/replace", "/files/grep", "/files/search",
		"/files/matches", "/files/glob":
		scoped = true
	}
	raw := q.str("path", ".")
	switch {
	case route == "/files/list":
		raw = q.str("directory", ".")
	case method == http.MethodPost:
		raw = acText(b, "path")
	}
	base := ""
	if scoped {
		base = relative
	}
	target := fs.resolve(raw, base)
	reply := func(v any) error { acReply(w, 200, v); return nil }
	switch {
	case method == http.MethodGet && route == "/files/cwd":
		return reply(map[string]any{"cwd": cwd, "home": acHome, "root": map[string]string{"path": acHome, "label": "Home"}})
	case method == http.MethodPost && route == "/files/cwd":
		if !fs.isDir(target) {
			return acDetail(404, "Directory not found")
		}
		if owner.session != "" {
			s.cwds[owner.session] = target
		}
		return reply(map[string]any{"cwd": target})
	case method == http.MethodGet && route == "/files/list":
		if !fs.isDir(target) {
			return acDetail(404, "Directory not found")
		}
		entries := []any{}
		for _, name := range fs.children(target) {
			p := acJoin(target, name)
			e := fs.stat(p)
			e["name"], e["writable"] = name, fs.writable(p)
			entries = append(entries, e)
		}
		return reply(map[string]any{"dir": target, "writable": fs.writable(target), "entries": entries})
	case method == http.MethodGet && route == "/files/display":
		return reply(map[string]any{"path": target, "exists": fs.isFile(target)})
	case method == http.MethodGet && route == "/files/read":
		if !fs.isFile(target) {
			return acDetail(404, "File not found")
		}
		data, _ := fs.read(target)
		if !utf8.Valid(data) {
			m := acMime(target)
			if strings.HasPrefix(m, "image") {
				acBinary(w, data, m)
				return nil
			}
			return acDetail(415, fmt.Sprintf("Unsupported binary file type: %s (%d bytes)", m, len(data)))
		}
		content := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
		l := acLines(content)
		start := min(max(int(q.num("start_line", 1))-1, 0), len(l))
		end := max(min(int(q.num("end_line", float64(len(l)))), len(l)), start)
		return reply(map[string]any{"path": target, "total_lines": len(l), "content": strings.Join(l[start:end], "")})
	case method == http.MethodGet && route == "/files/view":
		return s.view(w, target)
	case method == http.MethodGet && strings.HasPrefix(route, "/files/serve/"):
		return s.view(w, fs.resolve("/"+strings.TrimPrefix(route, "/files/serve/"), ""))
	case method == http.MethodPost && route == "/files/write":
		content := acText(b, "content")
		if err := fs.write(target, []byte(content)); err != nil {
			return err
		}
		return reply(map[string]any{"path": target, "size": len(content)})
	case method == http.MethodPost && route == "/files/mkdir":
		if err := fs.mkdir(target); err != nil {
			return err
		}
		return reply(map[string]any{"path": target})
	case method == http.MethodDelete && route == "/files/delete":
		if !fs.exists(target) {
			return acDetail(404, "Path not found")
		}
		kind := "file"
		if fs.isDir(target) {
			kind = "directory"
		}
		if err := fs.remove(target); err != nil {
			return err
		}
		return reply(map[string]any{"path": target, "type": kind})
	case method == http.MethodPost && route == "/files/move":
		src, dst := fs.resolve(acText(b, "source"), ""), fs.resolve(acText(b, "destination"), "")
		switch {
		case !fs.exists(src):
			return acDetail(404, "Source path not found")
		case !fs.isDir(path.Dir(dst)):
			return acDetail(400, "Destination parent directory not found")
		case fs.exists(dst):
			return acDetail(409, "Destination already exists")
		}
		if err := fs.rename(src, dst); err != nil {
			return err
		}
		return reply(map[string]any{"source": src, "destination": dst})
	case method == http.MethodPost && route == "/files/replace":
		return s.replace(w, target, b)
	case method == http.MethodPost && route == "/files/archive":
		return s.archive(w, b)
	case method == http.MethodGet && (route == "/files/grep" || route == "/files/glob" || route == "/files/search" || route == "/files/matches"):
		v, err := s.search(target, route, q)
		if err != nil {
			return err
		}
		return reply(v)
	case method == http.MethodGet && (route == "/skills" || route == "/skills/read"):
		v, err := s.skills(route, q)
		if err != nil {
			return err
		}
		return reply(v)
	}
	return acDetail(404, "Not Found")
}

func (s *acServer) view(w http.ResponseWriter, target string) error {
	if !s.fs.isFile(target) {
		return acDetail(404, "File not found")
	}
	data, _ := s.fs.read(target)
	acBinary(w, data, acMime(target))
	return nil
}

func (s *acServer) replace(w http.ResponseWriter, target string, b map[string]any) error {
	if !s.fs.isFile(target) {
		return acDetail(404, "File not found")
	}
	content, err := s.fs.text(target)
	if err != nil {
		return err
	}
	chunks, _ := b["replacements"].([]any)
	for _, x := range chunks {
		c, _ := x.(map[string]any)
		l := acLines(content)
		start := min(max(acInt(c["start_line"], 1)-1, 0), len(l))
		end := max(min(acInt(c["end_line"], len(l)), len(l)), start)
		region := strings.Join(l[start:end], "")
		needle := acText(c, "target")
		count := strings.Count(region, needle)
		if needle == "" {
			count = utf8.RuneCountInString(region) + 1
		}
		if count == 0 {
			r := []rune(needle)
			return acDetail(400, "Target string not found: "+acPyRepr(string(r[:min(len(r), 100)])))
		}
		if allow, _ := c["allow_multiple"].(bool); count > 1 && !allow {
			return acDetail(400, fmt.Sprintf("Found %d occurrences of target string but allow_multiple is false", count))
		}
		content = strings.Join(l[:start], "") + strings.ReplaceAll(region, needle, acText(c, "replacement")) + strings.Join(l[end:], "")
	}
	if err := s.fs.write(target, []byte(content)); err != nil {
		return err
	}
	acReply(w, 200, map[string]any{"path": target, "size": len(content)})
	return nil
}

func acInt(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case interface{ Int64() (int64, error) }:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return def
}

// acPyRepr quotes a string as Python's repr does (agent-companion's error messages).
func acPyRepr(s string) string {
	quote := '\''
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, c := range s {
		switch {
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == quote:
			b.WriteRune('\\')
			b.WriteRune(c)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteRune(quote)
	return b.String()
}

func (s *acServer) archive(w http.ResponseWriter, b map[string]any) error {
	paths, _ := b["paths"].([]any)
	if len(paths) == 0 {
		return acDetail(400, "No paths provided")
	}
	var targets []string
	for _, p := range paths {
		raw, _ := p.(string)
		t := s.fs.resolve(raw, "")
		if !s.fs.exists(t) {
			return acDetail(404, "Path not found: "+raw)
		}
		targets = append(targets, t)
	}
	name := "download"
	if len(targets) == 1 {
		name = path.Base(targets[0])
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, t := range targets {
		base := path.Base(t)
		type entry struct{ src, name string }
		var files []entry
		if s.fs.isFile(t) {
			files = append(files, entry{t, base})
		} else {
			for _, e := range s.fs.walk(t, true) {
				if e.kind == "file" {
					files = append(files, entry{e.path, base + "/" + strings.TrimPrefix(e.path, t+"/")})
				}
			}
		}
		for _, f := range files {
			fw, err := z.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate})
			if err != nil {
				return acDetail(500, err.Error())
			}
			data, _ := s.fs.read(f.src)
			_, _ = fw.Write(data)
		}
	}
	if err := z.Close(); err != nil {
		return acDetail(500, err.Error())
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".zip"))
	acBinary(w, buf.Bytes(), "application/zip")
	return nil
}

// acGlob matches as agent-companion's glob crate does with literal separators off: * and ?
// also match "/", [...] is a class ([!...] negated).
func acGlob(pattern, name string) bool {
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			re.WriteString(".*")
		case '?':
			re.WriteString(".")
		case '[':
			j := strings.IndexByte(pattern[i+1:], ']')
			if j < 0 {
				re.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : i+1+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			re.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += j + 1
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	ok, _ := regexp.MatchString(re.String(), name)
	return ok
}

func acRank(name, q string) int {
	switch {
	case name == q:
		return 0
	case strings.HasPrefix(name, q):
		return 1
	case strings.Contains(name, q):
		return 2
	}
	return 4
}

func (s *acServer) search(target, route string, q acQuery) (any, error) {
	fs := s.fs
	query := q.str("query", "")
	isGrep := route == "/files/grep"
	if isGrep && !fs.exists(target) {
		return nil, acDetail(404, "Search path not found")
	}
	if !isGrep && !fs.isDir(target) {
		return nil, acDetail(404, "Search directory not found")
	}
	maxN := int(q.num("max_results", 50))
	if isGrep {
		pattern := query
		if !q.flag("regex", true) {
			pattern = regexp.QuoteMeta(query)
		}
		if q.flag("case_insensitive", false) {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, acDetail(400, "Invalid regex: "+err.Error())
		}
		entries := []acWalked{{target, "file"}}
		if fs.isDir(target) {
			entries = fs.walk(target, true)
		}
		perLine := q.flag("match_per_line", true)
		include := q.all("include")
		out := []any{}
	files:
		for _, e := range entries {
			if e.kind != "file" {
				continue
			}
			name := path.Base(e.path)
			if fs.isDir(target) && len(include) > 0 && !acAnyGlob(include, name) {
				continue
			}
			content, err := fs.text(e.path)
			if err != nil {
				continue
			}
			for i, line := range strings.SplitAfter(content, "\n") {
				if line == "" || !re.MatchString(line) {
					continue
				}
				if perLine {
					out = append(out, map[string]any{"file": e.path, "line": i + 1, "content": strings.TrimRight(line, "\r\n")})
				} else {
					out = append(out, map[string]any{"file": e.path})
				}
				if len(out) >= maxN {
					break files
				}
				if !perLine {
					break
				}
			}
		}
		return map[string]any{"query": query, "path": target, "truncated": len(out) >= maxN, "matches": out}, nil
	}
	if route == "/files/glob" {
		pattern := q.str("pattern", "")
		excluded := q.all("exclude")
		typ := q.str("type", "any")
		out := []any{}
		for _, e := range fs.walk(target, true) {
			if typ != "any" && typ != e.kind {
				continue
			}
			rel, name := strings.TrimPrefix(e.path, target+"/"), path.Base(e.path)
			if !acGlob(pattern, rel) && !acGlob(pattern, name) {
				continue
			}
			if acAnyGlob(excluded, rel) || acAnyGlob(excluded, name) {
				continue
			}
			st := fs.stat(e.path)
			st["path"] = rel
			out = append(out, st)
			if len(out) >= maxN {
				break
			}
		}
		return map[string]any{"pattern": pattern, "path": target, "truncated": len(out) >= maxN, "matches": out}, nil
	}
	query = strings.TrimSpace(query)
	if route == "/files/matches" && query == "" {
		return nil, acDetail(400, "Query must not be blank")
	}
	lower := strings.ToLower(query)
	hidden := q.flag("show_hidden", false)
	entries := fs.walk(target, hidden)
	var content map[string][]any
	if route == "/files/matches" {
		content = s.contentMatches(entries, lower)
	}
	type ranked struct {
		r, n int
		rel  string
		v    map[string]any
	}
	var out []ranked
	typ := q.str("type", "any")
	for _, e := range entries {
		if route == "/files/search" && typ != "any" && typ != e.kind {
			continue
		}
		name, rel := path.Base(e.path), strings.TrimPrefix(e.path, target+"/")
		r := acRank(strings.ToLower(name), lower)
		if route == "/files/search" {
			if r == 4 && lower != "" {
				continue
			}
			v := fs.stat(e.path)
			v["path"], v["name"] = e.path, name
			if lower == "" {
				r = 2
			}
			out = append(out, ranked{r, utf8.RuneCountInString(name), strings.ToLower(rel), v})
			continue
		}
		if r == 4 && strings.Contains(strings.ToLower(rel), lower) {
			r = 3
		}
		c := content[e.path]
		if r == 4 && len(c) == 0 {
			continue
		}
		if c == nil {
			c = []any{}
		}
		out = append(out, ranked{r, utf8.RuneCountInString(rel), strings.ToLower(rel), map[string]any{"path": e.path,
			"relative_path": rel, "name": name, "type": e.kind, "name_match": r < 4, "content_matches": c}})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.r != b.r {
			return a.r < b.r
		}
		if a.n != b.n {
			return a.n < b.n
		}
		return a.rel < b.rel
	})
	offset, limit := 0, int(q.num("limit", 20))
	if route == "/files/matches" {
		offset, limit = int(q.num("offset", 0)), int(q.num("limit", 100))
	}
	results := []any{}
	for i := offset; i < len(out) && i < offset+limit; i++ {
		results = append(results, out[i].v)
	}
	if route == "/files/matches" {
		var next any
		if offset+limit < len(out) {
			next = offset + limit
		}
		return map[string]any{"results": results, "next_offset": next}, nil
	}
	return map[string]any{"results": results}, nil
}

func acAnyGlob(patterns []string, name string) bool {
	for _, p := range patterns {
		if acGlob(p, name) {
			return true
		}
	}
	return false
}

// contentMatches: up to three matching lines per file ({line, column, text}; the column in
// UTF-16 units, 1-based), files over 1 MiB or with a NUL in their first 8 KiB left out.
func (s *acServer) contentMatches(entries []acWalked, lower string) map[string][]any {
	out := map[string][]any{}
	for _, e := range entries {
		if e.kind != "file" {
			continue
		}
		raw, _ := s.fs.read(e.path)
		if len(raw) > 1<<20 || bytes.IndexByte(raw[:min(len(raw), 8192)], 0) >= 0 {
			continue
		}
		for i, line := range acLines(strings.ToValidUTF8(string(raw), "�")) {
			text := strings.TrimRight(line, "\r\n")
			idx := strings.Index(strings.ToLower(text), lower)
			if idx < 0 {
				continue
			}
			prefix := []rune(text)[:utf8.RuneCountInString(strings.ToLower(text)[:idx])]
			out[e.path] = append(out[e.path], map[string]any{"line": i + 1, "column": len(utf16.Encode(prefix)) + 1, "text": text})
			if len(out[e.path]) >= 3 {
				break
			}
		}
	}
	return out
}

// skills lists the SKILL.md files under the home's .agents, .cptr, .claude and .codex skill
// folders (name and description from their front matter).
func (s *acServer) skills(route string, q acQuery) (any, error) {
	skills := []any{}
	seen := map[string]bool{}
	for _, dir := range []string{".agents/skills", ".cptr/skills", ".claude/skills", ".codex/skills"} {
		root := acJoin(acHome, dir)
		for _, name := range s.fs.children(root) {
			p := acJoin(acJoin(root, name), "SKILL.md")
			if strings.HasPrefix(name, ".") || !s.fs.isDir(acJoin(root, name)) || !s.fs.isFile(p) {
				continue
			}
			src, err := s.fs.text(p)
			if err != nil {
				return nil, err
			}
			fm, body := acFrontMatter(src)
			n := strings.TrimSpace(fm["name"])
			if n == "" {
				n = name
			}
			desc := strings.TrimSpace(fm["description"])
			if desc == "" || seen[n] {
				continue
			}
			seen[n] = true
			skill := map[string]any{"id": "terminal:" + n, "name": n, "description": desc, "location": p, "scope": "global", "source": "terminal"}
			if route == "/skills/read" && q.str("name", "") == n {
				skill["content"], skill["resources"] = body, []any{}
				return skill, nil
			}
			skills = append(skills, skill)
		}
	}
	if route == "/skills/read" {
		return nil, acDetail(404, "Skill not found")
	}
	return skills, nil
}

func acFrontMatter(src string) (map[string]string, string) {
	fm := map[string]string{}
	rest, ok := strings.CutPrefix(src, "---\n")
	if !ok {
		return fm, src
	}
	head, body, ok := strings.Cut(rest, "\n---")
	if !ok {
		return fm, src
	}
	for _, line := range strings.Split(head, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fm[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return fm, strings.TrimPrefix(strings.TrimPrefix(body, "\n"), "\n")
}
