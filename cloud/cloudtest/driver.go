package cloudtest

import (
	"strconv"
	"strings"
	"time"
)

// The mock driver: a tiny command language instead of real machines (see docs/MOCK-DRIVER.md). A
// program is argv, or "sh -c <script>", or a shell string; a script is commands separated by ";".

type mockCmd struct{ argv []string }

func parseProgram(argv []string, shell string) []mockCmd {
	script := shell
	if script == "" {
		if len(argv) >= 3 && (argv[0] == "sh" || argv[0] == "/bin/sh") && argv[1] == "-c" {
			script = argv[2]
		} else {
			return []mockCmd{{argv: argv}}
		}
	}
	var out []mockCmd
	for _, part := range strings.Split(script, ";") {
		if f := strings.Fields(part); len(f) > 0 {
			out = append(out, mockCmd{argv: f})
		}
	}
	return out
}

// procEnv is what a mock command may touch.
type procEnv struct {
	stdin    []byte
	env      map[string]string
	user     string // agent, root, or "uid:<n>" for a supervised job
	readFile func(path, user string) ([]byte, string)
	write    func(path string, data []byte, user string) string
	hostname string
}

// step is the result of one command: output to append, an optional wait, and the exit code.
type step struct {
	stdout, stderr []byte
	sleep          time.Duration
	exit           int
}

func runMock(cmd mockCmd, e *procEnv) step {
	a := cmd.argv
	arg := func(i int) string {
		if i < len(a) {
			return a[i]
		}
		return ""
	}
	switch a[0] {
	case "echo":
		return step{stdout: []byte(strings.Join(a[1:], " ") + "\n")}
	case "cat":
		if len(a) == 1 {
			return step{stdout: e.stdin}
		}
		fallthrough
	case "cat-file":
		b, errMsg := e.readFile(arg(1), e.user)
		if errMsg != "" {
			return step{stderr: []byte(a[0] + ": " + arg(1) + ": " + errMsg + "\n"), exit: 1}
		}
		return step{stdout: b}
	case "printenv":
		v, ok := e.env[arg(1)]
		if !ok {
			return step{exit: 1}
		}
		return step{stdout: []byte(v + "\n")}
	case "true":
		return step{}
	case "false":
		return step{exit: 1}
	case "exit":
		n, _ := strconv.Atoi(arg(1))
		return step{exit: n}
	case "sleep":
		f, err := strconv.ParseFloat(arg(1), 64)
		if err != nil || f < 0 {
			return step{stderr: []byte("sleep: invalid time\n"), exit: 1}
		}
		return step{sleep: time.Duration(f * float64(time.Second))}
	case "seq":
		n, _ := strconv.Atoi(arg(1))
		var b strings.Builder
		for i := 1; i <= n; i++ {
			b.WriteString(strconv.Itoa(i) + "\n")
		}
		return step{stdout: []byte(b.String())}
	case "emit":
		n, _ := strconv.Atoi(arg(1))
		size, _ := strconv.Atoi(arg(2))
		line := strings.Repeat("x", size) + "\n"
		return step{stdout: []byte(strings.Repeat(line, n))}
	case "stderr":
		return step{stderr: []byte(strings.Join(a[1:], " ") + "\n")}
	case "write":
		if msg := e.write(arg(1), []byte(strings.Join(a[2:], " ")), e.user); msg != "" {
			return step{stderr: []byte("write: " + arg(1) + ": " + msg + "\n"), exit: 1}
		}
		return step{}
	case "whoami":
		u := e.user
		if strings.HasPrefix(u, "uid:") {
			u = "agent"
		}
		return step{stdout: []byte(u + "\n")}
	case "id":
		uid := "10001"
		switch {
		case e.user == "root":
			uid = "0"
		case strings.HasPrefix(e.user, "uid:"):
			uid = strings.TrimPrefix(e.user, "uid:")
		}
		return step{stdout: []byte(uid + "\n")}
	case "hostname":
		return step{stdout: []byte(e.hostname + "\n")}
	}
	return step{stderr: []byte("mock: " + a[0] + ": command not found\n"), exit: 127}
}
