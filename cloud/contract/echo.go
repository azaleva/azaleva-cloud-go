package contract

import (
	_ "embed"
	"fmt"
)

// echoPy is the echo service of the real-recipe machine template (echo.py).
//
//go:embed echo.py
var echoPy []byte

// EchoPy is the echo service itself (echo.py), for other live checks.
func EchoPy() []byte { return echoPy }

// EchoRecipe is echoRecipe for other live checks (the transport's acceptance and benchmarks).
func EchoRecipe(port int) map[string][]byte { return echoRecipe(port) }

// echoRecipe is a real machine recipe (Env.RealRecipes) that serves echo.py on port as a
// systemd service of the agent user, started with the machine: cloudtest.EchoHandler's
// behaviour behind the real transport and a real guest.
func echoRecipe(port int) map[string][]byte {
	unit := fmt.Sprintf(`[Unit]
Description=the contract suite's echo service
After=network.target

[Service]
User=agent
ExecStart=/usr/local/bin/python3 /opt/svc-echo/echo.py %d
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`, port)
	recipe := `# the contract suite's echo machine (cloud/contract/echo.go)
KIND = "machine"


def template(ctx):
    from e2b import Template

    return (
        Template(file_context_path=ctx)
        .from_image("python:3.12-slim")
        .set_user("root")
        .copy("echo.py", "/opt/svc-echo/echo.py")
        .copy("svc-echo.service", "/etc/systemd/system/svc-echo.service")
        .run_cmd("id agent >/dev/null 2>&1 || useradd --uid 10001 --user-group --create-home --home-dir /home/agent --shell /bin/bash agent;"
                 " mkdir -p /workspace && chown agent:agent /workspace && chmod 0755 /workspace"
                 " && chmod 0644 /opt/svc-echo/echo.py /etc/systemd/system/svc-echo.service"
                 " && mkdir -p /etc/systemd/system/multi-user.target.wants"
                 " && ln -sf /etc/systemd/system/svc-echo.service /etc/systemd/system/multi-user.target.wants/svc-echo.service")
        .set_user("agent")
        .set_workdir("/workspace")
    )
`
	return map[string][]byte{"recipe.py": []byte(recipe), "echo.py": echoPy, "svc-echo.service": []byte(unit)}
}
