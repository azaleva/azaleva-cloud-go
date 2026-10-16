// Command quickstart creates a project, runs a job and starts a machine using only the Go SDK.
//
// By default it starts an in-process cloudtest server and sets up a consumer and an API key on
// it (what an installation's operators do once per consumer). With CLOUD_URL and CLOUD_API_KEY
// set it talks to a real installation instead and uses that key.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
	"github.com/azaleva/azaleva-cloud-go/cloud/cloudtest"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	url, key := os.Getenv("CLOUD_URL"), os.Getenv("CLOUD_API_KEY")
	if url == "" {
		srv := cloudtest.NewServer(cloudtest.Options{})
		defer srv.Close()
		url, key = srv.URL, provision(srv)
		fmt.Println("started an in-memory Azaleva Cloud at", url)
	}
	c, err := cloud.New(url, key)
	check(err)

	// A project, idempotent on the consumer's own ID for it.
	p, err := c.Projects.Create(ctx, cloud.ProjectCreate{Name: "quickstart", ExternalID: "quickstart"})
	check(err)
	fmt.Println("project", p.ID, "in pool", p.Pool)

	// A one-shot job on the built-in job template, smallest job profile.
	jobProfile := smallest(ctx, c, cloud.KindJob)
	j, err := c.Jobs.Create(ctx, cloud.JobCreate{
		Project: p.ID, Template: "cloud-job", Profile: jobProfile, TTLSeconds: 300,
		Egress: &cloud.EgressPolicy{Mode: cloud.EgressNone},
		Exec:   cloud.JobExec{Argv: []string{"sh", "-c", "echo hello from a job; printenv GREETING"}, SecretEnv: map[string]string{"GREETING": "hi"}},
		Labels: cloud.Labels{"example": "quickstart"},
	})
	check(err)
	out, err := c.Jobs.Output(ctx, j.ID, cloud.OutputOptions{})
	check(err)
	b, err := io.ReadAll(out) // follows the output until the job exits
	check(err)
	j, err = c.Jobs.Wait(ctx, j.ID)
	check(err)
	fmt.Printf("job %s: %s, output %q\n", j.ID, *j.Outcome, b)

	// A persistent machine, an exec and a file.
	m, err := c.Machines.Create(ctx, cloud.MachineCreate{Project: p.ID, Template: "computer-base", Profile: smallest(ctx, c, cloud.KindMachine)})
	check(err)
	m, err = c.Machines.WaitState(ctx, m.ID, cloud.MachineReady)
	check(err)
	_, err = c.Machines.WriteFile(ctx, m.ID, "/workspace/notes.txt", []byte("persisted"), cloud.FileOptions{})
	check(err)
	ex, err := c.Machines.Exec(ctx, m.ID, cloud.ExecRequest{Argv: []string{"cat", "/workspace/notes.txt"}})
	check(err)
	fmt.Printf("machine %s on %s: exec printed %q\n", m.ID, *m.Node, ex.Stdout)
	_, err = c.Machines.Delete(ctx, m.ID)
	check(err)
	fmt.Println("done")
}

// provision creates a consumer and an API key with every scope on the in-memory server.
func provision(srv *cloudtest.Server) string {
	id, err := srv.CreateConsumer(cloudtest.Consumer{Name: "quickstart", Pools: srv.Pools()[:1]})
	check(err)
	key, err := srv.CreateKey(id, "")
	check(err)
	return key
}

func smallest(ctx context.Context, c *cloud.Client, kind cloud.TemplateKind) string {
	ps, err := c.Profiles.List(ctx, kind)
	check(err)
	best := ps[0]
	for _, p := range ps {
		if p.MemoryMiB < best.MemoryMiB {
			best = p
		}
	}
	return best.Name
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
