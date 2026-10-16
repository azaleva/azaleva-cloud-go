# Azaleva Cloud Go SDK

The Go client of the Azaleva Cloud API: run jobs, sandboxes and persistent machines for your
agents and apps, with execs, files, terminals, egress control and service access. Standard
library only.

```sh
go get github.com/azaleva/azaleva-cloud-go@latest
```

| Package | Contents |
|---|---|
| `cloud` | the client: projects, jobs, machines, templates, services, operations, events, webhooks |
| `cloud/cloudtest` | an in-memory implementation of the API for tests (`cloudtest.Start(t)`) |
| `cloud/contract` | the contract suite every implementation (`cloudtest`, Azaleva Cloud's server) must pass |

## Use

```go
c, _ := cloud.New("https://cloud.azaleva.net", os.Getenv("CLOUD_API_KEY"))
p, _ := c.Projects.Create(ctx, cloud.ProjectCreate{Name: "acme", ExternalID: "ws_123"})
j, _ := c.Jobs.Create(ctx, cloud.JobCreate{
	Project: p.ID, Template: "worker@3", Profile: "job-small", TTLSeconds: 1800,
	Exec: cloud.JobExec{Argv: []string{"/app/run"}},
}, cloud.WithIdempotencyKey("my-run-41"))
out, _ := c.Jobs.Output(ctx, j.ID, cloud.OutputOptions{}) // resumable io.Reader
```

See [`examples/quickstart`](examples/quickstart) for a complete program against `cloudtest`.

### Errors, waiting and the HTTP client

- Every API error is a `*cloud.Error` (`cloud.AsError`, `cloud.IsCode`, `cloud.IsRetryable`).
  An answer that is not Azaleva Cloud's problem document (a proxy in between) becomes an `Error`
  with an empty `Type` and a code derived from its status (401 `unauthenticated`, 403
  `forbidden`, 404 `not_found`, 409 `conflict`, 410 `gone`, 412 `precondition_failed`, 429
  `rate_limited`, 408/502/503/504 `unavailable`, other 5xx `internal`, else `invalid_request`).
- `Machines.WaitState` polls until the machine is in one of the states asked for; it returns
  early with an error wrapping `cloud.ErrMachineState` (and the machine) when the machine is
  `destroyed` or `error` and that state was not asked for.
- `cloud.New` uses an HTTP client of its own whose transport waits at most
  `cloud.DefaultResponseHeaderTimeout` (330 s) for response headers, with no overall timeout
  (streams last as long as they need). `cloud.WithHTTPClient` replaces it (mTLS, proxies, your
  own bounds); give calls a context deadline for anything tighter.

## Guides

- [Mock driver](docs/MOCK-DRIVER.md): the command language programs use in `cloudtest`, its
  file rules, deterministic failures, seed content and test hooks.

## Versions

Tags are `vX.Y.Z`. While the API is pre-1.0 (`cloud.Version`, the version of the API document the
SDK implements, is sent in the User-Agent), the module stays at v0.x and a minor bump may break
callers; the changelog of each release says how. v0.5.0 is the first public release under
this module path.

## Testing your code

`cloudtest.Start(t)` runs the API in memory, with a [mock driver](docs/MOCK-DRIVER.md)
instead of real machines; the contract suite (`cloud/contract`) is what keeps it faithful to
the real server. Plain Go methods set up what the API cannot: consumers and their keys, pools
and nodes.

```go
srv := cloudtest.Start(t)
id, _ := srv.CreateConsumer(cloudtest.Consumer{Name: "acme"})
key, _ := srv.CreateKey(id, "") // every scope
c, _ := cloud.New(srv.URL, key)
```

```sh
go vet ./... && go test -race ./...
```

## License

Apache License 2.0: see [LICENSE](LICENSE).
