# The mock driver (cloudtest)

`cloudtest` has no real machines: programs of jobs and execs run in a **mock driver**, a tiny
command language. On a real installation the same programs are real commands (`echo`, `cat`,
`sleep`, `printenv`, `id`, `hostname` behave the same), so tests written against `cloudtest`
keep their meaning. The contract suite (`cloud/contract`) uses only these commands.

## Programs

A program is `argv`, or `["sh", "-c", "<script>"]`, or an exec's `shell` string. A script is
commands separated by `;`, each split on whitespace (no quoting). Commands run in order; the
exit code is the last command's. Output is appended to the journal as each command runs, so a
`sleep` between two `echo`s makes output arrive while the program runs.

| Command | Effect |
|---|---|
| `echo <words…>` | the words and a newline on stdout |
| `cat` | stdin to stdout |
| `cat <path>`, `cat-file <path>` | the file's content (exit 1 with a message on stderr if missing or not readable by the user) |
| `printenv <NAME>` | the variable and a newline; exit 1 if unset (`secret_env` is visible here, only to the program; an exec's `CLOUD_EXEC_ID` is its exec ID) |
| `true`, `false`, `exit <n>` | exit 0, 1, n |
| `sleep <seconds>` | wait (fractions allowed); cancel, TTL, lease and the exec timeout interrupt it |
| `seq <n>` | the lines 1 … n |
| `emit <n> <size>` | n lines of `size` × `x` (for output limits and `framing: lines`) |
| `stderr <words…>` | the words on stderr |
| `write <path> <words…>` | write a file as the program's user (rules below) |
| `whoami`, `id` | `agent`/`root` and `10001`/`0` (a supervised job prints its uid) |
| `hostname` | the machine's hostname (`sandbox` for sandboxes and jobs) |
| anything else | `mock: <cmd>: command not found` on stderr, exit 127 |

The built-in templates of a real installation ship `emit`, `stderr`, `write` and `cat-file` as
small helpers, so the same programs run there unchanged.

## Users and files

- Machine and sandbox execs run as `agent` (uid 10001) or `root`. A supervised job runs as
  `supervisor.uid` (default 10001); `supervisor: "none"` runs as root.
- Job `files` owned by `root` are readable by a non-root program only if the mode's "other read"
  bit is set (`0400` is unreadable, `0444` readable); `owner: user` files belong to the program.
- `agent` may write under `/workspace`, `/home/agent` and `/tmp`, nowhere else, and never inside
  a read-only tree (`files/tree`, root-owned); root may write anywhere except in a tree.
- A machine restart with the `fresh_template` policy (the on-demand default) keeps `/workspace`
  only; `keep_disk` (the always-on default) keeps the whole disk; a migration keeps everything.

## Deterministic failures

| Trigger | Result |
|---|---|
| a job egress allowlist with a domain ending in `.refuse-binding.test` | the binding fails: outcome `refused`, reason `egress_binding` |
| a template package whose recipe contains `# mock: build-fail` | every build fails; the template is `failed`; creates answer `409 template_not_ready` |
| a pool without schedulable nodes (or without room) | `409 capacity_exhausted` (retryable) |

## Seed content

| Kind | Content |
|---|---|
| Pools and nodes | `default`: `node-1`, `node-2`; `spare`: `node-3` (64 GiB, 32 job slots each, IPv6 blocks `2001:db8:N::/64`); `Options.Nodes` replaces them |
| Profiles | `job-small`, `job-large` (kind `job`, egress up to `allowlist`); `machine-small` (modes `on_demand` and `always_on`), `machine-large` (kind `machine`, egress up to `internet`); 8 concurrent execs and 4 terminals per instance; `Options.Profiles` adds or replaces |
| Built-in templates | `cloud-job@1` (job), `computer-base@1` (machine), ready on every node |
| Built-in presets | `github`, `pypi` |
| Consumers | none: create them with `Server.CreateConsumer` (see Setup) |

The contract suite does not depend on these names: its Provisioner names the pools, and it
discovers the smallest profile of each kind and a ready built-in template of each kind.

## Setup

What an installation's operators do, and the consumer API cannot, is a Go method on the
`Server` (not an HTTP route):

| Method | Effect |
|---|---|
| `CreateConsumer(cloudtest.Consumer{…})` | a consumer (its pools, allowed profiles and templates); returns its ID |
| `CreateKey(consumer, project, scopes…)` | an API key (`ack_<id>_<secret>`); no scopes: every scope; a project pins it |
| `RevokeKey(key)` | revokes a key at once (its tickets' connections close) |
| `DisableConsumer(id)` | the consumer's keys stop working |
| `SetConsumerPools(id, pools…)`, `SetCeilings(id, quotas)` | the consumer's pools and ceilings |
| `AddTemplateSigner(id, pub, names…)` | a key that may sign the consumer's template packages |
| `SetWebhook(id, url)` | posts the consumer's events to url; returns the signing secret |
| `Pools()`, `CreatePool(name)`, `SetNodePool(node, pool)` | pools and the nodes in them |
| `KillInstance(id, reason)` | kills a job, sandbox or machine as an operator would (outcome `killed/operator`, event `machine.operator_action`) |

## Test hooks

- `Server.Advance(d)` moves the clock: TTLs, leases, terminal timeouts, usage hours, event and
  output retention, reference report age, ticket expiry (`Server.Now()` reads it).
- The service transport's test hooks: see the Azaleva Cloud documentation.
- The service transport's hooks are in [Service transport](SERVICE-TRANSPORT.md#testing-with-cloudtest).
- With `CLOUDTEST_LOG` set, `cloudtest.Start(t)` logs every request to the test.
