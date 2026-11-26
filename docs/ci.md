# What CI actually runs, and how to check that it did

A workflow file proves what was *declared*. A check-run proves what *ran*. This
document exists because those two drifted apart once in this project family: a CI
gate listed a package that a build tag had excluded, so the job reported `ok`
over a package that contributed neither a PASS nor a SKIP. Green, and about
nothing.

Everything below was read from the check-runs API, not from the YAML.

## The two jobs

| job | steps that do work | what each one proves |
|---|---|---|
| `test` | Format, Vet, Test (no skips), Race, Zero dependencies, Cross-compile, README commands, Exit-code contract, JSON is machine-readable | the code builds on 5 platforms, every test runs (a SKIP fails the job), the CLI's exit codes and JSON shape hold when run as a real binary |
| `lint` | golangci-lint v2.12.2 via `golangci-lint-action@v8` | static analysis at the same version developers run locally |

`test` is the long one. The steps are ordered so that a cheap failure happens
first: `Format` and `Vet` take seconds, and `Cross-compile` — the most expensive
at ~36s — only runs once the suite is green.

## Reading a run

```bash
# the run for a commit, then its jobs and steps
gh api repos/atop0914/portwhy/commits/<sha>/check-runs \
  --jq '.check_runs[] | {name, status, conclusion}'

RUN=$(gh api "repos/atop0914/portwhy/actions/runs?per_page=1" --jq '.workflow_runs[0].id')
gh api "repos/atop0914/portwhy/actions/runs/$RUN/jobs" \
  --jq '.jobs[] | {name, conclusion, steps: [.steps[] | {name, conclusion, started_at, completed_at}]}'
```

Step timestamps are the evidence that a step ran rather than being skipped by a
condition: a skipped step has no `started_at`.

## The measurement this repository was built on (2026-11-25, `29ca163`)

Run [45616595509](https://github.com/atop0914/portwhy/actions/runs/45616595509):
both jobs `success`, total 83 seconds.

| job | step | duration |
|---|---|---|
| test | Format | <1s |
| test | Vet | 12s |
| test | Test (no skips) | 6s |
| test | Race | 16s |
| test | Zero dependencies | <1s |
| test | Cross-compile (5 platforms + darwin vet) | 36s |
| test | Exit-code contract | 6s |
| test | JSON is machine-readable | <1s |
| lint | golangci-lint | 12s |

Two things worth keeping from those numbers:

- **`-race` has room.** It runs with no explicit timeout, so Go's default of 600s
  applies, and the suite finishes in 16s — about 37× margin. The number that
  matters is not the margin but its trend: this suite has real sockets and
  subprocess fixtures, which is where a race run starts to grow. If it ever
  passes a few minutes, the cause is a test that is waiting on a real network or
  a sleep, not a slow machine.
- **`Test (no skips)` is 6s because every test is local.** No test dials a real
  host, and none waits on a DNS lookup. A suite that reaches the network is the
  one that starts failing on a runner with a different resolver.

## The failure mode this document is about

The four commits of Day 10 (`926a043`, `7b55675`, `64fef3e`, `29ca163`) were all
green on both jobs, so there was nothing to attribute this time.

The shape to look for when several commits are red at once: **one root cause or
four flakes?** In an earlier project on this same template, four consecutive
commits were red in `lint` for the same unused variable — one cause, four
appearances, and reading the first failure would have fixed all four. A flake, by
contrast, disappears when the same SHA is re-run. That is the discriminator: a
re-run of the identical commit, not a look at the diff.

## What is deliberately not a CI gate

- **`make fuzz`** — a fuzz run finds inputs by chance; a green run says nothing
  about what it did not try. The deterministic part is the corpus under
  `testdata/fuzz/`, which `go test` replays.
- **The benchmarks** (`docs/design.md`, "What a round costs") — runner noise is
  larger than the regression they would catch, so an absolute threshold there
  would be a false alarm generator. They are recorded, not asserted.
- **`external` network access** — nothing here needs it, and a test that does is
  a test that fails for a reason unrelated to the code.
