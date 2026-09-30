# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Kubewarden Runtime Enforcer is a Kubernetes security tool that uses eBPF to
observe process executions in workloads and enforce allow-list based
security policies at the kernel level. It has three phases: **Learn**
(generate `WorkloadPolicyProposal`), **Monitor** (report violations), and
**Protect** (block violating executions).

Module: `github.com/kubewarden/runtime-enforcer` (Go 1.27.1).

## Code Layout

- `api/`: Go types for the `WorkloadPolicy` and `WorkloadPolicyProposal` CRDs.
- `bpf/`: C source of the eBPF programs.
- `charts/`: Helm chart for deployment.
- `cmd/`: main entry points for `agent`, `controller`, `debugger`, and
  `kubectl-plugin` executables.
- `docs/`: developer docs, generated CRD reference, RFCs.
- `hack/`: helper scripts and Tilt Dockerfiles.
- `internal/`: private Go implementation packages used by the executables.
- `pkg/generated`: generated Kubernetes clientset, informers, listers.
- `proto/`: gRPC API between the agent and other components.
- `test/e2e/`: end-to-end tests using a real Kubernetes cluster (Docker + Kind).
- `updatecli/`: automation that bumps dependencies and the Helm chart.

## Build

```sh
make controller   # builds bin/controller
make agent        # builds bin/agent
make debugger     # builds bin/debugger
make kubectl-plugin        # current platform
make kubectl-plugin-cross  # all supported platforms
```

Each of these targets runs `generate-ebpf` first, so eBPF objects must be
(re)generated before compiling Go code that depends on them.

Requires clang, llvm, libbpf and libelf to compile eBPF programs in `bpf/`
(Debian/Ubuntu: `clang`, `llvm`, `libbpf-dev`, `libelf-dev`,
`build-essential`).

## Test

```sh
make generate-ebpf          # required before running Go tests
make test                   # unit tests (excludes test/e2e and internal/bpf)
make test-bpf               # eBPF tests, needs sudo
make helm-unittest          # Helm chart tests (helm-unittest plugin)
make test-e2e               # end-to-end tests against a Kind cluster
```

`make test` requires `setup-envtest` binaries (handled by the `test` target)
and writes coverage to `coverage/cover.out`.

## Lint / Format

All linters run through [pre-commit](https://pre-commit.com/); CI runs the
same hooks.

```sh
make generate-ebpf                          # Go linter needs generated eBPF objects
pre-commit run --all-files                  # run every linter
make fmt                                    # go fmt
make vet                                    # go vet
pre-commit run golangci-lint-full --all-files   # Go linter
pre-commit run clang-format --all-files     # format eBPF C code
pre-commit run clang-tidy --all-files       # lint eBPF C code
pre-commit run protolint --all-files        # lint .proto files
```

## Code Generation

```sh
make generate   # runs manifests, generate-ebpf, generate-proto, generate-api,
                 # generate-crd-docs, generate-chart, generate-kubectl-plugin-docs
```

Run `make generate` (or the specific sub-target) after changing CRD types,
`.proto` files, RBAC markers, or values schema, and commit the regenerated
output alongside the source change.

## Conventions

- Follow the global [Kubewarden CONTRIBUTING guidelines](https://github.com/kubewarden/community/blob/main/CONTRIBUTING.md)
  and [AI usage policy](https://github.com/kubewarden/community/blob/main/AI_POLICY.md).
- Go code is scaffolded with kubebuilder (`go.kubebuilder.io/v4`); CRD group
  is `runtimeenforcer.kubewarden.io`.
- Commit messages are linted with commitlint (`commitlint.config.js`) —
  follow Conventional Commits.
- Sign off commits (`git commit -s`).
- Never add code without running the relevant `make`/`pre-commit` targets
  above before considering a change complete.

## Code Review

When reviewing a change (PR, diff, or patch), check for:

- **Correctness**: logic errors, edge cases, race conditions, resource leaks
  (missing `defer` cleanup), and error handling (no discarded errors, use
  `errors.Is` for comparisons).
- **Tests**: new/changed behavior is covered; `make test`, `make test-bpf`,
  and `make helm-unittest` still pass as applicable.
- **Generated code**: any change to CRD types, `.proto` files, RBAC markers,
  or the Helm values schema is followed by `make generate` with the
  regenerated output committed.
- **Lint/format**: code passes `make fmt`, `make vet`, and the relevant
  `pre-commit run <hook> --all-files` targets.
- **Documentation**: README, `CONTRIBUTING.md`, CRD docs, and this file are
  updated when behavior, commands, or layout change.

### Breaking Changes

- Explicitly identify any breaking change: changes to CRD schemas/fields,
  Helm chart `values.yaml` keys, gRPC/proto messages, CLI flags, or exported
  Go APIs that are incompatible with previous versions.
- Confirm the PR description calls out the breaking change and any required
  migration steps.
- **Commit message**: verify it follows
  [Conventional Commits](https://www.conventionalcommits.org/) semver
  rules — a breaking change must have `!` right after the type/scope in the
  title (e.g. `feat!: drop support for v1alpha1` or
  `fix(api)!: rename field X to Y`), and/or a `BREAKING CHANGE:` footer in
  the body. Commit messages are linted with commitlint
  (`commitlint.config.js`, extends `@commitlint/config-conventional`) —
  a missing `!` on a breaking change will not be caught by commitlint itself,
  so reviewers must check it manually.
