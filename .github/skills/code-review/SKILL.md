---
name: code-review
description: Use when reviewing a pull request, diff, or patch in the kubewarden/runtime-enforcer repository — covers generic review checks plus breaking-change and commit message (semver `!`) verification.
---

# Code Review

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
- **Documentation**: README, `CONTRIBUTING.md`, CRD docs, and `AGENTS.md` are
  updated when behavior, commands, or layout change.

## Breaking Changes

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
