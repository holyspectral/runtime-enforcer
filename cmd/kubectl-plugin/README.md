# kubectl runtime-enforcer

Kubernetes plugin for SUSE Security Runtime Enforcer.

## Usage

- `kubectl runtime-enforcer` or `kubectl runtime-enforcer -h/--help` — show help
- `kubectl runtime-enforcer -v/--version` — print version

## Installation

### Download a pre-built binary

Pre-built binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`, and `darwin/arm64`
are attached to every [GitHub Release](../../releases).

```bash
# Example: linux/amd64
VERSION=v0.1.0
curl -Lo kubectl-runtime_enforcer \
  "https://github.com/rancher-sandbox/runtime-enforcer/releases/download/${VERSION}/kubectl-runtime_enforcer-linux-amd64"
chmod +x kubectl-runtime_enforcer
sudo mv kubectl-runtime_enforcer /usr/local/bin/
```

Verify the download with the accompanying `.sha256` file:

```bash
sha256sum --check kubectl-runtime_enforcer-linux-amd64.sha256
```

### Build from source

```bash
# Current platform
make kubectl-plugin          # output: bin/kubectl-runtime_enforcer
# All supported platforms at once
make kubectl-plugin-cross    # output: bin/kubectl-plugin/kubectl-runtime_enforcer-<os>-<arch>
```
