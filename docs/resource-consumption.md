# Runtime Enforcer — Resource Consumption

This document provides measured resource consumption data for the runtime enforcer agent to help with capacity planning.

All measurements were collected with [hack/bench/bench.py](../hack/bench/bench.py). See [Reproducing the benchmark](#reproducing-the-benchmark) for instructions.

## Environment

| Field | Value |
|-------|-------|
| Enforcer chart | runtime-enforcer-0.1.7 |
| Agent version | v0.5.0 |
| Agent image | ghcr.io/rancher-sandbox/runtime-enforcer/agent:latest |
| Kubernetes | v1.32.0 |
| Kernel | 6.17.0-22-generic |
| OS (node) | Debian GNU/Linux 12 (bookworm) |
| Container runtime | containerd 2.2.1 |
| Node CPU capacity | 16 vCPUs |
| Node memory capacity | ~14.4 GiB |

## 1. Idle Baseline

Agent sampled every 30 s for 60 s with no workload pods.

| Metric | Value |
|--------|-------|
| CPU avg | 1m |
| CPU max | 1m |
| RSS avg | 123 MiB |
| RSS max | 123 MiB |

## 2. Pod Scaling

Pause pods (`registry.k8s.io/pause:3.10`) deployed in a dedicated namespace. Agent metrics sampled for 30 s after each batch stabilises.

> **Note:** The single-node minikube cluster tested here has a pod limit of ~110. At the 100-pod mark, 94/100 pods were scheduled due to system pods occupying the remaining slots. Production multi-node clusters distribute pods across nodes and are not subject to this constraint.

| Pod count | CPU avg (m) | CPU max (m) | RSS avg (MiB) | RSS max (MiB) |
|-----------|-------------|-------------|---------------|---------------|
| 10 | 1 | 1 | 123 | 123 |
| 50 | 2 | 2 | 123 | 123 |
| 100 | 1 | 1 | 121 | 121 |

Memory footprint is largely flat across pod counts because the agent tracks containers via eBPF maps that are pre-allocated at a fixed size (see [§4](#4-ebpf-map-footprint)).

## 3. Policy Scaling

One `WorkloadPolicy` CR and one labeled pod are created per step (cumulative). eBPF map entry counts are read via `bpftool` after each batch is Running.

- **cg\_to\_policy\_map**: keyed by container cgroup ID — one entry per running container with an active policy assignment.
- **policy\_mode\_map**: keyed by policy ID — one entry per unique policy assigned to at least one running container.

Both maps are pre-allocated (`max_entries = 65536`) so `memlock` does not grow with entry count; only the populated key count grows.

| Policy count | cg\_to\_policy\_map entries | policy\_mode\_map entries |
|--------------|--------------------------|--------------------------|
| 1 | 1 | 1 |
| 5 | 5 | 5 |
| 10 | 10 | 10 |
| 20 | 20 | 20 |

Entries scale linearly with policy count (O(N)), with no observable RSS growth — confirming that map memory is statically reserved rather than dynamically grown.

## 4. eBPF Map Footprint

Map metadata as reported by `bpftool map show`. `memlock` is an upper bound on the kernel memory reserved for the map; hash maps are pre-allocated so `memlock` does not grow with entry count.

| Map name | Type | Key (B) | Value (B) | max\_entries | memlock (KiB) |
|----------|------|---------|-----------|-------------|---------------|
| cgtracker\_map | hash | 8 | 8 | 65 536 | 1 026 |
| cg\_to\_policy\_ma | hash | 8 | 8 | 65 536 | 1 025 |
| process\_evt\_sto | percpu\_array | 4 | 12 304 | 1 | 192 |
| ringbuf\_logs | ringbuf | — | — | 16 777 216 | 16 460 |
| pol\_str\_maps\_\* (×11) | hash\_of\_maps | 8 | 4 | 65 536 | 1 025 each |
| policy\_mode\_map | hash | 8 | 1 | 65 536 | 1 025 |
| ringbuf\_monitor | ringbuf | — | — | 16 777 216 | 16 460 |
| ringbuf\_execve | ringbuf | — | — | 16 777 216 | 16 460 |

Total kernel `memlock` per agent instance: ~**72 MiB** (dominated by the three 16 MiB ring buffers and eleven `pol_str_maps_*` hash-of-maps).

> BPF map names are truncated to 15 characters by the kernel (`BPF_OBJ_NAME_LEN = 16` including the null terminator). Full names are defined in [`bpf/main.c`](../bpf/main.c).

## 5. Hot-Path Overhead

A test pod runs `for i in $(/usr/bin/seq 5000); do /usr/bin/true; done` (via `/usr/bin/dash`) and wall-clock time is measured **inside the container** using `date +%s%N`, excluding kubectl API server and network round-trip overhead:

> **Note:** On Ubuntu 22.04, `/bin` is a symlink to `usr/bin`. The benchmark uses absolute `/usr/bin/` paths because the enforcer resolves the canonical executable path when evaluating policies. The `WorkloadPolicy` allowlist entries must use these resolved paths.

- **no-policy**: pod has no `WorkloadPolicy` label
- **monitor**: pod references a `WorkloadPolicy` in Monitor mode
- **protect**: pod references a `WorkloadPolicy` in Protect mode

| Mode | Run 1 (s) | Run 2 (s) | Run 3 (s) | Avg (s) |
|------|-----------|-----------|-----------|---------|
| no-policy | 2.778 | 2.813 | 2.811 | 2.801 |
| monitor | 2.797 | 2.823 | 2.807 | 2.809 |
| protect | 2.783 | 2.791 | 2.817 | 2.797 |

All three modes are within ~1% of each other — within normal measurement variance for a shared minikube VM. No statistically significant overhead is detected for this exec-heavy workload.

## 6. T-Shirt Sizing

The table below gives suggested Kubernetes resource requests and limits for the agent DaemonSet, derived from the §2 pod-scaling measurements:
- CPU request = max(observed avg × 2, 5) m
- CPU limit = max(observed avg × 10, 50) m
- Memory request = observed avg + 16 Mi
- Memory limit = max(observed avg × 2, 128) Mi

Adjust based on your actual workload profile.

| Cluster size | Pods/node | CPU request | CPU limit | Memory request | Memory limit |
|--------------|-----------|-------------|-----------|----------------|--------------|
| S (≤ 10 pods/node) | 10 | 5m | 50m | 139Mi | 246Mi |
| M (≤ 50 pods/node) | 50 | 5m | 50m | 139Mi | 246Mi |
| L (≤ 100 pods/node) | 100 | 5m | 50m | 137Mi | 242Mi |
| XL (≤ 250 pods/node) | 250 | 5m | 50m | 137Mi | 242Mi |

Memory requests/limits account for RSS headroom above the observed baseline (~121–123 MiB at load).

## Reproducing the benchmark

```bash
# Prerequisites: minikube with containerd runtime, NRI enabled,
#                cert-manager, cert-manager-csi-driver, and runtime-enforcer installed.
#                metrics-server addon enabled.
python3 hack/bench/bench.py --namespace runtime-enforcer
```

The script writes a timestamped Markdown report to `hack/bench/results/YYYYMMDD-HHMMSS.md`.

See [`hack/bench/bench.py`](../hack/bench/bench.py) for full details and configuration options.
