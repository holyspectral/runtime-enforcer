# Runtime Enforcer — Resource Consumption

This document provides measured resource consumption data for the runtime enforcer agent to help with capacity planning.

All measurements were collected with [hack/bench/bench.sh](../hack/bench/bench.sh). See [Reproducing the benchmark](#reproducing-the-benchmark) for instructions.

## Environment

| Field | Value |
|-------|-------|
| Enforcer chart | runtime-enforcer-0.1.7 |
| Agent image | ghcr.io/rancher-sandbox/runtime-enforcer/agent:latest |
| Kubernetes | v1.32.0 |
| Kernel | 6.17.0-22-generic |
| OS (node) | Debian GNU/Linux 12 (bookworm) |
| Container runtime | containerd 2.2.1 |
| Node CPU capacity | 16 vCPUs |
| Node memory capacity | ~14.4 GiB |

## 1. Idle Baseline

Agent sampled every 5 s for 60 s with no workload pods.

| Metric | Value |
|--------|-------|
| CPU avg | 2m |
| CPU p99 | 2m |
| RSS avg | 113 MiB |
| RSS p99 | 113 MiB |

## 2. Pod Scaling

Pause pods (`registry.k8s.io/pause:3.10`) deployed in a dedicated namespace. Agent metrics sampled for 30 s after each batch stabilises.

> **Note:** The single-node minikube cluster tested here has a pod limit of ~110. At the 100-pod mark, 94/100 pods were scheduled due to system pods occupying the remaining slots. Production multi-node clusters distribute pods across nodes and are not subject to this constraint.

| Pod count | CPU avg (m) | CPU p99 (m) | RSS avg (MiB) | RSS p99 (MiB) |
|-----------|-------------|-------------|---------------|---------------|
| 10 | 2 | 2 | 113 | 113 |
| 50 | 1 | 1 | 115 | 115 |
| 100 | 1 | 1 | 115 | 115 |

Memory footprint is largely flat across pod counts because the agent tracks containers via eBPF maps that are pre-allocated at a fixed size (see [§4](#4-ebpf-map-footprint)).

## 3. Policy Scaling

`WorkloadPolicy` CRs created with a single-rule allow-list. eBPF map entry counts are read via `bpftool` after each batch.

> **Note:** `cg_to_policy_map` and `policy_map` entries reflect _active_ pod-policy assignments, not the count of `WorkloadPolicy` objects. These maps are populated when a running pod carries the `security.rancher.io/policy` label pointing at a policy. Creating policies without associated pods results in 0 entries.

| Policy count | cg\_to\_policy\_map entries | policy\_map entries |
|--------------|--------------------------|---------------------|
| 1 | 0 | 0 |
| 5 | 0 | 0 |
| 10 | 0 | 0 |
| 20 | 0 | 0 |

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

A test pod runs `for i in $(seq 5000); do /bin/true; done` and wall-clock time is measured under three conditions:

- **no-policy**: pod has no `WorkloadPolicy` label
- **monitor**: pod references a `WorkloadPolicy` in Monitor mode
- **protect**: pod references a `WorkloadPolicy` in Protect mode

| Mode | Run 1 (s) | Run 2 (s) | Run 3 (s) | Avg (s) |
|------|-----------|-----------|-----------|---------|
| no-policy | 2.808 | 2.799 | 2.796 | 2.801 |
| monitor | 2.817 | 2.792 | 2.800 | 2.803 |
| protect | 2.806 | 2.819 | 2.819 | 2.815 |

Overhead is **< 1%** across all modes for this exec-heavy workload.

## 6. T-Shirt Sizing

The table below gives suggested Kubernetes resource requests and limits for the agent DaemonSet, derived from the measurements above. Adjust based on your actual workload profile.

| Cluster size | Pods/node | CPU request | CPU limit | Memory request | Memory limit |
|--------------|-----------|-------------|-----------|----------------|--------------|
| S (≤ 10 pods/node) | 10 | 10m | 50m | 64Mi | 128Mi |
| M (≤ 50 pods/node) | 50 | 20m | 100m | 96Mi | 192Mi |
| L (≤ 100 pods/node) | 100 | 30m | 150m | 128Mi | 256Mi |
| XL (≤ 250 pods/node) | 250 | 50m | 250m | 192Mi | 384Mi |

Memory limits account for RSS headroom above the ~113–115 MiB observed baseline.

## Reproducing the benchmark

```bash
# Prerequisites: minikube with containerd runtime, NRI enabled,
#                cert-manager, cert-manager-csi-driver, and runtime-enforcer installed.
#                metrics-server addon enabled.
bash hack/bench/bench.sh --namespace runtime-enforcer
```

The script writes a timestamped Markdown report to `hack/bench/results/YYYYMMDD-HHMMSS.md`.

See [`hack/bench/bench.sh`](../hack/bench/bench.sh) for full details and configuration options.
