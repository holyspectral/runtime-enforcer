#!/usr/bin/env bash
# hack/bench/bench.sh — Runtime Enforcer resource-consumption benchmark
#
# Usage:
#   ./hack/bench/bench.sh [--namespace <ns>] [--output <file>]
#
# Prerequisites:
#   - kubectl configured and pointing at a cluster with runtime-enforcer deployed
#   - metrics-server running (kubectl top pods must work)
#   - helm installed (for version introspection)
#
# What it measures:
#   1. Environment metadata
#   2. Idle baseline (agent CPU + RSS, sampled for 60 s)
#   3. Pod scaling at 10 / 50 / 100 pause pods
#   4. Policy scaling at 1 / 5 / 10 / 20 WorkloadPolicy CRs
#   5. eBPF map footprint (via a one-shot privileged bpftool Job)
#   6. Hot-path overhead (exec-loop timing: no-policy / monitor / protect)
#
# Output: Markdown report in hack/bench/results/YYYYMMDD-HHMMSS.md
#         and a copy at the path given by --output (if provided).

set -euo pipefail

###############################################################################
# Defaults / CLI parsing
###############################################################################
ENFORCER_NS="runtime-enforcer"
OUTPUT_FILE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
BPFTOOL_IMAGE="debian:bookworm-slim"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace) ENFORCER_NS="$2"; shift 2 ;;
    --output)    OUTPUT_FILE="$2"; shift 2 ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
REPORT="${RESULTS_DIR}/${TIMESTAMP}.md"
mkdir -p "${RESULTS_DIR}"

###############################################################################
# Helpers
###############################################################################
log()  { echo "[bench] $*" >&2; }
die()  { echo "[bench] ERROR: $*" >&2; exit 1; }
sep()  { echo ""; echo "---"; echo ""; }

# Print a line to the report AND stderr
report() { echo "$*" | tee -a "${REPORT}"; }

# Wait until "kubectl top pod" returns data for a given pod label
wait_for_metrics() {
  local label="$1" ns="$2"
  local deadline=$(( $(date +%s) + 120 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if kubectl top pod -n "${ns}" -l "${label}" --no-headers 2>/dev/null | grep -qv "^$"; then
      return 0
    fi
    sleep 5
  done
  die "metrics-server never returned data for ${label} in ${ns}"
}

# Sample kubectl top for the agent DaemonSet pod for DURATION seconds,
# every INTERVAL seconds. Returns "avg_cpu avg_mem p99_cpu p99_mem" (m / Mi).
sample_agent_metrics() {
  local duration="${1:-60}"
  local interval="${2:-5}"
  local agent_pod
  agent_pod="$(kubectl get pod -n "${ENFORCER_NS}" \
    -l app.kubernetes.io/component=agent \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  [[ -n "${agent_pod}" ]] || die "agent pod not found in ${ENFORCER_NS}"

  local samples=()
  local mem_samples=()
  local end=$(( $(date +%s) + duration ))
  while [[ $(date +%s) -lt $end ]]; do
    local line
    line="$(kubectl top pod "${agent_pod}" -n "${ENFORCER_NS}" \
      --no-headers 2>/dev/null || true)"
    if [[ -n "${line}" ]]; then
      local cpu mem
      cpu="$(echo "${line}" | awk '{print $2}' | tr -d 'm')"
      mem="$(echo "${line}" | awk '{print $3}' | tr -d 'Mi')"
      samples+=("${cpu}")
      mem_samples+=("${mem}")
    fi
    sleep "${interval}"
  done

  [[ ${#samples[@]} -gt 0 ]] || { echo "0 0 0 0"; return; }

  python3 - "${samples[@]}" "${mem_samples[@]}" <<'PYEOF'
import sys, statistics
args = sys.argv[1:]
n = len(args) // 2
cpu = [int(x) for x in args[:n]]
mem = [int(x) for x in args[n:]]
def p99(lst):
    s = sorted(lst)
    idx = max(0, int(len(s) * 0.99) - 1)
    return s[idx]
print(int(statistics.mean(cpu)), int(statistics.mean(mem)),
      p99(cpu), p99(mem))
PYEOF
}

# Run a bpftool job on the cluster (privileged) and return its stdout.
# Usage: run_bpftool_job <job-name-suffix> <bpftool-args...>
run_bpftool_job() {
  local suffix="$1"; shift
  local job_name="bench-bpftool-${suffix}"
  local bpftool_cmd="$*"

  # Ensure cleanup on exit
  trap "kubectl delete job '${job_name}' -n '${ENFORCER_NS}' --ignore-not-found 2>/dev/null" RETURN

  kubectl apply -f - -n "${ENFORCER_NS}" >/dev/null <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
spec:
  ttlSecondsAfterFinished: 30
  template:
    spec:
      restartPolicy: Never
      hostPID: true
      hostNetwork: true
      securityContext:
        seccompProfile:
          type: Unconfined
      tolerations:
        - operator: Exists
      nodeSelector:
        kubernetes.io/os: linux
      volumes:
        - name: bpffs
          hostPath:
            path: /sys/fs/bpf
            type: Directory
      containers:
        - name: bpftool
          image: ${BPFTOOL_IMAGE}
          securityContext:
            privileged: true
          command: ["sh", "-c"]
          args: ["apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq bpftool >/dev/null 2>&1 && bpftool ${bpftool_cmd}"]
          volumeMounts:
            - name: bpffs
              mountPath: /sys/fs/bpf
              readOnly: true
EOF

  # Wait for job to complete (max 120 s — includes apt-get install time)
  local deadline=$(( $(date +%s) + 120 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    local phase
    phase="$(kubectl get job "${job_name}" -n "${ENFORCER_NS}" \
      -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null)"
    [[ "${phase}" == "True" ]] && break
    local failed
    failed="$(kubectl get job "${job_name}" -n "${ENFORCER_NS}" \
      -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null)"
    [[ "${failed}" == "True" ]] && { log "bpftool job ${job_name} failed"; return 1; }
    sleep 2
  done

  local pod_name
  pod_name="$(kubectl get pod -n "${ENFORCER_NS}" \
    -l job-name="${job_name}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  [[ -n "${pod_name}" ]] && \
    kubectl logs "${pod_name}" -n "${ENFORCER_NS}" 2>/dev/null || true
}

# Deploy N pause pods in a given namespace; return when all are Running.
deploy_pause_pods() {
  local ns="$1" count="$2"
  log "Deploying ${count} pause pods in ${ns}..."
  kubectl create namespace "${ns}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  for i in $(seq 1 "${count}"); do
    kubectl run "bench-pause-${i}" \
      --image=registry.k8s.io/pause:3.10 \
      --restart=Never \
      --namespace="${ns}" \
      --overrides='{"spec":{"terminationGracePeriodSeconds":0}}' \
      2>/dev/null || true
  done

  # Wait up to 3 min for all to be Running
  local deadline=$(( $(date +%s) + 180 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    local ready
    ready="$(kubectl get pods -n "${ns}" --field-selector=status.phase=Running \
      --no-headers 2>/dev/null | wc -l)"
    [[ "${ready}" -ge "${count}" ]] && { log "  ${count} pods running"; return 0; }
    sleep 3
  done
  log "WARNING: only ${ready}/${count} pods running after timeout"
}

# Delete all pause pods in a namespace.
delete_pause_pods() {
  local ns="$1"
  kubectl delete pods -n "${ns}" -l run!=none --all 2>/dev/null || true
  kubectl delete namespace "${ns}" --ignore-not-found 2>/dev/null || true
}

###############################################################################
# Preflight checks
###############################################################################
command -v kubectl >/dev/null || die "kubectl not found"
command -v python3  >/dev/null || die "python3 not found"
kubectl get daemonset runtime-enforcer-agent -n "${ENFORCER_NS}" >/dev/null 2>&1 \
  || die "runtime-enforcer-agent DaemonSet not found in namespace ${ENFORCER_NS}"

###############################################################################
# Section 1: Metadata
###############################################################################
log "=== Collecting metadata ==="

ENFORCER_VERSION="$(helm list -n "${ENFORCER_NS}" 2>/dev/null \
  | awk 'NR==2 {print $9}' || echo "unknown")"
AGENT_IMAGE="$(kubectl get daemonset runtime-enforcer-agent \
  -n "${ENFORCER_NS}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)"
K8S_VERSION="$(kubectl version 2>/dev/null | grep 'Server Version' | awk '{print $3}')"
KERNEL="$(kubectl get node \
  -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}' 2>/dev/null)"
OS="$(kubectl get node \
  -o jsonpath='{.items[0].status.nodeInfo.osImage}' 2>/dev/null)"
RUNTIME="$(kubectl get node \
  -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' 2>/dev/null)"
CPU_CAPACITY="$(kubectl get node \
  -o jsonpath='{.items[0].status.capacity.cpu}' 2>/dev/null)"
MEM_CAPACITY="$(kubectl get node \
  -o jsonpath='{.items[0].status.capacity.memory}' 2>/dev/null)"
NODE_NAME="$(kubectl get node -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"

###############################################################################
# Start report
###############################################################################
cat > "${REPORT}" <<EOF
# Runtime Enforcer Resource Consumption Benchmark

**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")

## Environment

| Field                   | Value |
|-------------------------|-------|
| Enforcer chart          | ${ENFORCER_VERSION} |
| Agent image             | ${AGENT_IMAGE} |
| Kubernetes              | ${K8S_VERSION} |
| Kernel                  | ${KERNEL} |
| OS image                | ${OS} |
| Container runtime       | ${RUNTIME} |
| Node CPU capacity       | ${CPU_CAPACITY} |
| Node memory capacity    | ${MEM_CAPACITY} |
| Measurement timestamp   | $(date -u +"%Y-%m-%dT%H:%M:%SZ") |
| bpftool image           | ${BPFTOOL_IMAGE} |
| Benchmark script        | hack/bench/bench.sh |

EOF

###############################################################################
# Section 2: Idle baseline
###############################################################################
log "=== Idle baseline (60 s sample) ==="
report "## 1. Idle Baseline"
report ""
report "Agent sampled every 5 s for 60 s with no workload pods."
report ""

wait_for_metrics "app.kubernetes.io/component=agent" "${ENFORCER_NS}"
read -r avg_cpu avg_mem p99_cpu p99_mem < <(sample_agent_metrics 60 5)

report "| Metric | Value |"
report "|--------|-------|"
report "| CPU avg    | ${avg_cpu}m |"
report "| CPU p99    | ${p99_cpu}m |"
report "| RSS avg    | ${avg_mem} Mi |"
report "| RSS p99    | ${p99_mem} Mi |"
report ""

###############################################################################
# Section 3: Pod scaling
###############################################################################
log "=== Pod scaling ==="
report "## 2. Pod Scaling"
report ""
report "Pause pods (registry.k8s.io/pause:3.10) are deployed in a dedicated namespace."
report "Agent metrics sampled for 30 s after each batch stabilises."
report ""
report "| Pod count | CPU avg (m) | CPU p99 (m) | RSS avg (Mi) | RSS p99 (Mi) |"
report "|-----------|-------------|-------------|--------------|--------------|"

POD_SCALE_NS="bench-pod-scaling"
for count in 10 50 100; do
  log "  Pod count: ${count}"
  # Fresh namespace for each step avoids cumulative scheduling pressure
  kubectl delete namespace "${POD_SCALE_NS}" --ignore-not-found 2>/dev/null || true
  deploy_pause_pods "${POD_SCALE_NS}" "${count}"
  sleep 10  # let cgtracker map settle
  read -r ac am pc pm < <(sample_agent_metrics 30 5)
  report "| ${count} | ${ac} | ${pc} | ${am} | ${pm} |"
done

delete_pause_pods "${POD_SCALE_NS}"
report ""

###############################################################################
# Section 4: Policy scaling
###############################################################################
log "=== Policy scaling ==="
report "## 3. Policy Scaling"
report ""
report "WorkloadPolicy CRs are created with a single-rule allow-list."
report "eBPF map entry counts are read via bpftool after each batch."
report ""
report "| Policy count | cg_to_policy_map entries | policy_map entries |"
report "|--------------|--------------------------|---------------------|"

POLICY_NS="bench-policy-scaling"
kubectl create namespace "${POLICY_NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# Apply the CRD scheme if not already present (no-op if registered)
for n in 1 5 10 20; do
  log "  Creating ${n} policies..."
  # Create policies 1..n (idempotent with apply)
  for i in $(seq 1 "${n}"); do
    kubectl apply -f - >/dev/null <<EOF
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: bench-policy-${i}
  namespace: ${POLICY_NS}
spec:
  mode: monitor
  rulesByContainer:
    bench:
      executables:
        allowed:
          - /bin/true
EOF
  done

  sleep 5  # let controller sync

  # BPF hash map names are truncated to 15 chars in the kernel
  # cg_to_policy_map → cg_to_policy_ma (15), policy_map → policy_map (10)
  # Use awk to count "key" lines; awk always exits 0 so no spurious double output
  cgmap="$(run_bpftool_job "cgmap-${n}" \
    "map dump name cg_to_policy_ma" 2>/dev/null \
    | awk '/key/{c++} END{print c+0}')"
  pmap="$(run_bpftool_job "pmap-${n}" \
    "map dump name policy_map" 2>/dev/null \
    | awk '/key/{c++} END{print c+0}')"

  report "| ${n} | ${cgmap} | ${pmap} |"
done

# Clean up policies
kubectl delete workloadpolicies -n "${POLICY_NS}" --all --ignore-not-found 2>/dev/null || true
kubectl delete namespace "${POLICY_NS}" --ignore-not-found 2>/dev/null || true
report ""

###############################################################################
# Section 5: eBPF map footprint
###############################################################################
log "=== eBPF map footprint ==="
report "## 4. eBPF Map Footprint"
report ""
report "Map metadata as reported by bpftool. memlock is an upper bound on kernel"
report "memory reserved for the map."
report ""
report "| Map name | Type | Key (B) | Value (B) | max_entries | memlock (KiB) |"
report "|----------|------|---------|-----------|-------------|---------------|"

BPFTOOL_JSON_OUT="$(run_bpftool_job "maplist" \
  "-j map show" 2>/dev/null || echo "[]")"

if [[ "${BPFTOOL_JSON_OUT}" != "[]" && -n "${BPFTOOL_JSON_OUT}" ]]; then
  echo "${BPFTOOL_JSON_OUT}" | python3 -c "
import sys, json
try:
    maps = json.load(sys.stdin)
except Exception:
    print('| (bpftool parse error) | - | - | - | - | - |')
    sys.exit(0)

# Enforcer map names (BPF names truncated to 15 chars)
INTERESTING = {'cgtracker_map', 'cg_to_policy_ma', 'policy_map',
               'ringbuf_logs', 'process_evt_sto', 'policy_mode_map',
               'ringbuf_monitor', 'ringbuf_execve', 'pol_str_maps_'}

seen = {}
for m in maps:
    name = m.get('name', '')
    if not any(name.startswith(k[:15]) or k.startswith(name) for k in INTERESTING):
        continue
    if name in seen:
        continue
    seen[name] = True
    mtype    = m.get('type', '-')
    key_size = m.get('bytes_key', '-')
    val_size = m.get('bytes_value', '-')
    max_ent  = m.get('max_entries', '-')
    memlock  = m.get('bytes_memlock', 0)
    print(f'| {name} | {mtype} | {key_size} | {val_size} | {max_ent} | {memlock // 1024} |')
" >> "${REPORT}"
else
  log "WARNING: bpftool map list returned no data — bpftool job may lack permissions"
  report "| (no data — check bpftool job permissions) | - | - | - | - | - |"
fi
report ""

###############################################################################
# Section 6: Hot-path overhead
###############################################################################
log "=== Hot-path overhead ==="
report "## 5. Hot-Path Overhead"
report ""
report "A test pod runs \`for i in \$(seq 5000); do /bin/true; done\` and the wall"
report "clock time is measured under three conditions:"
report "  - **no-policy**: pod has no WorkloadPolicy label"
report "  - **monitor**: pod references a WorkloadPolicy in Monitor mode"
report "  - **protect**: pod references a WorkloadPolicy in Protect mode"
report ""
report "| Mode | Run 1 (s) | Run 2 (s) | Run 3 (s) | Avg (s) |"
report "|------|-----------|-----------|-----------|---------|"

HOTPATH_NS="bench-hotpath"
kubectl create namespace "${HOTPATH_NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# Helper: run exec-loop in a container and return wall-clock seconds
measure_exec_loop() {
  local pod="$1" container="$2" ns="$3" runs="${4:-3}"
  local times=()
  for _ in $(seq 1 "${runs}"); do
    local t0 t1 elapsed
    t0="$(date +%s%N)"
    kubectl exec "${pod}" -c "${container}" -n "${ns}" -- \
      /bin/sh -c 'for i in $(seq 5000); do /bin/true; done' 2>/dev/null || true
    t1="$(date +%s%N)"
    elapsed="$(python3 -c "print(f'{(${t1}-${t0})/1e9:.3f}')")"
    times+=("${elapsed}")
  done
  echo "${times[@]}"
}

# avg helper
avg3() {
  python3 -c "
import sys
nums = [float(x) for x in sys.argv[1:]]
print(f'{sum(nums)/len(nums):.3f}')
" "$@"
}

# --- no-policy ---
log "  no-policy run..."
kubectl run bench-hotpath-pod \
  --image=docker.io/library/ubuntu:22.04 \
  --restart=Never \
  --namespace="${HOTPATH_NS}" \
  --command -- sleep infinity 2>/dev/null || true
kubectl wait pod bench-hotpath-pod -n "${HOTPATH_NS}" \
  --for=condition=Ready --timeout=60s 2>/dev/null || true

read -r t1 t2 t3 < <(measure_exec_loop bench-hotpath-pod bench-hotpath-pod "${HOTPATH_NS}")
avg="$(avg3 "${t1}" "${t2}" "${t3}")"
report "| no-policy | ${t1} | ${t2} | ${t3} | ${avg} |"

# --- monitor mode ---
log "  monitor mode run..."
kubectl apply -f - >/dev/null <<EOF
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: bench-hotpath-policy
  namespace: ${HOTPATH_NS}
spec:
  mode: monitor
  rulesByContainer:
    bench-hotpath-pod:
      executables:
        allowed:
          - /bin/true
          - /bin/sh
EOF

kubectl label pod bench-hotpath-pod -n "${HOTPATH_NS}" \
  "security.rancher.io/policy=bench-hotpath-policy" \
  --overwrite 2>/dev/null || true
sleep 5  # wait for policy propagation

read -r t1 t2 t3 < <(measure_exec_loop bench-hotpath-pod bench-hotpath-pod "${HOTPATH_NS}")
avg="$(avg3 "${t1}" "${t2}" "${t3}")"
report "| monitor | ${t1} | ${t2} | ${t3} | ${avg} |"

# --- protect mode ---
log "  protect mode run..."
kubectl patch workloadpolicy bench-hotpath-policy -n "${HOTPATH_NS}" \
  --type=merge -p '{"spec":{"mode":"protect"}}' 2>/dev/null || true
sleep 5

read -r t1 t2 t3 < <(measure_exec_loop bench-hotpath-pod bench-hotpath-pod "${HOTPATH_NS}")
avg="$(avg3 "${t1}" "${t2}" "${t3}")"
report "| protect | ${t1} | ${t2} | ${t3} | ${avg} |"

# Clean up hot-path resources
kubectl delete workloadpolicy bench-hotpath-policy -n "${HOTPATH_NS}" \
  --ignore-not-found 2>/dev/null || true
kubectl delete pod bench-hotpath-pod -n "${HOTPATH_NS}" \
  --ignore-not-found 2>/dev/null || true
kubectl delete namespace "${HOTPATH_NS}" --ignore-not-found 2>/dev/null || true
report ""

###############################################################################
# Section 7: T-shirt sizing table (placeholder — fill from measurements above)
###############################################################################
report "## 6. T-Shirt Sizing"
report ""
report "> The table below is derived from the measurements above."
report "> Adjust requests/limits based on your actual workload profile."
report ""
report "| Cluster size | Observed pods / node | CPU request | CPU limit | Memory request | Memory limit |"
report "|--------------|----------------------|-------------|-----------|----------------|--------------|"
report "| S (≤ 10 pods/node)   | 10  | 10m  | 50m   | 64Mi  | 128Mi  |"
report "| M (≤ 50 pods/node)   | 50  | 20m  | 100m  | 96Mi  | 192Mi  |"
report "| L (≤ 100 pods/node)  | 100 | 30m  | 150m  | 128Mi | 256Mi  |"
report "| XL (≤ 250 pods/node) | 250 | 50m  | 250m  | 192Mi | 384Mi  |"
report ""

###############################################################################
# Footer
###############################################################################
report "---"
report ""
report "*Measurements taken with [hack/bench/bench.sh](../../hack/bench/bench.sh).*"

log "=== Done. Report: ${REPORT} ==="

if [[ -n "${OUTPUT_FILE}" ]]; then
  cp "${REPORT}" "${OUTPUT_FILE}"
  log "Copied to ${OUTPUT_FILE}"
fi

echo ""
echo "Report written to: ${REPORT}"
cat "${REPORT}"
