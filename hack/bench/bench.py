#!/usr/bin/env python3
"""hack/bench/bench.py — Runtime Enforcer resource-consumption benchmark

Usage:
    ./hack/bench/bench.py [--namespace NS] [--output FILE] [-l <>]

Output: Markdown report in hack/bench/results/YYYYMMDD-HHMMSS.md
        and a copy at the path given by --output (if provided).
"""

baseline_header = [ "Node CPU avg (m)", "Node RSS avg (Mi)", "NoPolicy execve throughput(ops/sec)" ]
baseline_result = []

pod_testcase = (0, 10, 50, 100)
pod_header = [ "Pod count", "Node CPU avg (m)", "Node RSS avg (Mi)", "CPU avg (m)", "CPU max (m)", "RSS avg (Mi)", "RSS max (Mi)", "NoPolicy execve throughput(ops/sec)", "Monitor execve throughput(ops/sec)", "Protect execve throughput(ops/sec)"]
pod_result = []

policy_testcase = (1, 10, 30, 50)
policy_header = [ "Pod count", "Node CPU avg (m)", "Node RSS avg (Mi)", "CPU avg (m)", "CPU max (m)", "RSS avg (Mi)", "RSS max (Mi)", "NoPolicy execve throughput(ops/sec)", "Monitor execve throughput(ops/sec)", "Protect execve throughput(ops/sec)"]
policy_result = []

import argparse
import json
import shutil
import statistics
import string
import subprocess
import sys
import time
import textwrap
import yaml
from tabulate import tabulate

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MANIFESTS_DIR = Path(__file__).parent / "manifests"


def load_manifest(filename: str, **kwargs: str) -> str:
    """Load a YAML manifest template from manifests/ and substitute variables."""
    template = string.Template((MANIFESTS_DIR / filename).read_text())
    return template.substitute(**kwargs)

# ---------------------------------------------------------------------------
# Globals (populated in main before any section runs)
# ---------------------------------------------------------------------------
AGENT_NS: str = ""
REPORT_PATH: Path = Path()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Runtime Enforcer resource-consumption benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--namespace", default="runtime-enforcer",
        help="Namespace where runtime-enforcer is deployed (default: runtime-enforcer)",
    )
    p.add_argument(
        "--output", default="",
        help="Copy finished report to this path in addition to results/",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def run(
    cmd: List[str],
    *,
    input: Optional[str] = None,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """Run *cmd*, optionally feeding *input* to stdin. Never raises on non-zero exit."""
    return subprocess.run(
        cmd,
        input=input,
        capture_output=capture,
        text=True,
        check=False,
    )


def kubectl(*args: str, input: Optional[str] = None) -> subprocess.CompletedProcess:
    result = run(["kubectl"] + list(args), input=input)
    if result.returncode != 0:
        print("Output:", result.stdout)
        print("Errors:", result.stderr)
        print("Return Code:", result.returncode)
    return result

def helm(*args: str) -> subprocess.CompletedProcess:
    result = run(["helm"] + list(args))
    if result.returncode != 0:
        print("Output:", result.stdout)
        print("Errors:", result.stderr)
        print("Return Code:", result.returncode)
    return result

# ---------------------------------------------------------------------------
# Logging / report helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[bench] {msg}", file=sys.stderr)


def die(msg: str) -> None:
    print(f"[bench] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def report(line: str = "") -> None:
    """Append *line* to the report file and print it to stdout."""
    print(line)
    with REPORT_PATH.open("a") as f:
        f.write(line + "\n")

# ---------------------------------------------------------------------------
# Namespace helper
# ---------------------------------------------------------------------------
def recreate_namespace(ns: str, wait_timeout: int = 60) -> None:
    """
    Delete *ns* if it exists, wait for termination, then recreate it.
    This ensures no stale pods or policies from a prior run affect results.
    """
    kubectl("delete", "namespace", ns, "--ignore-not-found", "--wait=false")
    # Poll until the namespace is fully gone (or didn't exist)
    deadline = time.monotonic() + wait_timeout
    while time.monotonic() < deadline:
        r = kubectl("get", "namespace", ns, "--ignore-not-found", "--no-headers")
        if not r.stdout.strip():
            break
        time.sleep(3)
    else:
        die(f"namespace {ns} still terminating after {wait_timeout} s")
    kubectl("create", "namespace", ns)

def checkthroughput(mode: str, ns: str, labels: Optional[Dict[str, str]] = None) -> float:
    log(f"Checking throughput in {mode} mode...")
    label_args = []
    if labels:
        label_str = ",".join(f"{k}={v}" for k, v in labels.items())
        label_args = [f"--labels={label_str}"]

    kubectl(
        "run", "bench-hotpath-pod",
        "--image=docker.io/library/ubuntu:24.04",
        "--restart=Never",
        f"--namespace={ns}",
        *label_args,
        "--command", "--", "/usr/bin/sleep", "infinity",
    )
    kubectl(
        "wait", "pod", "bench-hotpath-pod", f"-n={ns}",
        "--for=condition=Ready", "--timeout=60s",
    )

    ops_per_sec = measure_syscall(
        "bench-hotpath-pod", "bench-hotpath-pod", ns
    )

    log(f"execve: {ops_per_sec} ops/second")

    kubectl(
        "delete", "pod", "bench-hotpath-pod",
        f"-n={ns}", "--ignore-not-found",
    )
    return ops_per_sec


def sample_node_metrics(
    duration: int = 60, interval: int = 30
) -> Tuple[int, int, int, int]:
    cpu_samples: List[int] = []
    mem_samples: List[int] = []
    end = time.monotonic() + duration

    while time.monotonic() < end:
        r = kubectl("top", "node", "--no-headers")
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.split()
            log(parts)
            if len(parts) >= 4:
                cpu_samples.append(int(parts[1].rstrip("m")))
                mem_samples.append(int(parts[3].rstrip("Mi")))
        time.sleep(interval)

    if not cpu_samples:
        log("WARNING: no metrics — reporting zeros")
        return 0, 0, 0, 0

    return (
        int(statistics.mean(cpu_samples)),
        int(statistics.mean(mem_samples)),
        max(cpu_samples),
        max(mem_samples),
    )

def sample_agent_metrics(
    duration: int = 60, interval: int = 30
) -> Tuple[int, int, int, int]:
    cpu_samples: List[int] = []
    mem_samples: List[int] = []
    end = time.monotonic() + duration

    r = kubectl(
        "get", "pod", "-n", AGENT_NS,
        "-l", "app.kubernetes.io/component=agent",
        "-o", "jsonpath={.items[0].metadata.name}",
    )
    agent_pod = r.stdout.strip()
    if not agent_pod:
        die(f"agent pod not found in {AGENT_NS}")

    while time.monotonic() < end:
        r = kubectl("top", "pod", agent_pod, "-n", AGENT_NS, "--no-headers")
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.split()
            log(parts)
            if len(parts) >= 4:
                log(parts)
                cpu_samples.append(int(parts[1].rstrip("m")))
                mem_samples.append(int(parts[2].rstrip("Mi")))
        time.sleep(interval)

    if not cpu_samples:
        log("WARNING: no metrics — reporting zeros")
        return 0, 0, 0, 0

    return (
        int(statistics.mean(cpu_samples)),
        int(statistics.mean(mem_samples)),
        max(cpu_samples),
        max(mem_samples),
    )

def deploy_pause_pods(ns: str, count: int) -> None:
    log(f"Deploying {count} pause pods in {ns}...")

    kubectl("apply", "-f", "-", input=load_manifest(
        "pause-deployment.yaml",
        index=0,
        namespace=ns,
        replicas=count,
    ))

    kubectl(
        "rollout", "status", "deployment/pause-deployment", f"-n={ns}", "--timeout=180s",
    )

# TODO: kernel version
def measure_syscall(
    pod: str, container: str, ns: str, repeat: int = 10000
) -> float:
    r = kubectl(
        "exec", pod, "-c", container, "-n", ns, "--",
        "/usr/bin/bash", "-c",
        "apt update &> /dev/null && apt install -y linux-tools-6.17.0-23-generic &> /dev/null;"
        "/usr/lib/linux-tools/6.17.0-23-generic/perf bench syscall execve | tail -1 | awk '{print $1}'",
    )
    raw = r.stdout.strip()
    return float(raw)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global AGENT_NS, REPORT_PATH

    args = parse_args()
    AGENT_NS = args.namespace

    script_dir = Path(__file__).parent
    results_dir = script_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    REPORT_PATH = results_dir / f"{timestamp}.md"
    REPORT_PATH.write_text("")  # create / truncate

    # ------------------------------------------------------------------
    # Preflight checks
    # ------------------------------------------------------------------
    for cmd in ("kubectl","helm"):
        if not shutil.which(cmd):
            die(f"{cmd} not found in PATH")

    r = kubectl("get", "namespace", AGENT_NS)
    if r.returncode == 0:
        die(f"runtime-enforcer is already installed")

    # ------------------------------------------------------------------
    # Section 1: Baseline
    # ------------------------------------------------------------------

    report("## Baseline")
    log(f"Collecting metrics...")
    baseline_ns = "bench-baseline"
    pod_avg_cpu: Dict[int, int] = {}
    pod_avg_mem: Dict[int, int] = {}

    recreate_namespace(baseline_ns)
    avg_nopolicy = checkthroughput("no-policy", baseline_ns)
    node_ac, node_am, node_mc, node_mm = sample_node_metrics(60)
    baseline_result.append([node_ac, node_mc, avg_nopolicy])

    report(tabulate(baseline_result, headers=baseline_header, tablefmt="github"))
    kubectl("delete", "namespace", baseline_ns, "--ignore-not-found")

    # ------------------------------------------------------------------
    # Section 2: Pod scaling
    # ------------------------------------------------------------------

    # Before everything, install runtime-enforcer
    helm("upgrade", "--install", "-n", "runtime-enforcer", "runtime-enforcer", "../../charts/runtime-enforcer", "--wait", "--create-namespace")

    report("## Pod Scaling")
    report()
    report("Pause pods (registry.k8s.io/pause:3.10) are deployed in a dedicated namespace.")
    report()

    pod_scale_ns = "bench-pod-scaling"
    pod_avg_cpu: Dict[int, int] = {}
    pod_avg_mem: Dict[int, int] = {}

    for count in pod_testcase:
        log(f"Pod count: {count}")
        recreate_namespace(pod_scale_ns)

        kubectl("apply", "-f", "-", input=load_manifest(
            "hotpath-policy.yaml", namespace=pod_scale_ns,
        ))

        kubectl("apply", "-f", "-", input=load_manifest(
            "pause-policy.yaml", namespace=pod_scale_ns,
        ))

        log(f"Deploying pause pods...")
        deploy_pause_pods(pod_scale_ns, count)
        if count != 0:
            time.sleep(60)  # wait for metrics-server to pick up new pod state

        log(f"Collecting metrics...")
        ac, am, mc, mm = sample_agent_metrics(60)
        pod_avg_cpu[count] = ac
        pod_avg_mem[count] = am

        node_ac, node_am, node_mc, node_mm = sample_node_metrics(60)

        avg_nopolicy = checkthroughput("no-policy", pod_scale_ns)
        avg_monitor = checkthroughput("monitor", pod_scale_ns, {"security.rancher.io/policy": "bench-hotpath-policy"})
        avg_protect = checkthroughput("protect", pod_scale_ns, {"security.rancher.io/policy": "bench-hotpath-policy"})

        pod_result.append([count, node_ac, node_mc, ac, mc, am, mm, avg_nopolicy, avg_monitor, avg_protect])

        kubectl("delete", "namespace", pod_scale_ns, "--ignore-not-found")

    report(tabulate(pod_result, headers=pod_header, tablefmt="github"))


    # ------------------------------------------------------------------
    # Section 3: Policy scaling
    # ------------------------------------------------------------------
    log("=== Policy scaling ===")
    report("## Policy Scaling")
    report()
    report("WorkloadPolicy CRs are created alongside one labeled pod per policy.")
    report("eBPF map entries are counted after each cumulative batch is Running.")
    report()
    report(
        "- **cg_to_policy_map**: keyed by container cgroup ID; "
        "one entry per running container with an active policy assignment."
    )
    report(
        "- **policy_mode_map**: keyed by policy ID; "
        "one entry per unique policy assigned to at least one running container."
    )
    report()
    report("| Policy count | cg_to_policy_map entries | policy_mode_map entries |")
    report("|--------------|--------------------------|------------------------|")

    policy_ns = "bench-policy-scaling"
    log(f"  Cleaning up namespace {policy_ns} from any prior run...")
    recreate_namespace(policy_ns)

    for n in policy_testcase:
        log(f"  Creating {n} policies and pods...")
        recreate_namespace(policy_ns)

        kubectl("apply", "-f", "-", input=load_manifest(
            "hotpath-policy.yaml", namespace=policy_ns,
        ))

        # Create policies and pods.  This can take a while...
        for i in range(n):
            kubectl("apply", "-f", "-", input=load_manifest(
                "policy-scaling-policy.yaml",
                index=str(i),
                namespace=policy_ns,
            ))
            kubectl("apply", "-f", "-", input=load_manifest(
                "policy-scaling-pod.yaml",
                index=str(i),
                namespace=policy_ns,
            ))

            r = kubectl(
                "wait", "pod", "-n", policy_ns,
                "--for=condition=Ready",
                "-l", "security.rancher.io/policy",
                "--timeout=120s",
            )
            if r.returncode != 0:
                log("WARNING: not all policy pods ready within timeout")

        log(f"Collecting metrics...")
        ac, am, mc, mm = sample_agent_metrics(60)
        pod_avg_cpu[count] = ac
        pod_avg_mem[count] = am

        node_ac, node_am, node_mc, node_mm = sample_node_metrics(60)

        avg_nopolicy = checkthroughput("no-policy", policy_ns)
        avg_monitor = checkthroughput("monitor", policy_ns, {"security.rancher.io/policy": "bench-hotpath-policy"})
        avg_protect = checkthroughput("protect", policy_ns, {"security.rancher.io/policy": "bench-hotpath-policy"})

        policy_result.append([count, node_ac, node_mc, ac, mc, am, mm, avg_nopolicy, avg_monitor, avg_protect])

        time.sleep(3)  # let controller sync BPF maps
        kubectl("delete", "namespace", policy_ns, "--ignore-not-found")
    
    report(tabulate(policy_result, headers=policy_header, tablefmt="github"))

    # ------------------------------------------------------------------
    # Section 4: Metadata
    # ------------------------------------------------------------------
    log("=== Collecting metadata ===")

    # Resolve agent pod's node so all metadata is tied to the sampled node.
    r = kubectl(
        "get", "pod", "-n", AGENT_NS,
        "-l", "app.kubernetes.io/component=agent",
        "-o", "jsonpath={.items[0].spec.nodeName}",
    )
    agent_node = r.stdout.strip()
    if not agent_node:
        die(f"no agent pod found in {AGENT_NS} namespace")

    agent_image = kubectl(
        "get", "daemonset", "runtime-enforcer-agent", "-n", AGENT_NS,
        "-o", "jsonpath={.spec.template.spec.containers[0].image}",
    ).stdout.strip()

    agent_version = kubectl(
        "get", "daemonset", "runtime-enforcer-agent", "-n", AGENT_NS,
        "-o", "jsonpath={.metadata.labels.app\\.kubernetes\\.io/version}",
    ).stdout.strip() or "unknown"

    chart_version = kubectl(
        "get", "daemonset", "runtime-enforcer-agent", "-n", AGENT_NS,
        "-o", "jsonpath={.metadata.labels.helm\\.sh/chart}",
    ).stdout.strip() or "unknown"

    def node_info(field: str) -> str:
        return kubectl("get", "node", agent_node, "-o", f"jsonpath={{{field}}}").stdout.strip()

    k8s_raw = run(["kubectl", "version"]).stdout
    k8s_version = next(
        (line.split()[-1] for line in k8s_raw.splitlines() if "Server Version" in line),
        "unknown",
    )
    kernel    = node_info(".status.nodeInfo.kernelVersion")
    os_image  = node_info(".status.nodeInfo.osImage")
    runtime   = node_info(".status.nodeInfo.containerRuntimeVersion")
    cpu_cap   = node_info(".status.capacity.cpu")
    mem_cap   = node_info(".status.capacity.memory")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    REPORT_PATH.write_text(textwrap.dedent(f"""\
        # Runtime Enforcer Resource Consumption Benchmark

        **Generated:** {now}

        ## Environment

        | Field                   | Value |
        |-------------------------|-------|
        | Enforcer chart          | {chart_version} |
        | Agent version           | {agent_version} |
        | Agent image             | {agent_image} |
        | Kubernetes              | {k8s_version} |
        | Kernel                  | {kernel} |
        | OS image                | {os_image} |
        | Container runtime       | {runtime} |
        | Sampled node            | {agent_node} |
        | Node CPU capacity       | {cpu_cap} |
        | Node memory capacity    | {mem_cap} |
        | Measurement timestamp   | {now} |
        | Benchmark script        | hack/bench/bench.py |

    """))

"""
    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------
    report("---")
    report()
    report("*Measurements taken with [hack/bench/bench.py](../../hack/bench/bench.py).*")

    log(f"=== Done. Report: {REPORT_PATH} ===")

    if args.output:
        shutil.copy(REPORT_PATH, args.output)
        log(f"Copied to {args.output}")

    print(f"\nReport written to: {REPORT_PATH}")
    print(REPORT_PATH.read_text())
"""

if __name__ == "__main__":
    main()
