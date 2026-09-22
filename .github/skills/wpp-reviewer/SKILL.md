---
name: wpp-reviewer
description: >-
  Reviews a Kubewarden runtime-enforcer WorkloadPolicyProposal (WPP),
  produces a security risk/severity assessment plus an approval
  recommendation, and can then generate the target YAML manifest to
  promote the reviewed proposal into an enforced WorkloadPolicy (monitor
  or protect mode). This manifest is normally applied by the user
  themselves, but the agent may apply it on the user's behalf via
  whatever other means it has available, once the user explicitly
  confirms they want it applied now (or, for bulk requests across many
  WPPs, once the explicit batch-mode conditions in this skill are met).
  Use this whenever asked to review, assess, audit, recommend
  approval/rejection, promote, apply, or approve a WorkloadPolicyProposal,
  WPP, runtime-enforcer proposal, or a learned executable allowlist —
  including requests to do so for every WPP in a namespace/cluster.
license: Apache-2.0
---

# WorkloadPolicyProposal (WPP) Security Review & Promotion

This skill is self-contained so any agent that understands the `SKILL.md`
convention (GitHub Copilot CLI, Claude Code, kagent, etc.) can use it, even
outside this repository's tooling. No access to the runtime-enforcer Go
source is required — everything needed is described below.

**Discovery note:** this skill's canonical name is `wpp-reviewer` (matching
the `name:` field in the frontmatter above), and it must live in a
directory of the same name — some runtimes require the directory name and
frontmatter `name` to match in order to register the skill at all. Some
agent runtimes don't auto-scan a repository for skills; they instead
require the skill to be explicitly declared in the agent's own
configuration and then unpack/mount it at a fixed path (e.g. kagent
unpacks each declared skill to `/skills/<name>/`, so this skill would land
at `/skills/wpp-reviewer/SKILL.md`). If an agent reports this skill as
"not available," first check that it's actually declared/registered in
that agent's own configuration; if it's unclear whether auto-discovery
happened, explicitly point the agent at its mounted path (e.g.
`/skills/wpp-reviewer/SKILL.md`) in the prompt.

Three phases:

- **Phase 1 — Security Review** (sections 1–6): produces a risk assessment
  and an approve/request-changes/comment recommendation for a WPP. Usable
  standalone, with no promotion intent.
- **Phase 2 — Promotion** (section 7): generates the **target YAML
  manifest** for a *previously reviewed* WPP, with the promotion label set
  to the user's chosen mode (`monitor` or `protect`). By default this
  manifest is for the **user to apply themselves** (`kubectl apply`, a
  GitOps PR, or any other means they use to manage cluster manifests). If
  the agent has some other available means (e.g. another skill/tool) to
  apply Kubernetes manifests, it may use it **only** after the user
  explicitly confirms they want it applied now (see 7.4). Phase 2 is
  **only** reachable after Phase 1 has completed, in this same
  conversation, for the exact proposal and content being promoted — never
  skip straight to Phase 2.
- **Phase 3 — Batch / unattended mode** (section 9): an explicit, narrow
  opt-in that lets a single initiating instruction cover many WPPs (e.g.
  "review and promote every WPP in namespace X") without per-proposal
  confirmation, but **only** when that instruction contains specific,
  explicit signals (see section 9) — otherwise every proposal is still
  gated exactly as Phases 1–2 describe.

The agent may run in any environment; **do not assume `kubectl` or any
other cluster-access tooling is present**. Phase 2 always produces the
target manifest as text first, for the user to review and, by default,
apply themselves — that path needs no agent confirmation, since the agent
isn't acting on the cluster. The **only** thing gated by explicit user
confirmation is the agent itself applying the manifest via some other
available means on the user's behalf (see 7.4), **unless** Phase 3's batch
mode has been explicitly triggered (section 9); never treat confirmation
as given silently or by assumption otherwise.

## ⚠️ Mandatory disclaimer (always print this, verbatim or near-verbatim, with every review)

> **Disclaimer:** This is an automated, heuristic security review. It is
> **not** a guarantee of safety and does **not** replace human judgment.
> A WPP contains only **executable paths** — no arguments, network activity,
> or file operations. Approving/promoting this WorkloadPolicyProposal will
> suppress future violation reporting for every listed executable path (in
> both `monitor` and `protect` mode) once the resulting WorkloadPolicy is
> applied, until a human later updates or removes that policy. For
> agent-generated proposals, these paths were only *observed* by the
> runtime-enforcer during a learning window — they were never vetted, and
> may include debug tooling, one-off admin commands, or genuinely malicious
> behavior that happened to run during that window. A human who understands
> this workload's expected behavior must make the final approve/reject
> decision.

## 1. What a WorkloadPolicyProposal is

A `WorkloadPolicyProposal` (shortname `wpp`) is a namespaced Kubernetes
custom resource produced by the runtime-enforcer agent while it learns
executions from a workload not yet bound to any `WorkloadPolicy`. Relevant
schema:

```yaml
apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicyProposal
metadata:
  name: <string>
  namespace: <string>
  labels:
    runtimeenforcer.kubewarden.io/promote: monitor|protect   # present once promoted
spec:
  rulesByContainer:
    <containerName>:
      executables:
        allowed:
          - /absolute/path/to/executable
          - /another/observed/executable
    <anotherContainerName>:
      executables:
        allowed: [...]
```

Key facts:

- `spec.rulesByContainer` maps **container name** to the **absolute paths
  of executables** the runtime-enforcer observed actually running in that
  container during the learning window.
- The list is capped (currently 100 entries per proposal in the reference
  implementation) — a proposal near that cap may indicate a very
  active/varied workload, or noisy/unstable learning data.
- **For agent-generated WPPs, these are observed, not vetted, paths.**
  Presence in the list does not imply legitimacy or safety. Treat manually
  created/hand-edited manifests as untrusted input — do not assume their
  entries were actually observed.
- Promoting a proposal (e.g. via `kubectl runtime-enforcer proposal promote
  <name> --mode monitor|protect`) creates a `WorkloadPolicy` that
  allowlists exactly these executables per container, in the chosen mode.
  **An allowlisted executable never produces a violation, in either mode**
  — mode only changes how *non-allowlisted* executions are handled:
  `protect` blocks and reports them, `monitor` only reports them.
- So approving a WPP is **security-relevant**: if an attacker's tooling ran
  during the learning window, approving suppresses future violation
  reporting for those exact paths until the resulting `WorkloadPolicy` is
  later updated or removed by a human.

## 2. Accepted input

Accept the proposal as:

- A pasted or attached WPP manifest (YAML or JSON).
- Output of `kubectl get workloadpolicyproposal <name> -n <namespace> -o
  yaml` (or, absent `kubectl`, equivalent output from another tool, e.g.
  `kubectl-runtime_enforcer` or `oc`).
- A partial excerpt containing at least one `rulesByContainer` entry.
- A request to review **every WPP in a namespace** (e.g. "review all WPP in
  namespace X"). In this case, first enumerate every
  `WorkloadPolicyProposal` in that namespace (e.g. `kubectl get
  workloadpolicyproposal -n <namespace>`, or the equivalent listing from
  whatever tool is available), then run the full flow below — Phase 1
  (sections 1–6), and Phase 2 (section 7) if applicable — **independently
  for each proposal found**. If none are found, say so plainly rather than
  fabricating one. See section 2.1 for how to pace this output across
  multiple proposals, and section 9 for handling this at scale without
  per-proposal confirmation, when explicitly requested.

If no `rulesByContainer` data is present, or the resource can't be parsed,
say so and ask for the manifest — never fabricate executables or
containers.

If context about the workload's expected purpose (e.g. "static Go binary
web server", "Python ETL job") is missing and would materially change the
assessment of an ambiguous executable, ask rather than guess silently.

### 2.1 Processing multi-proposal scopes one at a time

Whenever more than one proposal is in scope (e.g. "every WPP in
namespace X"), never batch multiple proposals' full output into the
same response — printing everything at once risks the response being
cut off by the model's max-output-token limit before it finishes. This
constraint applies regardless of whether Phase 2/batch mode (section 9)
is subsequently triggered.

Instead:

- Process proposals **strictly one at a time**: each response/turn
  contains the full Phase 1 output (structured block + Markdown table +
  disclaimer, per section 6) — and Phase 2's output too, if applicable —
  for exactly **one** proposal.
- Clearly label each proposal's output with its position in the scope,
  e.g. "Reviewing proposal 4 of 11: `namespace/name`."
- After finishing one proposal, move on to the next one in a
  subsequent turn: if the runtime supports the agent autonomously
  continuing to a new turn on its own, do so without waiting on the
  user; otherwise, end the response by stating which proposal is next
  and asking the user to continue (e.g. "reply to continue"), keeping
  track of progress (position and remaining proposals) so it can pick
  back up correctly. Either way, never silently stop before every
  proposal in scope has been addressed.
- Once every proposal in scope has been processed this way, print a
  final aggregate summary (see section 6.1).

## 3. Risk taxonomy

**Scope limit:** `executables.allowed` contains only absolute **paths** —
no arguments, environment, network activity, or file-system operations.
Classify strictly from the path/name itself (plus what other paths appear
in the same container). Never report argument-, network-, read-, or
write-based indicators (e.g. "ran `nc -e`", "wrote to `authorized_keys`")
as *observed facts* — a WPP can't prove any of that. Frame these as "if
invoked this way, this binary's presence would enable X," not as
confirmed, unless the user supplies corroborating telemetry.

For **every container and every executable** in `executables.allowed`,
classify against the categories below (highest-severity match wins if
several apply). Categories are illustrative, not exhaustive — use
judgment for executables serving the same purpose under another name.

| Category | Example paths/binaries | Typical severity |
|---|---|---|
| Shells / interpreters | `sh`, `bash`, `dash`, `zsh`, `python`, `python3`, `perl`, `ruby`, `node` | 🟠 HIGH (🟡 MEDIUM if clearly the app's own runtime, e.g. `python3` in a Python app image) |
| Network tools | `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat`, `ssh`, `telnet`, `nmap` | 🟠 HIGH |
| Privilege escalation | `sudo`, `su`, `pkexec`, `setcap`, `doas` | 🔴 CRITICAL |
| Package managers / installers | `apt`, `apt-get`, `dpkg`, `yum`, `dnf`, `apk`, `pip`, `pip3`, `npm`, `go` | 🟡 MEDIUM–🟠 HIGH (installing new code at runtime is a common compromise/persistence step) |
| Debug / introspection tools | `strace`, `ltrace`, `gdb`, `tcpdump`, `nsenter`, `perf` | 🟠 HIGH (expected only in genuine debug sessions) |
| Unusual paths | any executable under `/tmp`, `/dev/shm`, `/var/tmp`, a hidden dot-directory, or world-writable directory | 🔴 CRITICAL (classic dropper/staging location) |
| File manipulation | `base64`, `xxd`, `tar`, `zip`, `scp`, `rsync`, `openssl`, `dd` | 🟡 MEDIUM–🟠 HIGH, higher alongside network tools in the same container (path co-occurrence raises suspicion, not proof, of exfiltration capability) |
| Container / host escape tooling | `runc`, `ctr`, `crictl`, `docker`, `nsenter`, `chroot`, `nerdctl` | 🔴 CRITICAL |
| Reverse-shell-capable binaries | `nc`/`ncat`, `socat`, `sh`/`bash`, `python`/`python3`, `perl` present together, especially with an unusual path | 🟠 HIGH–🔴 CRITICAL — flag the *capability*; don't claim a reverse shell was actually spawned from path evidence alone |
| Persistence-capable tooling | `crontab`, `at`, `systemctl`, `useradd`, `usermod`, `ssh-keygen` | 🟠 HIGH–🔴 CRITICAL — flag the *capability*; don't claim a crontab/authorized_keys entry was actually written without corroborating telemetry |
| Cloud / credential-capable tooling | `aws`, `gcloud`, `az`, `kubectl` run inside a workload container | 🔴 CRITICAL — unusual and worth flagging even without proof of credential access |
| Anti-forensics tooling | `shred`, `wipe` | 🟠 HIGH — flags the *capability* for log/evidence tampering |
| Compiler / build tooling in a runtime image | `gcc`, `cc`, `clang`, `make`, `ld`, `cargo`, `go` (for `build`) | 🟠 HIGH (build tooling has no business in a deployed runtime container) |
| Runtime / language mismatch | an interpreter/runtime not expected for the image (e.g. `python` in a static-Go-binary image, `node` in a Java app image) | 🟠 HIGH — flag as suspicious-by-context even if the binary looks benign |
| Executable-count anomalies | unusually large learned set (approaching the ~100 cap) or inconsistent with a simple/expected workload | 🟡 MEDIUM — flag for human review of noisy/unstable learning data |
| Everything matching the workload's obvious, expected role | e.g. the container's own entrypoint binary, well-known runtime helpers | ⚪ LOW |

## 4. Severity and confidence format

For each flagged executable, report:

- **Severity**: 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / ⚪ LOW
- **Confidence**: score out of 10 (lower when workload context is missing
  or the name alone is ambiguous)
- **Rationale**: one short sentence citing matching taxonomy categories

Summarize ⚪ LOW-severity executables in one compact line (e.g. "12 other
executables matched the container's expected entrypoint/runtime and were
assessed as LOW risk") instead of one row per item, to keep the report
readable.

## 5. Overall recommendation

Mirror GitHub's pull request review verdicts:

- **✅ Approve** — no CRITICAL/HIGH findings; only LOW (and at most a
  couple of well-explained MEDIUM) findings plausibly matching the
  workload's expected behavior.
- **🚫 Request Changes** — any CRITICAL or HIGH finding, or multiple
  unexplained MEDIUM findings. Recommend pruning the offending executables
  (or investigating the workload) before promotion, naming exactly which
  executables/containers are the problem.
- **💬 Comment / Needs More Info** — findings are ambiguous (e.g.
  MEDIUM-only, or a runtime/language mismatch that could be legitimate)
  and missing context prevents a confident Approve/Request Changes call.
  Ask the specific question that would resolve the ambiguity.

Never default to Approve when uncertain — uncertainty maps to Comment /
Needs More Info, not Approve.

### 5.1 Iterating after a Request Changes verdict (pruning)

`request_changes` is not a dead end. If the user explicitly asks to remove
specific flagged executables and try again (e.g. "remove those
CRITICAL/HIGH findings and promote it"), the skill **can** help — a
distinct, allowed action separate from Phase 1 review and Phase 2
promotion:

- Producing an edited **candidate manifest** with named executables
  removed is plain text generation, **not** a cluster mutation, and isn't
  covered by Phase 2's "never add/remove entries" rule (7.3) — that rule
  only governs how Phase 2 treats already-reviewed content; it doesn't
  forbid this separate, earlier, user-requested editing step.
- **Scope guard**: only remove entries the user explicitly confirmed as
  exact `(containerName, executablePath)` pairs — named directly, or via
  agreement to "remove the ones flagged in the most recent review" (i.e.
  *all and only* the findings in that immediately preceding review,
  nothing broader). If a named path appears in more than one container
  and it's unclear which, ask rather than guess. Never prune anything
  else.
- Clearly label the result as an **unreviewed candidate — not yet
  promotable**.
- Producing a pruned candidate **always invalidates the prior review**: a
  fresh Phase 1 review (sections 1–6) of the pruned
  `spec.rulesByContainer` content is **mandatory** before Phase 2. Never
  skip straight from "pruned" to "promote."
- Once the fresh review completes, treat it like any other Phase 1 result:
  Phase 2 (section 7) is reachable next, but still only after the user
  explicitly confirms (per section 8) they want to proceed to promotion
  having seen this fresh review — a prior "prune and promote it" request
  does not itself substitute for that post-review confirmation, since the
  review's outcome (and thus what's being confirmed) wasn't known yet when
  that request was made.

## 6. Output format

Produce **both**, in this order:

1. A machine-readable structured block (YAML or JSON, matching the
   conversation's preference):

   ```yaml
   wppReview:
     proposal: <namespace>/<name>
     overallRecommendation: approve | request_changes | comment
     containers:
       <containerName>:
         findings:
           - executable: /path/to/bin
             severity: critical | high | medium | low
             confidence: <0-10>
             categories: [reverse_shell_capable, unusual_path]
             rationale: "..."
         lowRiskCount: <int>
     disclaimer: "<the disclaimer text from section above>"
   ```

2. A human-readable Markdown summary:
   - A findings table per container: `# | Severity | Executable | Category | Rationale | Confidence`.
   - The overall recommendation with a one-paragraph justification.
   - The disclaimer from the top of this document, printed in full.

If Phase 2 (promotion) is subsequently performed, additionally produce a
matching structured block once section 7's flow completes:

```yaml
wppPromotion:
  proposal: <namespace>/<name>
  gatingReview: <Phase 1 wppReview.overallRecommendation used to gate this>
  mode: monitor | protect
  labelKey: runtimeenforcer.kubewarden.io/promote
  targetManifest: |
    <full YAML of the WPP, identical to what was reviewed, with
     metadata.labels["runtimeenforcer.kubewarden.io/promote"] set to
     the chosen mode>
  applyWith:
    - "kubectl apply -f <file-containing-targetManifest>"
    - "any other means the user manages cluster manifests with (GitOps PR, oc apply, etc.)"
  verify:
    - "kubectl get workloadpolicyproposal <name> -n <namespace> -o yaml   # confirm the promotion label is set"
    - "kubectl get workloadpolicy <name> -n <namespace>                  # confirm the controller created the resulting WorkloadPolicy"
```

followed by the target manifest as its own fenced `yaml` code block (so
the user can copy/paste or redirect it into a file), and a short summary
of what the manifest does.

### 6.1 Final aggregate summary for multi-proposal scopes

When a request covers more than one proposal (section 2.1) and is
processed as a plain review (not batch/promote-everything mode, section
9), once every proposal in scope has been processed one-by-one, print
one final consolidated summary in its own response, covering:

- Total proposals found/processed.
- Counts by overall recommendation (approve / request_changes / comment).
- Which proposals (by `namespace/name`) had CRITICAL or HIGH findings.
- Any enumeration or parse failures encountered along the way, named
  explicitly.

This final summary is in addition to, not a replacement for, each
proposal's own full Phase 1 output produced in section 2.1. It is
distinct from section 9.3's batch-mode summary, which additionally
reports promotion/apply outcomes for the promote-everything opt-in — use
this section 6.1 summary whenever section 9 wasn't triggered, and
section 9.3's summary when it was.

## 7. Promotion (Phase 2)

Only start this phase once Phase 1 (sections 1–6) has produced a
`wppReview` for the **exact** proposal and `spec.rulesByContainer` content
being promoted, in this same conversation. If no such review exists, or
it's for a different revision (e.g. the executable list changed since),
go back and (re-)run Phase 1 first — never promote from a stale or
missing review.

This phase produces a **target YAML manifest** the user can apply with
whatever tooling they already use (`kubectl`, `oc`, a GitOps PR, the
`runtime-enforcer` CLI, etc.). By default the skill applies nothing to a
cluster itself — but if the agent has some other available means (e.g.
another skill/tool) to apply Kubernetes manifests, it may use it on the
user's behalf **only** after the user explicitly confirms, in this
conversation, they want it applied now (see 7.4). Never assume such a
means is available, and never apply without that explicit confirmation.

### 7.1 Gate: re-surface the review before proceeding

Before anything else, restate to the user:

- The proposal being promoted (`<namespace>/<name>`).
- Phase 1's `overallRecommendation` and a one-line reason.

If Phase 1's recommendation was `request_changes`, warn clearly that
promoting anyway would enforce (in `monitor` or `protect` mode) an
allowlist containing the flagged CRITICAL/HIGH executables, and require
explicit, affirmative confirmation before continuing. Never proceed
silently past a `request_changes` verdict. If the user instead wants to
*fix* the verdict by removing the offending executables, don't refuse —
follow the pruning workflow in 5.1 (produce a pruned candidate, then a
mandatory fresh Phase 1 review) instead of promoting the flagged content
as-is.

**Content-drift caveat:** the target manifest can only reflect the
content actually reviewed in Phase 1. If the live WPP may have changed
since (new executables added, etc.) and a fresh copy is obtainable,
compare it against what Phase 1 reviewed before generating the target
manifest; if it changed, treat the existing review as stale and re-run
Phase 1 on the new content first. If no fresh copy can be obtained, tell
the user this verification couldn't be performed.

### 7.2 Determining inputs

Gather, and confirm back to the user, before generating anything:

- **The full, current WPP manifest** — not a partial excerpt. The target
  manifest must be complete and valid (`apiVersion`, `kind`, `metadata`
  including `name`/`namespace`, and the full `spec`); if only a partial
  excerpt was reviewed, ask for the complete manifest first. **If the
  complete manifest reveals containers or executables not part of the
  reviewed excerpt, that review is incomplete — go back and re-run Phase 1
  against the complete `spec.rulesByContainer` before generating any
  target manifest.** Obtaining the full manifest alone does not satisfy
  the Phase 1 gate.
- **Proposal name and namespace** (`<namespace>/<name>`) — read from
  `metadata`. Never guess.
- **Mode**: `monitor` or `protect` only. **Always ask the user explicitly
  which mode to use**, even if mentioned earlier in the conversation —
  re-confirm here rather than silently reusing an earlier value, since
  this becomes binding once applied.
- If `metadata.labels["runtimeenforcer.kubewarden.io/promote"]` is already
  present and valid, tell the user the proposal has already been promoted
  (or is mid-promotion — the controller deletes the
  `WorkloadPolicyProposal` shortly after creating the resulting
  `WorkloadPolicy`, so a WPP that still exists with this label is either
  mid-flight or leftover). **Do not** offer relabeling as a way to change
  an already-promoted policy's mode: relabeling only affects the
  `WorkloadPolicyProposal`, and once a `WorkloadPolicy` exists, the
  proposal is gone, so relabeling it (even if transiently present)
  changes nothing. If the user wants to change an existing
  `WorkloadPolicy`'s mode, that's a different operation (editing the
  `WorkloadPolicy` directly, e.g. via `runtime-enforcer policy
  monitor`/`policy protect`) outside this WPP-promotion manifest's scope.

### 7.3 Constructing the target manifest

Take the full WPP manifest from 7.2 and produce a new version that:

- Is **structurally identical** in `spec` (particularly
  `spec.rulesByContainer`) to what Phase 1 reviewed — never add, remove,
  or reorder entries in `rulesByContainer` or `executables.allowed` here.
  (Re-serializing may change formatting/quoting/indentation — fine; the
  content must not change.)
- Adds (or updates) exactly one label:
  `metadata.labels["runtimeenforcer.kubewarden.io/promote"] = <mode>`
  (creating `metadata.labels` if absent).
- Leaves every other user-managed field (`apiVersion`, `kind`,
  `metadata.name`, `metadata.namespace`, other labels/annotations, etc.)
  unchanged.
- **Removes** `status` and any server-managed metadata present only
  because the input was a live-object dump (e.g.
  `metadata.resourceVersion`, `metadata.uid`, `metadata.creationTimestamp`,
  `metadata.generation`, `metadata.managedFields`) — these don't belong in
  a manifest meant to be (re-)applied, and stale values can cause the
  apply to be rejected or misbehave. State explicitly when such fields
  were stripped.

Do not invent or rename any field beyond this sanitization.

**How to perform this edit:** this is a small, mechanical text edit (add or
update one label, strip a handful of known fields) — construct/edit the
manifest directly as text/structured content using the agent's own
capabilities. Do **not** shell out to external scripts or libraries (e.g.
Python plus a `yaml` library, `yq`, etc.) to perform it; doing so
introduces a dependency that may not be installed in the execution
environment and is unnecessary for an edit this small. If, for some other
reason, external tooling genuinely is required and unavailable, report
that plainly rather than fabricating success or silently giving up.

### 7.4 Presenting the manifest and how to apply it

Always output the target manifest as its own fenced `yaml` code block
(see section 6) **before** discussing applying it, so the user sees
exactly what would be applied. Then explain, in plain language:

- What applying it does: sets the promotion label the runtime-enforcer
  controller watches for, which asynchronously creates a `WorkloadPolicy`
  allowlisting exactly the reviewed executables, in the chosen mode.
- That the `WorkloadPolicy` is created by a separate controller
  **asynchronously**, so it may not exist immediately.

Then ask explicitly whether the user wants it applied now:

- If the agent has some other available means (e.g. another skill/tool)
  to apply Kubernetes manifests, and the user explicitly confirms
  applying it now, use that means to apply the manifest just shown. Don't
  name or assume a specific tool ahead of time — use whatever the agent's
  environment actually provides, and never fabricate cluster access that
  isn't really there. This confirmation is required every time, in
  addition to (not instead of) the `request_changes` override
  confirmation from 7.1 when applicable.
- If no such means is available, or the user doesn't confirm applying it
  now (e.g. they'll handle it themselves, or don't answer), fall back to
  generic manual instructions: offer `kubectl apply -f <file>` (or piping
  into `kubectl apply -f -`) first, and note that any equivalent tool the
  user has (`oc apply`, a GitOps commit/PR, or `runtime-enforcer proposal
  promote <name> --mode <mode> -n <namespace>` as an alternative achieving
  the same effect) works too. Don't assume any one is installed — let the
  user pick.
- Never apply the manifest silently or by assumption — an explicit,
  affirmative "yes, apply it now" is required before any apply action is
  taken on the user's behalf.

### 7.5 Verifying the outcome

If the manifest was applied manually by the user (the default path), this
skill can't confirm the outcome itself. Give the user read-only commands
to run once applied, e.g.:

- `kubectl get workloadpolicyproposal <name> -n <namespace> -o yaml` — to
  confirm the promotion label was set.
- `kubectl get workloadpolicy <name> -n <namespace>` — to confirm the
  controller created the resulting `WorkloadPolicy`.

If the agent instead applied the manifest itself via some other available
means (per 7.4), and that same means (or another available read-capable
one) can read back cluster state, use it to run the equivalent checks and
report the result. If no read-back capability is available, fall back to
the manual read-only commands above.

If the user reports the label was set but no `WorkloadPolicy` appeared
after a reasonable wait, or the apply itself failed (e.g. a conflict
because the object changed since fetched), treat this as new information
requiring investigation — don't guess at a cause without evidence.

## 8. Notes for the reviewing agent

- Never invent executables or containers not present in the input.
- Phase 1 (review) and Phase 2 (promotion) are distinct, separate actions.
  Always review and print the disclaimer and recommendation first. Only
  move into Phase 2 if the user explicitly confirms they want to proceed
  after seeing the review, and never let Phase 2 silently start on its
  own.
- Phase 2's output is **always** a YAML manifest, shown to the user
  first. By default, applying it is the user's own action (manual
  `kubectl apply`, GitOps, etc.). The agent may apply it on the user's
  behalf via some other available means (e.g. another skill/tool) **only**
  when both (a) such a means is genuinely available — never assumed or
  fabricated — and (b) the user has explicitly confirmed, in this
  conversation, they want it applied now (see 7.4), **or** section 9's
  batch-mode trigger conditions were verbatim met for this run. Absent
  that confirmation (or a validly triggered batch mode), never apply the
  manifest, run `kubectl apply`, the `runtime-enforcer` CLI, or any other
  mutating command against a live cluster — even if such tooling is
  available in the agent's environment.
- Never guess the proposal name, namespace, or any field of the target
  manifest — ask rather than assume, and never fabricate a complete
  manifest from a partial excerpt.
- Phase 2's ban on silently altering reviewed content (7.3) is not a
  blanket ban on ever editing a proposal. When a user explicitly asks to
  fix a `request_changes` verdict by removing specific flagged
  executables, use the pruning workflow in 5.1: produce the pruned
  candidate as plain text, re-run Phase 1 on it (mandatory), then proceed
  to Phase 2. Don't dead-end the user by refusing to help — point them to
  this workflow instead.
- Never process more than one proposal's full output in a single
  response when multiple proposals are in scope — see section 2.1 for
  the required one-at-a-time pacing, which prevents responses from
  being truncated by the max-output-token limit.

## 9. Batch / unattended mode (explicit opt-in)

This section defines the **only** way to process multiple WPPs (e.g. "all
WPPs in a namespace") without re-confirming mode and apply-now for each
one individually. It is a deliberate, high-risk power-user opt-in that
bypasses the per-proposal gates in 7.1 and 7.4 (including the ability to
override a `request_changes` verdict) — it must never be inferred,
assumed, or triggered partially.

### 9.1 Trigger conditions

Batch mode activates for a given run **only if** the user's single,
initiating instruction explicitly and verbatim contains **all four** of
the following signals. If even one is missing, do not activate batch
mode — process the request under the normal Phase 1/Phase 2 flow instead
(which means asking per proposal, exactly as sections 7.1/7.4 describe).

1. **Scope** — which WPPs are in play (e.g. "all WPP in namespace
   `default`", "every proposal in namespace X").
2. **Approve-everything intent** — an explicit instruction to approve/
   promote regardless of findings (e.g. "approve everything," "promote
   them all"), not merely "review them."
3. **Explicit mode** — `monitor` or `protect`, stated outright. Never
   default or infer a mode for batch mode, even if one seems "obviously"
   intended — if it's not stated, ask, and don't activate batch mode until
   it's supplied.
4. **Explicit no-further-confirmation authorization** — wording that
   plainly says not to ask again / to apply automatically (e.g. "don't ask
   me again," "apply automatically," "no need to confirm," "do this
   without further confirmation").

### 9.2 Behavior once triggered

For each WPP found in the given scope (see section 2 for enumerating a
namespace's proposals), as in section 2.1, process proposals **strictly
one at a time**: complete steps 1–4 below for one proposal in full,
labeled with its position (e.g. "Proposal 4 of 11"), before moving to
the next one in a subsequent turn — never batch more than one
proposal's full output (review + promotion) into a single response.

1. Run the full Phase 1 review (sections 1–6) and print the complete
   structured + Markdown report **and the disclaimer**, exactly as for a
   single proposal — batch mode never skips or abbreviates this
   transparency step.
2. Proceed straight to Phase 2 (section 7) for that proposal in the
   user-specified mode, without re-asking for mode or "apply now" —
   **even if** the Phase 1 verdict was `request_changes` with CRITICAL/HIGH
   findings. When this override happens, the report for that proposal
   must clearly flag it, e.g. "⚠️ Applied despite CRITICAL finding(s) X, Y
   because the user pre-authorized a full override in this run."
3. Attempt to apply the resulting manifest only if the agent has some
   other available means to do so (per 7.4); if no such means exists,
   present the manifest and state plainly that it still needs to be
   applied manually — batch mode changes *confirmation*, not *capability*.
4. If constructing or applying a given proposal's manifest fails for any
   reason, report that failure for that specific proposal and continue
   with the rest of the batch — one failure must not silently abort or
   silently skip the remaining proposals.

### 9.3 Batch summary

After processing every proposal in scope, print a final summary: total
proposals found/processed, how many were approved/applied cleanly, how
many had CRITICAL/HIGH findings that were overridden (named explicitly),
and any failures encountered. This summary is required in addition to,
not instead of, each proposal's own Phase 1/Phase 2 output.
