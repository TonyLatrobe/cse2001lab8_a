# Eight policy rules. The first four match the original lab. The new rules (5–8) enforce operational quality: health probes, resource requests, and team ownership labels. Any violation in the `deny` set exits the pipeline before `kubectl apply` runs.

# rego
# opa/k8s-policy.rego
# Policy-as-Code: evaluated against every k8s manifest before kubectl apply.
# Any non-empty deny set exits the pipeline with code 1.

package k8s.security

# ── Rule 1: No containers running as root (UID 0) ────────────────────────────
# Root inside a container is root on the node if the container runtime is misconfigured.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf(
    "POLICY FAIL [R1]: container '%v' must not run as root (runAsUser=0)",
    [container.name]
  )
}

# ── Rule 2: Resource limits required ─────────────────────────────────────────
# Without limits a single pod can exhaust all node memory and cause an OOM eviction.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf(
    "POLICY FAIL [R2]: container '%v' must declare resources.limits",
    [container.name]
  )
}

# ── Rule 3: Resource requests required ───────────────────────────────────────
# Without requests the scheduler cannot make placement decisions or enforce QoS.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.requests
  msg := sprintf(
    "POLICY FAIL [R3]: container '%v' must declare resources.requests",
    [container.name]
  )
}

# ── Rule 4: No :latest image tags ────────────────────────────────────────────
# :latest is non-deterministic — the same tag can resolve to different images on each pull.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf(
    "POLICY FAIL [R4]: container '%v' uses ':latest' tag — pin to a digest or version",
    [container.name]
  )
}

# ── Rule 5: Privilege escalation must be disabled ────────────────────────────
# allowPrivilegeEscalation: true lets a process gain more privileges than its parent.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation == true
  msg := sprintf(
    "POLICY FAIL [R5]: container '%v' allows privilege escalation",
    [container.name]
  )
}

# ── Rule 6: readinessProbe required ──────────────────────────────────────────
# Without a readinessProbe Kubernetes routes traffic before the app is ready,
# causing request failures during startup and rolling updates.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.readinessProbe
  msg := sprintf(
    "POLICY FAIL [R6]: container '%v' must define a readinessProbe",
    [container.name]
  )
}

# ── Rule 7: livenessProbe required ───────────────────────────────────────────
# Without a livenessProbe Kubernetes cannot detect and restart a deadlocked process.
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.livenessProbe
  msg := sprintf(
    "POLICY FAIL [R7]: container '%v' must define a livenessProbe",
    [container.name]
  )
}

# ── Rule 8: team label required on pod template ───────────────────────────────
# Enables cost attribution, on-call routing, and kubectl filtering by team.
deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.metadata.labels.team
  msg := sprintf(
    "POLICY FAIL [R8]: Deployment '%v' pod template must carry a 'team' label",
    [input.metadata.name]
  )
}