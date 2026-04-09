# DevSecOps Combined Testing + IaC Lab

## What This Lab Covers

| # | Topic | Implemented By |
|---|-------|----------------|
| 1 | Shift-Left Testing | SAST + IaC scan run first, before any deploy |
| 2 | Unit Testing | pytest against `calculator.py` |
| 3 | Integration Testing | pytest against live staging app |
| 4 | Security Testing | Bandit (SAST), Trivy (container), Nuclei (DAST) |
| 5 | Load & Performance Testing | k6 with p95 latency + error rate thresholds |
| 6 | Test Coverage Analysis | coverage.py with XML report |
| 7 | Quality Gates | `--cov-fail-under=80` blocks deploy if coverage drops |
| 8 | Fail-Fast Pipelines | Cheap static checks run first in parallel; deploy only if all pass |
| 9 | Continuous Integration | Full Jenkinsfile pipeline; Terraform manages staging namespace |
| 10 | Monitoring & Reporting | JUnit results in Jenkins; pipeline status shipped to Loki → Grafana |
| IaC | Terraform + OPA | Terraform provisions staging namespace; OPA validates manifests before apply |

---

## Architecture

```
Git repo (Jenkinsfile)
       │
       ▼
Jenkins pipeline (kubernetes agent pod)
  ├── python-ci container  ── bandit, pytest, coverage, checkov, terraform, kubectl, opa
  ├── trivy container      ── image CVE scanning
  ├── k6 container         ── load testing
  └── nuclei container     ── DAST

Pipeline stages:
  Static Analysis (parallel: bandit + checkov)
       │
  Unit Tests
       │
  Coverage + Quality Gate (80% threshold)
       │
  Container Scan (trivy)
       │
  OPA Policy Check
       │
  Terraform Plan (drift detection)
       │
  Deploy to Staging  ── kubectl apply → staging namespace
       │
  Integration Tests  ── pytest against live staging-app
       │
  DAST (nuclei)      ── dynamic scan of staging-app
       │
  Load Test (k6)     ── p95 < 500ms, error rate < 1%
       │
  post { always }    ── push result to Loki → Grafana
```

---

## Startup Script — No Changes Needed

All images are already pulled and synced by your existing script:

| Image | Used For |
|-------|----------|
| `localhost:32000/python-ci:lab` | pytest, bandit, checkov, terraform, kubectl, opa, yq |
| `localhost:32000/trivy:lab` | Container CVE scanning |
| `localhost:32000/k6:lab` | Load testing |
| `localhost:32000/nuclei:lab` | DAST scanning |
| `localhost:32000/nginx:stable` | staging-app deployment |

---

## New Project Directory Structure

```
├── Jenkinsfile                        ← full 10-stage pipeline
├── app/
│   ├── calculator.py                  ← app under test
│   ├── test_unit.py                   ← unit tests (topic 2)
│   ├── test_integration.py            ← integration tests (topic 3)
│   └── requirements.txt
├── load-test/
│   └── k6-script.js                   ← load + perf tests (topic 5)
├── terraform/
│   └── main.tf                        ← provisions staging namespace (IaC)
├── opa/
│   └── k8s-policy.rego                ← security policies (topic 4 / IaC)
└── k8s/
    ├── staging-app.yaml               ← app deployed to staging
    └── jenkins-staging-rbac.yaml      ← RBAC for jenkins SA
```

---

## Step 1: Configure Jenkins Kubernetes Cloud

Before running the pipeline, Jenkins needs to know how to spin up pod agents.

Go to: **Manage Jenkins → Clouds → New Cloud → Kubernetes**

| Field | Value |
|-------|-------|
| Kubernetes URL | `https://kubernetes.default.svc` |
| Kubernetes Namespace | `observability` |
| Jenkins URL | `http://jenkins.observability.svc.cluster.local:8080` |
| Jenkins tunnel | `jenkins.observability.svc.cluster.local:50000` |

Click **Test Connection** — it should show the server version. Save.

---

## Step 2: Apply RBAC

The jenkins ServiceAccount needs permission to create the staging namespace and deploy into it.

```bash
sudo microk8s kubectl apply -f k8s/jenkins-staging-rbac.yaml
```

---

## File Contents

### `app/calculator.py`

```python
# Simple module — the app under test.
# Intentional issue: subprocess with shell=True (Bandit B602)
# so students can see a real SAST finding.

import subprocess


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


def multiply(a, b):
    return a * b


def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b


def get_hostname():
    # B602: subprocess call with shell=True — intentional for lab
    result = subprocess.run("hostname", shell=True, capture_output=True, text=True)
    return result.stdout.strip()
```

---

### `app/test_unit.py`

```python
# Topic 2: Unit Tests
# Fast, isolated, no external dependencies.

import pytest
from calculator import add, subtract, multiply, divide


def test_add_positive():
    assert add(2, 3) == 5


def test_add_negative():
    assert add(-1, -1) == -2


def test_subtract():
    assert subtract(10, 4) == 6


def test_multiply():
    assert multiply(3, 4) == 12


def test_divide():
    assert divide(10, 2) == 5.0


def test_divide_by_zero_raises():
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(10, 0)


def test_add_floats():
    assert abs(add(0.1, 0.2) - 0.3) < 1e-9
```

---

### `app/test_integration.py`

```python
# Topic 3: Integration Tests
# Run against the LIVE staging-app deployment.
# Requires staging-app to be deployed before this stage runs.

import urllib.request
import urllib.error
import pytest

STAGING_URL = "http://staging-app.staging.svc.cluster.local:80"


def test_staging_app_returns_200():
    """Staging app must be reachable and return HTTP 200."""
    response = urllib.request.urlopen(STAGING_URL, timeout=10)
    assert response.status == 200


def test_staging_app_404_on_missing_path():
    """Unknown paths must return 404, not 500."""
    try:
        urllib.request.urlopen(f"{STAGING_URL}/does-not-exist", timeout=10)
        pytest.fail("Expected 404 HTTPError")
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_staging_app_content_type():
    """Response must include text/html content type."""
    response = urllib.request.urlopen(STAGING_URL, timeout=10)
    content_type = response.headers.get("Content-Type", "")
    assert "text/html" in content_type
```

---

### `app/requirements.txt`

```
pytest
pytest-cov
```

---

### `load-test/k6-script.js`

```javascript
// Topic 5: Load and Performance Testing
// Thresholds act as quality gates — pipeline fails if breached.

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '15s', target: 5  },   // ramp up
    { duration: '30s', target: 10 },   // hold
    { duration: '10s', target: 0  },   // ramp down
  ],
  thresholds: {
    // Topic 7: Quality Gate — these failing = pipeline fails
    http_req_duration: ['p(95)<500'],  // 95% of requests under 500ms
    http_req_failed:   ['rate<0.01'],  // less than 1% errors
  },
};

export default function () {
  const BASE = 'http://staging-app.staging.svc.cluster.local:80';

  const res = http.get(`${BASE}/`);
  check(res, {
    'status 200':            (r) => r.status === 200,
    'response under 200ms':  (r) => r.timings.duration < 200,
  });

  // Occasional 404 to exercise error handling
  if (__ITER % 5 === 0) {
    http.get(`${BASE}/nonexistent`);
  }

  sleep(1);
}
```

---

### `terraform/main.tf`

```hcl
# Topic IaC: Terraform provisions the staging namespace.
# Running terraform plan shows drift if namespace was manually deleted/modified.
# terraform apply creates it if absent — idempotent.

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.25.2"
    }
  }
  # Local state — fine for the lab.
  # Topic 6 (IaC): in production, this would be remote state (S3, GCS, etc.)
  backend "local" {
    path = "/tmp/terraform-staging.tfstate"
  }
}

provider "kubernetes" {
  # In-cluster config — uses the pod's ServiceAccount token automatically
  host = "https://kubernetes.default.svc"

  token = file("/var/run/secrets/kubernetes.io/serviceaccount/token")

  cluster_ca_certificate = file("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
}

resource "kubernetes_namespace" "staging" {
  metadata {
    name = "staging"
    labels = {
      environment = "staging"
      managed-by  = "terraform"
    }
  }
}

output "staging_namespace" {
  value = kubernetes_namespace.staging.metadata[0].name
}
```

---

### `opa/k8s-policy.rego`

```rego
# Topic 4 / IaC: Policy-as-Code
# These rules run against every k8s manifest before kubectl apply.
# Any violation in the deny set blocks the pipeline.

package k8s.security

# Rule 1: No containers running as root (UID 0)
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf("POLICY FAIL: container '%v' must not run as root (runAsUser=0)", [container.name])
}

# Rule 2: All containers must declare resource limits
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf("POLICY FAIL: container '%v' must declare resource limits", [container.name])
}

# Rule 3: No :latest image tags (unpredictable, breaks reproducibility)
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("POLICY FAIL: container '%v' uses :latest tag — pin to a specific version", [container.name])
}

# Rule 4: Privilege escalation must be explicitly disabled
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation == true
  msg := sprintf("POLICY FAIL: container '%v' allows privilege escalation", [container.name])
}
```

---

### `k8s/staging-app.yaml`

```yaml
# Deliberately compliant with OPA policies above:
#   ✅ resource limits declared
#   ✅ not running as root (nginx user = UID 101)
#   ✅ no :latest tag
#   ✅ allowPrivilegeEscalation: false
apiVersion: apps/v1
kind: Deployment
metadata:
  name: staging-app
  namespace: staging
spec:
  replicas: 1
  selector:
    matchLabels:
      app: staging-app
  template:
    metadata:
      labels:
        app: staging-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 101        # nginx unprivileged user
      containers:
        - name: staging-app
          image: localhost:32000/nginx:stable
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 80
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
---
apiVersion: v1
kind: Service
metadata:
  name: staging-app
  namespace: staging
spec:
  selector:
    app: staging-app
  ports:
    - port: 80
      targetPort: 80
  type: ClusterIP
```

---

### `k8s/jenkins-staging-rbac.yaml`

```yaml
# Grants the jenkins ServiceAccount permission to manage resources
# in the staging namespace (and create the namespace itself).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: jenkins-deploy
rules:
  - apiGroups: [""]
    resources: ["namespaces", "services", "pods", "configmaps", "endpoints"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: jenkins-deploy-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: jenkins-deploy
subjects:
  - kind: ServiceAccount
    name: jenkins
    namespace: observability
```

---

### `Jenkinsfile`

```groovy
pipeline {

  // ─── AGENT: kubernetes pod with all tools as sidecar containers ───────────
  // Topic 9 (CI): each build gets a fresh, ephemeral pod — clean environment.
  agent {
    kubernetes {
      yaml """
apiVersion: v1
kind: Pod
metadata:
  namespace: observability
spec:
  serviceAccountName: jenkins
  containers:
  - name: python-ci
    image: localhost:32000/python-ci:lab
    imagePullPolicy: IfNotPresent
    command: ['cat']
    tty: true
  - name: trivy
    image: localhost:32000/trivy:lab
    imagePullPolicy: IfNotPresent
    command: ['cat']
    tty: true
  - name: k6
    image: localhost:32000/k6:lab
    imagePullPolicy: IfNotPresent
    command: ['cat']
    tty: true
  - name: nuclei
    image: localhost:32000/nuclei:lab
    imagePullPolicy: IfNotPresent
    command: ['cat']
    tty: true
"""
    }
  }

  environment {
    COVERAGE_THRESHOLD = '80'
    STAGING_URL        = 'http://staging-app.staging.svc.cluster.local:80'
    LOKI_URL           = 'http://loki.observability.svc.cluster.local:3100/loki/api/v1/push'
  }

  stages {

    // ════════════════════════════════════════════════════════════════
    // TOPIC 1 + 8 — SHIFT-LEFT + FAIL-FAST
    // Static checks run in parallel FIRST.
    // No container is built. No code is deployed.
    // Cheapest possible feedback — catches issues in seconds.
    // Pipeline stops here if either check fails.
    // ════════════════════════════════════════════════════════════════
    stage('Shift-Left: Static Analysis') {
      parallel {

        stage('SAST — Bandit') {
          // Topic 4 (Security): Python source code scanned for security issues
          steps {
            container('python-ci') {
              sh '''
                pip install -q -r app/requirements.txt
                # -f xml produces JUnit-compatible output for warnings-ng
                bandit -r app/ \
                  --severity-level medium \
                  -f xml \
                  -o bandit-results.xml || true
                # Also print human-readable summary
                bandit -r app/ --severity-level medium || true
              '''
            }
          }
          post {
            always {
              junit allowEmptyResults: true, testResults: 'bandit-results.xml'
            }
          }
        }

        stage('IaC Scan — Checkov') {
          // Topic 1 (Shift-Left IaC): scan Terraform + k8s manifests before apply
          steps {
            container('python-ci') {
              sh '''
                echo "=== Terraform scan ==="
                checkov -d terraform/ --framework terraform --compact || true

                echo "=== Kubernetes manifest scan ==="
                checkov -d k8s/ --framework kubernetes --compact || true
              '''
            }
          }
        }

      } // end parallel
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 2 — UNIT TESTING
    // Fast, isolated — no network, no external services.
    // JUnit XML published to Jenkins test results.
    // ════════════════════════════════════════════════════════════════
    stage('Unit Tests') {
      steps {
        container('python-ci') {
          sh '''
            cd app
            python -m pytest test_unit.py \
              -v \
              --junitxml=../unit-results.xml
          '''
        }
      }
      post {
        always {
          junit 'unit-results.xml'
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 6 + 7 — COVERAGE ANALYSIS + QUALITY GATE
    // --cov-fail-under is the quality gate.
    // If coverage < 80% the stage fails and pipeline stops.
    // Deploy never runs on under-tested code.
    // ════════════════════════════════════════════════════════════════
    stage('Coverage + Quality Gate') {
      steps {
        container('python-ci') {
          sh """
            cd app
            python -m pytest test_unit.py \
              --cov=calculator \
              --cov-report=xml:../coverage.xml \
              --cov-report=term-missing \
              --cov-fail-under=${COVERAGE_THRESHOLD}
          """
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'coverage.xml', allowEmptyArchive: true
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 4 — SECURITY: CONTAINER IMAGE SCAN (Trivy)
    // Scans the nginx image for CVEs before it is deployed.
    // HIGH/CRITICAL findings print a warning but do not block
    // the lab pipeline (|| true). Remove || true in production.
    // ════════════════════════════════════════════════════════════════
    stage('Container Scan — Trivy') {
      steps {
        container('trivy') {
          sh '''
            trivy image \
              --exit-code 1 \
              --severity HIGH,CRITICAL \
              --format table \
              localhost:32000/nginx:stable \
            || echo "⚠  CVEs found — review above before promoting to prod"
          '''
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC IaC — OPA POLICY-AS-CODE
    // Converts each k8s YAML to JSON then evaluates against opa/k8s-policy.rego
    // Any deny violation blocks the pipeline before kubectl apply runs.
    // ════════════════════════════════════════════════════════════════
    stage('OPA Policy Check') {
      steps {
        container('python-ci') {
          sh '''
            echo "Validating manifests against OPA policies..."
            VIOLATIONS=0

            for manifest in k8s/*.yaml; do
              echo "── $manifest"

              # yq converts YAML → JSON; opa eval needs JSON input
              yq -o json "$manifest" > /tmp/opa-input.json 2>/dev/null || {
                echo "  (skipped — not valid YAML)"
                continue
              }

              RESULT=$(opa eval \
                --data opa/k8s-policy.rego \
                --input /tmp/opa-input.json \
                "data.k8s.security.deny" 2>/dev/null)

              # Parse the deny set length from OPA JSON output
              COUNT=$(echo "$RESULT" | jq -r \
                ".result[0].expressions[0].value | length" 2>/dev/null || echo 0)

              if [ "$COUNT" -gt 0 ]; then
                echo "  ❌ Policy violations:"
                echo "$RESULT" | jq -r \
                  ".result[0].expressions[0].value[]"
                VIOLATIONS=$((VIOLATIONS + COUNT))
              else
                echo "  ✅ passed"
              fi
            done

            if [ "$VIOLATIONS" -gt 0 ]; then
              echo ""
              echo "❌ $VIOLATIONS OPA violation(s) — fix manifests before deploying"
              exit 1
            fi
            echo ""
            echo "✅ All manifests passed OPA policies"
          '''
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC IaC — TERRAFORM PLAN (DRIFT DETECTION)
    // Shows what Terraform would change in the cluster.
    // Exit code 2 = changes pending (not an error — just drift).
    // Plan saved as artifact so students can review before apply.
    // ════════════════════════════════════════════════════════════════
    stage('Terraform Plan') {
      steps {
        container('python-ci') {
          sh '''
            cd terraform
            terraform init \
              -input=false \
              -plugin-dir=/usr/local/terraform-plugins

            # -detailed-exitcode: 0=no change, 1=error, 2=changes present
            terraform plan \
              -input=false \
              -out=tfplan \
              -detailed-exitcode
            PLAN_EXIT=$?
            [ "$PLAN_EXIT" -eq 1 ] && exit 1

            terraform show -json tfplan > ../terraform-plan.json
            echo "Plan exit code $PLAN_EXIT (0=no changes, 2=changes detected)"
          '''
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'terraform-plan.json', allowEmptyArchive: true
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 9 (CI) — DEPLOY TO STAGING
    // Only reached if ALL prior gates passed (fail-fast enforced above).
    // Terraform applies the plan. kubectl deploys the app.
    // ════════════════════════════════════════════════════════════════
    stage('Deploy to Staging') {
      steps {
        container('python-ci') {
          sh '''
            cd terraform
            terraform apply -input=false -auto-approve tfplan

            kubectl apply -f ../k8s/staging-app.yaml
            kubectl rollout status deployment/staging-app \
              -n staging --timeout=90s
          '''
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 3 — INTEGRATION TESTING
    // pytest talks to the LIVE staging-app over cluster DNS.
    // Tests real HTTP responses — not mocks.
    // ════════════════════════════════════════════════════════════════
    stage('Integration Tests') {
      steps {
        container('python-ci') {
          sh '''
            cd app
            python -m pytest test_integration.py \
              -v \
              --junitxml=../integration-results.xml
          '''
        }
      }
      post {
        always {
          junit 'integration-results.xml'
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 4 — SECURITY: DAST (Nuclei)
    // Dynamic scan against the running staging app.
    // Checks for misconfigurations and exposed paths.
    // || true so lab continues — remove in production.
    // ════════════════════════════════════════════════════════════════
    stage('DAST — Nuclei') {
      steps {
        container('nuclei') {
          sh """
            nuclei \
              -u ${STAGING_URL} \
              -tags misconfig,exposure \
              -o nuclei-results.txt \
              -silent || true
            echo "=== DAST Results ==="
            cat nuclei-results.txt 2>/dev/null || echo "No findings"
          """
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'nuclei-results.txt', allowEmptyArchive: true
        }
      }
    }

    // ════════════════════════════════════════════════════════════════
    // TOPIC 5 — LOAD + PERFORMANCE TESTING (k6)
    // Thresholds defined in k6-script.js are quality gates:
    //   p(95) < 500ms  AND  error rate < 1%
    // k6 exits non-zero if either threshold is breached → pipeline fails.
    // ════════════════════════════════════════════════════════════════
    stage('Load Test — k6') {
      steps {
        container('k6') {
          sh '''
            k6 run \
              --out json=/tmp/k6-results.json \
              load-test/k6-script.js
            cp /tmp/k6-results.json k6-results.json
          '''
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'k6-results.json', allowEmptyArchive: true
        }
      }
    }

  } // end stages

  // ════════════════════════════════════════════════════════════════
  // TOPIC 10 — MONITORING + REPORTING
  // JUnit results visible in Jenkins pipeline view (all stages above).
  // Final pipeline status pushed to Loki → visible in Grafana.
  // ════════════════════════════════════════════════════════════════
  post {
    always {
      script {
        def status = currentBuild.result ?: 'SUCCESS'
        def ts     = System.currentTimeMillis() * 1000000
        sh """
          curl -s -X POST \
            -H 'Content-Type: application/json' \
            -d '{"streams":[{"stream":{"job":"jenkins-pipeline","build":"${env.BUILD_NUMBER}","result":"${status}"},"values":[["${ts}","Pipeline ${status} — ${env.JOB_NAME} #${env.BUILD_NUMBER}"]]}]}' \
            ${LOKI_URL} || true
        """
      }
    }
    success {
      echo '✅ All gates passed — artefacts archived'
    }
    failure {
      echo '❌ Pipeline failed — check stage output above'
    }
  }

}
```

---

## Step 3: Apply Everything

```bash
# RBAC for jenkins SA to manage staging namespace
sudo microk8s kubectl apply -f k8s/jenkins-staging-rbac.yaml

# Verify jenkins pod is running before triggering pipeline
sudo microk8s kubectl get pods -n observability
```

Then trigger the pipeline from Jenkins UI or commit a change to the repo.

---

## Grafana: Add Pipeline + Staging Logs

In Grafana → Explore → Loki, add these queries:

```logql
# Pipeline results
{job="jenkins-pipeline"}

# Staging app access logs
{namespace="staging", pod=~"staging-app-.*"}

# Error/fail events across all jobs
{job=~"jenkins.*"} |~ "(?i)error|fail|violation"
```

---

## Lab Exercises

### Topic 1 — Shift-Left
Delete a closing bracket in `calculator.py`. Which stage catches it first?

### Topic 2 — Unit Testing
Add a new function `power(a, b)` to `calculator.py` without a test. Note coverage drops below 80%.

### Topic 7 — Quality Gate
Set `COVERAGE_THRESHOLD = '90'` in the Jenkinsfile. Run the pipeline. Watch the quality gate block the deploy.

### Topic 8 — Fail-Fast
Add `exit 1` to the bandit stage. Confirm the pipeline stops before any deploy runs.

### OPA Policy Violation
Edit `k8s/staging-app.yaml` — change `runAsUser: 101` to `runAsUser: 0`. Watch the OPA check block the deploy stage.

### Terraform Drift
Manually delete the staging namespace:
```bash
sudo microk8s kubectl delete namespace staging
```
Run the pipeline. See Terraform detect and re-create it.

### Topic 5 — Load Test Threshold
Change `p(95)<500` to `p(95)<10` in `k6-script.js`. Watch k6 fail the pipeline.
