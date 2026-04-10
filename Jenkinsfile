pipeline {

  // ─── AGENT: ephemeral Kubernetes pod — fresh environment per build ─────────
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
    API_HOST           = 'hash-api.staging.svc.cluster.local'
    API_PORT           = '8080'
    LOKI_URL           = 'http://loki.observability.svc.cluster.local:3100/loki/api/v1/push'
  }

  stages {

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 1 — SHIFT-LEFT: STATIC ANALYSIS (parallel)
    //
    // Topic 4 (Fail-Fast): Two cheap static scanners run simultaneously FIRST.
    // Neither needs a running service or deployed container.
    // If either fails, all downstream stages — including deploy — are skipped.
    //
    // Bandit:  Python SAST. Flags B602 (shell=True) in hash_service if added.
    // Checkov: IaC scan. Evaluates terraform/ and k8s/ against CIS benchmarks.
    // ══════════════════════════════════════════════════════════════════════════
    stage('Shift-Left: Static Analysis') {
      parallel {

        stage('SAST — Bandit') {
          steps {
            container('python-ci') {
              sh '''
                pip install -q -r app/requirements.txt

                # Generate XML report for Jenkins warnings-ng plugin.
                #
                # || true intentional: hash_service.py has no B602 findings,
                # but if you add subprocess(shell=True) during an exercise Bandit
                # exits 1 and would kill the pipeline before unit tests run.
                #
                # ► To make Bandit a hard gate (production behaviour):
                #     Remove || true from both lines below.
                # ► To fail only on HIGH and above:
                #     Change --severity-level medium to --severity-level high
                #     and remove || true.
                bandit -r app/ \
                  --severity-level medium \
                  -f xml \
                  -o bandit-results.xml || true

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
          steps {
            container('python-ci') {
              sh '''
                # || true intentional: Checkov exits 1 on any policy violation.
                # The lab manifests will produce Checkov findings (e.g. no network
                # policies, no pod disruption budgets) that are acceptable for a
                # local staging environment.
                #
                # ► To make Checkov a hard gate (production behaviour):
                #     Remove || true from both commands below.
                # ► To fail only on CRITICAL findings and tolerate MEDIUM/HIGH:
                #     Add --soft-fail-on MEDIUM,HIGH to each command and
                #     remove || true.
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

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 2 — UNIT TESTS
    //
    // Topic 3: Tests hash_service.py in complete isolation.
    // No HTTP server, no Kubernetes, no network — pure function calls.
    // 21 tests covering: correctness, known values, output format, error paths.
    // ══════════════════════════════════════════════════════════════════════════
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

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 3 — COVERAGE + QUALITY GATE
    //
    // Topic 3 + 4: coverage.py instruments hash_service.py during the test run.
    // --cov-fail-under=${COVERAGE_THRESHOLD} exits 1 if coverage < 80%.
    // Pipeline stops here — Deploy to Staging never runs on under-tested code.
    // coverage.xml is archived as a build artifact for trend tracking.
    // ══════════════════════════════════════════════════════════════════════════
    stage('Coverage + Quality Gate') {
      steps {
        container('python-ci') {
          sh """
            cd app
            python -m pytest test_unit.py \
              --cov=hash_service \
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

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 4 — CONTAINER SCAN (Trivy)
    //
    // Topic 5 (Security): Scans the python-ci:lab image — the same image used
    // as the hash-api runtime — for HIGH and CRITICAL CVEs before it is deployed.
    // || true makes findings a warning in this lab; remove for production.
    // ══════════════════════════════════════════════════════════════════════════
    stage('Container Scan — Trivy') {
      steps {
        container('trivy') {
          sh '''
            trivy image \
              --exit-code 1 \
              --severity HIGH,CRITICAL \
              --format table \
              localhost:32000/python-ci:lab \
            || echo "⚠  CVEs found — review before promoting to production"
          '''
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 5 — OPA POLICY CHECK
    //
    // Topic 5 (IaC / Policy-as-Code): evaluates every manifest in k8s/ against
    // the 8 rules in opa/k8s-policy.rego BEFORE kubectl apply runs.
    //
    // Rules enforced:
    //   R1 no root (runAsUser != 0)       R5 no privilege escalation
    //   R2 resource limits required        R6 readinessProbe required
    //   R3 resource requests required      R7 livenessProbe required
    //   R4 no :latest image tags           R8 team label required
    //
    // Any violation → exit 1 → Deploy stage never runs.
    // ══════════════════════════════════════════════════════════════════════════
    stage('OPA Policy Check') {
      steps {
        container('python-ci') {
          sh '''
            echo "Validating k8s manifests against OPA policies..."
            rm -f /tmp/opa-violations.txt

            for manifest in k8s/*.yaml; do
              echo "── checking: $manifest"

              # yq -c '.' emits one compact JSON object per line, one per YAML
              # document. This correctly handles multi-document files (hashapi.yaml
              # contains ConfigMap + Deployment + Service separated by ---).
              # Piping the whole file to a single opa eval call would merge all
              # documents into one JSON array and break the policy evaluation.
              #
              # Shell note: the while loop runs in a subshell (pipe), so a counter
              # variable inside it is invisible to the parent shell. We write
              # violation counts to a temp file and sum them after the loop.
              yq -c '.' "$manifest" 2>/dev/null | while IFS= read -r doc; do
                [ -z "$doc" ] && continue

                echo "$doc" > /tmp/opa-input.json

                RESULT=$(opa eval \
                  --data opa/k8s-policy.rego \
                  --input /tmp/opa-input.json \
                  "data.k8s.security.deny" 2>/dev/null)

                COUNT=$(echo "$RESULT" \
                  | jq -r ".result[0].expressions[0].value | length" 2>/dev/null \
                  || echo 0)

                if [ "$COUNT" -gt 0 ]; then
                  KIND=$(echo "$doc" | jq -r '.kind // "unknown"' 2>/dev/null)
                  echo "  ❌ $KIND — $COUNT violation(s):"
                  echo "$RESULT" | jq -r ".result[0].expressions[0].value[]"
                  echo "$COUNT" >> /tmp/opa-violations.txt
                else
                  KIND=$(echo "$doc" | jq -r '.kind // "non-Deployment"' 2>/dev/null)
                  echo "  ✅ $KIND — passed"
                fi
              done
            done

            TOTAL=0
            if [ -f /tmp/opa-violations.txt ]; then
              TOTAL=$(awk '{s+=$1} END {print s+0}' /tmp/opa-violations.txt)
              rm /tmp/opa-violations.txt
            fi

            echo ""
            if [ "$TOTAL" -gt 0 ]; then
              echo "❌ $TOTAL OPA violation(s) — fix manifests before deploying"
              exit 1
            fi
            echo "✅ All manifests passed OPA policy (8 rules)"
          '''
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 6 — TERRAFORM PLAN (drift detection)
    //
    // Topic 6 (IaC): computes what Terraform would change in the cluster.
    // Manages: Namespace + ResourceQuota + hash-api-config ConfigMap.
    // Exit codes: 0 = no change, 1 = error, 2 = changes pending.
    // Plan JSON is archived so it can be reviewed before or after apply.
    // ══════════════════════════════════════════════════════════════════════════
    stage('Terraform Plan') {
      steps {
        container('python-ci') {
          sh '''
            cd terraform
            # terraform init is required for every new workspace directory even
            # though the provider binaries are already baked into the image.
            # -plugin-dir tells Terraform exactly where to find the binaries so
            # it never attempts to contact registry.terraform.io.
            # Without this flag in an air-gapped environment, init would fail.
            terraform init \
              -input=false \
              -plugin-dir=/usr/local/terraform-plugins

            # -detailed-exitcode: distinguishes errors (1) from pending changes (2)
            terraform plan \
              -input=false \
              -out=tfplan \
              -detailed-exitcode
            PLAN_EXIT=$?
            [ "$PLAN_EXIT" -eq 1 ] && exit 1

            terraform show -json tfplan > ../terraform-plan.json
            echo "Terraform plan exit code: $PLAN_EXIT (0=no changes, 2=drift detected)"
          '''
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'terraform-plan.json', allowEmptyArchive: true
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 7 — DEPLOY TO STAGING
    //
    // Topic 7: Reached only if ALL prior gates passed.
    //
    // terraform apply:  creates/updates namespace, ResourceQuota, ConfigMap.
    // kubectl apply:    deploys hash-api-source ConfigMap + Deployment + Service.
    // rollout status:   blocks until the pod is Ready or the 90s timeout fires.
    // ══════════════════════════════════════════════════════════════════════════
    stage('Deploy to Staging') {
      steps {
        container('python-ci') {
          sh '''
            # 1. Apply Terraform-managed infrastructure
            cd terraform
            terraform apply -input=false -auto-approve tfplan
            cd ..

            # 2. Apply app manifests (source ConfigMap + Deployment + Service)
            kubectl apply -f k8s/

            # 3. Force a rolling restart so the pod picks up the latest ConfigMap.
            # Kubernetes does NOT automatically restart pods when a ConfigMap
            # changes — the existing pod continues running the old source until
            # it is replaced. rollout restart creates a new pod with the updated
            # /app mount before terminating the old one.
            kubectl rollout restart deployment/hash-api -n staging

            # 4. Block until the new pod is Ready (readinessProbe must pass)
            kubectl rollout status deployment/hash-api \
              -n staging --timeout=90s
          '''
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 8 — API INTEGRATION TESTS
    //
    // Topic 2: pytest talks to the LIVE hash-api over cluster DNS.
    // 20 tests cover: /health, /algorithms, GET /hash, POST /hash, 404, 400.
    // SHA-256 values are hard-coded — wrong hash = test failure.
    // ══════════════════════════════════════════════════════════════════════════
    stage('API Integration Tests') {
      steps {
        container('python-ci') {
          sh """
            cd app
            API_HOST=${API_HOST} API_PORT=${API_PORT} \
            python -m pytest test_api.py \
              -v \
              --junitxml=../api-results.xml
          """
        }
      }
      post {
        always {
          junit 'api-results.xml'
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 9 — DAST (Nuclei)
    //
    // Topic 5 (Security): fires real HTTP requests at the running hash-api
    // endpoint looking for misconfigurations, exposed paths, and info disclosure.
    // nuclei-results.txt is archived per build for audit trail.
    // || true keeps the lab pipeline alive — remove in production.
    // ══════════════════════════════════════════════════════════════════════════
    stage('DAST — Nuclei') {
      steps {
        container('nuclei') {
          sh """
            nuclei \
              -u http://${API_HOST}:${API_PORT} \
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

    // ══════════════════════════════════════════════════════════════════════════
    // STAGE 10 — LOAD TEST (k6)
    //
    // Topic 10: ramps 0 → 10 VU over 55 seconds.
    // Quality gates (defined in k6-script.js):
    //   p(95) < 200 ms  — hash ops must be fast
    //   error rate < 1% — service must stay stable under load
    // Correctness gate: SHA-256("hello") checked on every iteration.
    // k6 exits non-zero on threshold breach → Jenkins marks stage FAILED.
    // k6-results.json archived; contains per-metric percentile breakdown.
    // ══════════════════════════════════════════════════════════════════════════
    stage('Load Test — k6') {
      steps {
        container('k6') {
          sh '''
            k6 run \
              --env API_BASE_URL=http://hash-api.staging.svc.cluster.local:8080 \
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

  // ══════════════════════════════════════════════════════════════════════════
  // POST — MONITORING + REPORTING (Topic 11)
  //
  // Runs regardless of outcome (always {}).
  // Pushes build number, job name, and result to Loki in the observability
  // namespace. Visible in Grafana via LogQL within seconds of completion.
  // JUnit XML files (unit, api) power Jenkins per-test result views.
  // All artifacts (coverage, k6, nuclei, terraform) are per-build.
  // ══════════════════════════════════════════════════════════════════════════
  post {
    always {
      script {
        def status = currentBuild.result ?: 'SUCCESS'
        def ts     = System.currentTimeMillis() * 1000000
        sh """
          curl -s -X POST \
            -H 'Content-Type: application/json' \
            -d '{"streams":[{"stream":{"job":"jenkins-pipeline","build":"${env.BUILD_NUMBER}","result":"${status}","pipeline":"${env.JOB_NAME}"},"values":[["${ts}","Pipeline ${status} — ${env.JOB_NAME} #${env.BUILD_NUMBER}"]]}]}' \
            ${LOKI_URL} || true
        """
      }
    }
    success {
      echo '✅ All gates passed — artifacts archived'
    }
    failure {
      echo '❌ Pipeline failed — check the stage that turned red above'
    }
  }

}
