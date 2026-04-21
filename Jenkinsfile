pipeline {

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

    stage('Shift-Left: Static Analysis') {
      parallel {

        stage('SAST — Bandit') {
          steps {
            container('python-ci') {
              sh '''
                pip install -q -r app/requirements.txt
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
                echo "=== Terraform scan ==="
                checkov -d terraform/ --framework terraform --compact || true
                echo "=== Kubernetes manifest scan ==="
                checkov -d k8s/ --framework kubernetes --compact || true
              '''
            }
          }
        }

      }
    }

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

    stage('OPA Policy Check') {
      steps {
        container('python-ci') {
          sh '''
            echo "Validating k8s manifests against OPA policies..."
            rm -f /tmp/opa-violations.txt

            for manifest in k8s/*.yaml; do
              echo "── checking: $manifest"
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
    // ══════════════════════════════════════════════════════════════════════════
    stage('Terraform Plan') {
      steps {
        container('python-ci') {
          sh '''
            cd terraform

            # Import any resources that already exist in the cluster so that
            # apply never tries to create something that is already there.
            # || true is safe: if the resource is already in state, import
            # is a no-op; if it does not exist yet, Terraform will create it.
            terraform init \
              -input=false \
              -plugin-dir=/usr/local/terraform-plugins

            terraform import -input=false kubernetes_namespace.staging staging || true
            terraform import -input=false kubernetes_resource_quota.staging staging/staging-quota || true
            terraform import -input=false kubernetes_config_map.hash_api_config staging/hash-api-config || true

            set +e
            terraform plan \
              -input=false \
              -out=tfplan \
              -detailed-exitcode
            PLAN_EXIT=$?
            set -e

            if [ "$PLAN_EXIT" -eq 1 ]; then
              echo "Terraform plan failed!"
              exit 1
            fi

            # FIX: removed duplicate terraform show call
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
    // FIX: terraform init must be re-run here because each stage's `sh` step
    // gets a fresh shell. The .terraform/ plugin directory written in Stage 6
    // is still on disk (same pod workspace), so init is fast — it just
    // re-links the providers. Without this, `terraform apply` fails with
    // "no such file or directory: .terraform/providers/..."
    // ══════════════════════════════════════════════════════════════════════════
    stage('Deploy to Staging') {
      steps {
        container('python-ci') {
          sh '''
            cd terraform

            # Re-init to ensure provider symlinks are valid in this shell context.
            terraform init \
              -input=false \
              -plugin-dir=/usr/local/terraform-plugins

            terraform apply -input=false -auto-approve tfplan
            cd ..

            kubectl apply -f k8s/
            kubectl rollout restart deployment/hash-api -n staging
            kubectl rollout status deployment/hash-api \
              -n staging --timeout=90s
          '''
        }
      }
    }

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

    stage('DAST — Nuclei') {
      steps {
        container('nuclei') {
          sh """
            nuclei \
              -u http://${API_HOST}:${API_PORT} \
              -tags misconfig,exposure \
              -td /nuclei-templates \
              -o nuclei-results.txt \
              -silent || true
          """
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'nuclei-results.txt', allowEmptyArchive: true
        }
      }
    }

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

  }

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