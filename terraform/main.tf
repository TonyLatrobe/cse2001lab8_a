# terraform/main.tf
# IaC: Terraform provisions staging infrastructure.
# Manages: Namespace, ResourceQuota, ConfigMap (app config).
# App Deployment + Service are managed by kubectl (see k8s/hashapi.yaml).
# Run terraform plan to detect drift; exit code 2 = changes pending (not an error).

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.25.2"
    }
  }

  # Kubernetes backend — persists state inside the cluster (Secret).
  # This makes CI/CD runs idempotent even with ephemeral Jenkins agents.
  backend "kubernetes" {
    secret_suffix = "terraform-state"
    namespace     = "observability"
  }
}

provider "kubernetes" {
  # In-cluster config — consumes the pod's own ServiceAccount token.
  host                   = "https://kubernetes.default.svc"
  token                  = file("/var/run/secrets/kubernetes.io/serviceaccount/token")
  cluster_ca_certificate = file("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
}

# ── Namespace ──────────────────────────────────────────────────────────────────

resource "kubernetes_namespace" "staging" {
  metadata {
    name = "staging"
    labels = {
      environment = "staging"
      managed-by  = "terraform"
    }
  }
}

# ── ResourceQuota ──────────────────────────────────────────────────────────────
# Enforces a hard ceiling on total resources consumed in the staging namespace.
# Prevents runaway load tests or misconfigurations from starving the cluster.

resource "kubernetes_resource_quota" "staging" {
  metadata {
    name      = "staging-quota"
    namespace = kubernetes_namespace.staging.metadata[0].name
    labels = {
      managed-by = "terraform"
    }
  }

  spec {
    hard = {
      "requests.cpu"    = "500m"
      "requests.memory" = "512Mi"
      "limits.cpu"      = "1000m"
      "limits.memory"   = "1Gi"
      "pods"            = "10"
    }
  }
}

# ── ConfigMap: runtime config ──────────────────────────────────────────────────
# Injected into the hash-api pod as environment variables.
# Change LOG_LEVEL or PORT here, re-run terraform apply, then redeploy — no image rebuild.

resource "kubernetes_config_map" "hash_api_config" {
  metadata {
    name      = "hash-api-config"
    namespace = kubernetes_namespace.staging.metadata[0].name
    labels = {
      managed-by = "terraform"
      app        = "hash-api"
    }
  }

  data = {
    LOG_LEVEL = "INFO"
    PORT      = "8080"
  }
}

# ── Outputs ────────────────────────────────────────────────────────────────────

output "staging_namespace" {
  value = kubernetes_namespace.staging.metadata[0].name
}

output "resource_quota_name" {
  value = kubernetes_resource_quota.staging.metadata[0].name
}

output "hash_api_config_name" {
  value = kubernetes_config_map.hash_api_config.metadata[0].name
}