# Ero AI Deployment Guide

## 1. System Requirements

### Infrastructure
```
# Recommended Cluster Profile
cluster:
  nodes: 6
  vCPUs: 64 (minimum)
  memory: 256GB RAM (minimum)
  storage: 1TB SSD (NVMe preferred)
  network: 25 Gbps dedicated

platformComponents:
  kubernetes: 1.27+
  istio: 1.18+
  certManager: 1.12+
  vault: 1.14+
```

## 2. Base Installation

### Helm Chart Deployment
```
# Add Ero Helm repo
helm repo add Ero https://charts.Ero.ai --username <license-user> --password <license-key>

# Install core components
helm install phasma-core Ero/Ero-core \
  --namespace Ero-system \
  --create-namespace \
  --set global.tls.autoCert=true \
  --set global.observability.enabled=true \
  --set-json='global.featureGates={"quantumResistance":true,"sgxAttestation":false}' \
  --version 3.8.1
```
## 3. Multi-Cloud Configuration

### AWS EKS
```
# eks/main.tf
module "Ero_eks" {
  source  = "terraform-aws-modules/eks/aws"
  
  cluster_encryption_config = [
    {
      provider_key_arn = aws_kms_key.Ero.arn
      resources        = ["secrets"]
    }
  ]

  node_groups = {
    Ero-ng = {
      capacity_type  = "SPOT"
      instance_types = ["m6i.32xlarge", "c6i.48xlarge"]
      min_size       = 10
      max_size       = 100
      disk_size      = 1000
    }
  }
}
```

### Azure AKS
```
az aks create \
  --resource-group Ero-prod-rg \
  --name Ero-aks \
  --node-count 15 \
  --node-vm-size Standard_E96bs_v5 \
  --enable-addons monitoring \
  --network-plugin azure \
  --network-policy calico \
  --ssh-key-value ~/.ssh/Ero_prod.pub \
  --zones 1 2 3
```

## 4. Security Hardening
### Vault Integration
```
# security/vault-config.hcl
storage "raft" {
  path    = "/vault/data"
  node_id = "Ero-vault-1"
}

seal "azurekeyvault" {
  tenant_id      = "${VAULT_TENANT_ID}"
  vault_name     = "Ero-prod-vault"
  key_name       = "Ero-auto-unseal"
  environment    = "AZUREPUBLICCLOUD"
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
```

### Network Policies
```
# network/zero-trust-policies.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: Ero.zero-trust
spec:
  tier: Ero-security
  order: 1000
  selector: has(phasma-agent)
  types:
  - Ingress
  - Egress
  ingress:
  - action: Deny
  egress:
  - action: Deny
  - to:
    - namespaceSelector: has(phasma-system)
    ports:
    - protocol: TCP
      port: 443
```

## 5. Observability Setup

### Prometheus Scaling
```
# monitoring/prometheus-values.yaml
alertmanager:
  shards: 6
  persistence:
    size: 500Gi

prometheus:
  shards: 12
  retention: 31d
  walCompression: true
  queryLogFile: /var/log/prometheus/query.log

thanos:
  objectStorageConfig:
    type: s3
    config:
      bucket: Ero-prometheus-data
      endpoint: s3.dualstack.eu-central-1.amazonaws.com
      region: eu-central-1
```

## 6. Post-Install Verification
### Cluster Health Check
```
kubectl get Erohealthchecks.security.Ero.ai -n Ero-system -o json | \
  jq '.items[] | select(.status.overallStatus != "Healthy")'
```

### Performance Benchmark
```
phasma-cli benchmark deploy \
  --scenario enterprise-mix \
  --duration 1h \
  --metrics-interval 10s \
  --output-format ndjson > benchmark-results.json
```

## 7. Disaster Recovery
### State Backup Configuration
```
# backup/velero-config.yaml
backupStorageLocation:
  name: Ero-azure
  provider: azure
  objectStorage:
    bucket: Ero-backups
    prefix: cluster1/
  config:
    resourceGroup: Ero-backup-rg
    storageAccount: Erosabackup

schedule:
  full-daily:
    schedule: "0 2 * * *"
    ttl: 720h
    includedNamespaces:
    - Ero-system
    - Ero-data
    snapshotVolumes: true
```

## 8. Maintenance Operations
### Zero-Downtime Upgrade
```
helm upgrade Ero-core Ero/Ero-core \
  --namespace Ero-system \
  --reuse-values \
  --set updateStrategy=canary \
  --set canary.interval=5m \
  --set canary.successThreshold=3 \
  --version 3.8.2
```
