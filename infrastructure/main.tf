# infrastructure/main.tf
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.15.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "3.15.0"
    }
  }
}

module "phasma_ai_cluster" {
  source = "terraform-aws-modules/eks/aws"
  
  cluster_name    = "phasma-ai-prod"
  cluster_version = "1.27"
  vpc_id          = module.vpc.vpc_id
  
  node_security_group_additional_rules = {
    https_egress = {
      description      = "TLS inspection for AI models"
      protocol         = "TCP"
      from_port        = 443
      to_port          = 443
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      source_security_group_id = aws_security_group.model_firewall.id
    }
  }
  
  node_groups = {
    ai_workers = {
      capacity_type  = "SPOT"
      instance_types = ["p4d.24xlarge"]
      min_size       = 3
      max_size       = 50
      taints = [{
        key    = "nvidia.com/gpu"
        value  = "present"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

resource "vault_gcp_secret_roleset" "phasma_model_store" {
  backend      = "gcp"
  roleset      = "phasma-model-store"
  secret_type  = "access_token"
  project      = var.gcp_project
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  
  binding {
    resource = "//iam.googleapis.com/projects/${var.gcp_project}/serviceAccounts/phasma-tf@${var.gcp_project}.iam.gserviceaccount.com"
    roles    = ["roles/storage.objectAdmin"]
  }
}
