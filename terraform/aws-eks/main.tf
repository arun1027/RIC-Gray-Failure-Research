# Terraform Root Configuration for RIC Gray-Failure Research AWS Infrastructure
# Covers: Multi-AZ EKS Cluster, Node Groups, IAM Roles, EBS CSI Driver, VPC CNI, gp3 StorageClass
# Authoritative Baseline: MSc CA2 Report (m5.xlarge across 3 AZs in us-east-1)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.28.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "RIC-Gray-Failure-Research"
      Environment = var.environment
      Purpose     = "MScCloudComputingThesis"
      Owner       = "ArunNatarajan"
      ManagedBy   = "Terraform"
    }
  }
}

# Local variables for multi-AZ topology
locals {
  cluster_name = "${var.project_prefix}-eks"
  azs          = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
}

# Primary EKS VPC Module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5.0"

  name = "${var.project_prefix}-vpc"
  cidr = "10.0.0.0/16"

  azs             = local.azs
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true # Cost conservation for pilot runs
  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb"                      = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"             = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }
}

# EKS Cluster Definition
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.28" # Pinned Kubernetes version

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Core EKS Addons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  # Managed Node Group: Standardized 3-node cluster across 3 AZs
  eks_managed_node_groups = {
    database_workers = {
      name         = "${var.project_prefix}-db-nodes"
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = [var.node_instance_type] # m5.xlarge (4 vCPU, 16 GiB RAM)
      capacity_type  = "ON_DEMAND"

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 50
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 125
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      labels = {
        "node.kubernetes.io/scope"           = "database-worker"
        "ric.thesis/subsystem"               = "shared-workers"
        "topology.kubernetes.io/zone-spread" = "enforced"
      }
    }
  }
}

# Dedicated EBS gp3 StorageClass with Immediate Binding
resource "kubernetes_storage_class_v1" "gp3" {
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type       = "gp3"
    iops       = "3000"
    throughput = "125"
    encrypted  = "true"
  }

  depends_on = [module.eks]
}

# Optional Decoupled Aurora PostgreSQL Multi-AZ Module
# Provisioned independently or toggled via variable
module "aurora" {
  source = "../modules/aurora"

  project_prefix        = var.project_prefix
  vpc_id                = module.vpc.vpc_id
  database_subnets      = module.vpc.private_subnets
  eks_security_group_id = module.eks.node_security_group_id
  aurora_instance_class = var.aurora_instance_class
  engine_version        = "14.9"
  database_name         = "benchdb"
  master_username       = "postgres"
}
