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
  source = "../modules/eks"

  cluster_name    = local.cluster_name
  cluster_version = "1.34" # Standard supported Kubernetes version on AWS EKS

  # IAM & Encryption: Enable native least-privilege IAM role creation for personal AWS account
  create_iam_role           = true
  iam_role_arn              = var.eks_cluster_role_arn
  enable_irsa               = true
  create_kms_key            = false
  cluster_encryption_config = {}

  # Grant cluster administrator privileges to personal account IAM operator via standard access entry
  access_entries = {
    personal_admin = {
      principal_arn = "arn:aws:iam::397916376204:user/RIC_grey_failure"
      type          = "STANDARD"
      policy_associations = {
        admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  cluster_endpoint_public_access       = true
  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access_cidrs = [var.operator_public_ip_cidr]

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Core EKS Addons - pinned AWS default versions for Kubernetes 1.34
  cluster_addons = {
    coredns = {
      addon_version = "v1.13.2-eksbuild.75"
    }

    kube-proxy = {
      addon_version = "v1.34.6-eksbuild.69"
    }

    vpc-cni = {
      addon_version = "v1.22.4-eksbuild.14"
    }

    aws-ebs-csi-driver = {
      addon_version = "v1.68.0-eksbuild.1"
    }
  }

  # Managed Node Group: Standardized 3-node cluster across 3 AZs
  eks_managed_node_groups = {
    database_workers = {
      name         = "${var.project_prefix}-db-nodes"
      min_size     = 3
      max_size     = 3
      desired_size = 3

      create_iam_role = true
      iam_role_name   = "${var.project_prefix}-db-nodes"
      iam_role_arn    = var.eks_node_role_arn

      instance_types = [var.node_instance_type] # m5.large approved pilot (2 vCPU, 8 GiB RAM per node; 3 nodes = 6 vCPU, 24 GiB RAM)
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
        "node.kubernetes.io/scope" = "database-worker"
        "ric.thesis/subsystem"     = "shared-workers"
        "ric.thesis/zone-spread"   = "enforced"
      }
    }
  }
}

# Optional Decoupled Aurora PostgreSQL Multi-AZ Module
# Provisioned conditionally via var.enable_aurora (disabled by default for CockroachDB testing)
module "aurora" {
  count  = var.enable_aurora ? 1 : 0
  source = "../modules/aurora"

  project_prefix        = var.project_prefix
  vpc_id                = module.vpc.vpc_id
  database_subnets      = module.vpc.private_subnets
  eks_security_group_id = module.eks.node_security_group_id
  aurora_instance_class = var.aurora_instance_class
  engine_version        = "15.19"
  database_name         = "benchdb"
  master_username       = "postgres"
}
