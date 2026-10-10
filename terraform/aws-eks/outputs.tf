# Outputs for AWS EKS & Aurora Infrastructure Root Module

# Aurora PostgreSQL Cluster Writer Endpoint (Conditional on var.enable_aurora)
output "cluster_endpoint" {
  description = "Amazon Aurora PostgreSQL cluster writer endpoint hostname"
  value       = try(module.aurora[0].cluster_endpoint, null)
}

# Aurora PostgreSQL Cluster Reader Endpoint (Conditional on var.enable_aurora)
output "reader_endpoint" {
  description = "Amazon Aurora PostgreSQL cluster reader endpoint hostname"
  value       = try(module.aurora[0].reader_endpoint, null)
}

# EKS Cluster Name
output "eks_cluster_name" {
  description = "Amazon EKS cluster name"
  value       = module.eks.cluster_name
}

# EKS Cluster Endpoint
output "eks_cluster_endpoint" {
  description = "Amazon EKS control plane API endpoint"
  value       = module.eks.cluster_endpoint
}

# EKS Cluster Certificate Authority Data
output "eks_cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to authenticate with the EKS cluster"
  value       = module.eks.cluster_certificate_authority_data
}

