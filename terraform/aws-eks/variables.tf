# Variables for AWS EKS Infrastructure
variable "aws_region" {
  description = "Target AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "project_prefix" {
  description = "Prefix for all research resources"
  type        = string
  default     = "ric-gray-failure"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "pilot"
}

variable "node_instance_type" {
  description = "Standardized worker node instance type (m5.large approved for AWS Academy Learner Lab pilot; m5.xlarge CA2 baseline)"
  type        = string
  default     = "m5.large"
}

variable "aurora_instance_class" {
  description = "Aurora instance class (db.t4g.medium used for AWS Academy Learner Lab pilot; db.r6g.xlarge intended for full research scale)"
  type        = string
  default     = "db.t4g.medium"
}

variable "enable_aurora" {
  description = "Feature toggle to conditionally provision Aurora PostgreSQL Multi-AZ cluster. Disabled by default for CockroachDB testing."
  type        = bool
  default     = false
}

variable "max_spend_ceiling_usd" {
  description = "Hard financial stop ceiling for pilot runs"
  type        = number
  default     = 15.00
}

# Personal AWS Account IAM Configuration (Replaces legacy AWS Academy Learner Lab roles)
variable "eks_cluster_role_arn" {
  description = "Existing EKS Cluster Role ARN (leave null when create_iam_role is true)"
  type        = string
  default     = null
}

variable "eks_node_role_arn" {
  description = "Existing Worker Node Role ARN (leave null when create_iam_role is true)"
  type        = string
  default     = null
}

variable "operator_public_ip_cidr" {
  description = "Operator IPv4 CIDR (/32) authorized to query the EKS public API endpoint"
  type        = string
  default     = "109.78.55.177/32"
}

