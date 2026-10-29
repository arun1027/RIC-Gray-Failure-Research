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
  description = "Standardized worker node instance type (CA2 baseline)"
  type        = string
  default     = "m5.xlarge"
}

variable "aurora_instance_class" {
  description = "Aurora instance class with equivalent 4 vCPU compute"
  type        = string
  default     = "db.r6g.xlarge"
}

variable "max_spend_ceiling_usd" {
  description = "Hard financial stop ceiling for pilot runs"
  type        = number
  default     = 15.00
}
