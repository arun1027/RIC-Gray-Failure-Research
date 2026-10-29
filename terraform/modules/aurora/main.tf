# Terraform Module: Isolated Amazon Aurora PostgreSQL-Compatible Multi-AZ Provisioning
# Kept strictly decoupled from EKS compute to preserve CA2 managed-service architecture

variable "project_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "database_subnets" {
  type = list(string)
}

variable "eks_security_group_id" {
  type = string
}

variable "aurora_instance_class" {
  type    = string
  default = "db.r6g.xlarge"
}

variable "engine_version" {
  type    = string
  default = "14.9"
}

variable "database_name" {
  type    = string
  default = "benchdb"
}

variable "master_username" {
  type    = string
  default = "postgres"
}

# Random password generation for master user (never hardcoded)
resource "random_password" "master" {
  length  = 24
  special = false
}

# Subnet group spanning minimum 2 AZs in us-east-1
resource "aws_db_subnet_group" "aurora" {
  name       = "${var.project_prefix}-aurora-subnet-group"
  subnet_ids = var.database_subnets

  tags = {
    Name = "${var.project_prefix}-aurora-subnet-group"
  }
}

# Ingress Security Group permitting PostgreSQL traffic exclusively from EKS worker nodes
resource "aws_security_group" "aurora" {
  name        = "${var.project_prefix}-aurora-sg"
  description = "Permit PostgreSQL port 5432 exclusively from EKS cluster nodes"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from EKS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.eks_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Aurora Cluster Definition
resource "aws_rds_cluster" "aurora" {
  cluster_identifier      = "${var.project_prefix}-aurora-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = var.engine_version
  database_name           = var.database_name
  master_username         = var.master_username
  master_password         = random_password.master.result
  db_subnet_group_name    = aws_db_subnet_group.aurora.name
  vpc_security_group_ids  = [aws_security_group.aurora.id]
  storage_encrypted       = true
  deletion_protection     = false
  skip_final_snapshot     = true
  backup_retention_period = 1

  tags = {
    Name = "${var.project_prefix}-aurora-cluster"
  }
}

# 1 Primary Writer Instance (us-east-1a)
resource "aws_rds_cluster_instance" "writer" {
  identifier          = "${var.project_prefix}-aurora-writer"
  cluster_identifier  = aws_rds_cluster.aurora.id
  instance_class      = var.aurora_instance_class
  engine              = aws_rds_cluster.aurora.engine
  engine_version      = aws_rds_cluster.aurora.engine_version
  availability_zone   = "us-east-1a"
  publicly_accessible = false
}

# 1 Multi-AZ Reader Instance (us-east-1b)
resource "aws_rds_cluster_instance" "reader" {
  identifier          = "${var.project_prefix}-aurora-reader"
  cluster_identifier  = aws_rds_cluster.aurora.id
  instance_class      = var.aurora_instance_class
  engine              = aws_rds_cluster.aurora.engine
  engine_version      = aws_rds_cluster.aurora.engine_version
  availability_zone   = "us-east-1b"
  publicly_accessible = false
}

output "cluster_endpoint" {
  description = "Aurora Cluster Writer Endpoint"
  value       = aws_rds_cluster.aurora.endpoint
}

output "reader_endpoint" {
  description = "Aurora Cluster Reader Endpoint"
  value       = aws_rds_cluster.aurora.reader_endpoint
}
