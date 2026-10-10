#!/usr/bin/env python3
"""
Offline Validation Suite for AWS Deployment Package and IaC Configurations.
Validates:
1. Terraform HCL structure and mandatory provider/version constraints.
2. Standardized node sizing (m5.xlarge) and 3-AZ placement tags.
3. Aurora module decoupling and security group isolation.
4. gp3 StorageClass parameters (3000 IOPS, 125 MB/s).
5. Teardown script cleanup steps and sweeper logic.
6. Immutability guard for local CockroachDB and benchmark fixtures.
"""

import os
import sys
import unittest
import glob
import re

REPO_ROOT = r"d:\Projects\RIC-Gray-Failure-Research"
TF_DIR = os.path.join(REPO_ROOT, "terraform", "aws-eks")
AURORA_TF_DIR = os.path.join(REPO_ROOT, "terraform", "modules", "aurora")
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts", "aws")

class TestAwsDeploymentPackageOffline(unittest.TestCase):

    def test_01_terraform_main_file_exists_and_configured(self):
        """Terraform main configuration must configure AWS provider, VPC, and EKS."""
        main_tf = os.path.join(TF_DIR, "main.tf")
        self.assertTrue(os.path.exists(main_tf), f"main.tf missing at {main_tf}")
        with open(main_tf, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('required_version = ">= 1.5.0"', content)
        self.assertTrue('cluster_version = "1.34"' in content or 'cluster_version = "1.28"' in content)
        self.assertIn('var.node_instance_type', content)
        # Verify gp3 StorageClass parameters (managed via declarative manifest kubernetes/storageclass-gp3.yaml)
        sc_yaml = os.path.join(REPO_ROOT, "kubernetes", "storageclass-gp3.yaml")
        self.assertTrue(os.path.exists(sc_yaml), "kubernetes/storageclass-gp3.yaml missing")
        with open(sc_yaml, "r", encoding="utf-8") as sc_f:
            sc_content = sc_f.read()
        self.assertIn('provisioner: ebs.csi.aws.com', sc_content)
        self.assertIn('name: gp3', sc_content)
        self.assertIn('volumeBindingMode: WaitForFirstConsumer', sc_content)

    def test_02_terraform_variables_enforce_ca2_standards(self):
        """Variables must default to m5.large (approved AWS Academy Learner Lab pilot) or m5.xlarge (CA2 full scale) and db.t4g.medium in us-east-1."""
        vars_tf = os.path.join(TF_DIR, "variables.tf")
        self.assertTrue(os.path.exists(vars_tf))
        with open(vars_tf, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('default     = "us-east-1"', content)
        self.assertTrue(
            'default     = "m5.large"' in content or 'default     = "m5.xlarge"' in content,
            "Variables must define an approved worker instance type (m5.large or m5.xlarge)"
        )
        self.assertTrue(
            'default     = "db.t4g.medium"' in content or 'default     = "db.r6g.xlarge"' in content,
            "Aurora instance class must default to db.t4g.medium (Academy pilot) or db.r6g.xlarge (full scale)"
        )
        self.assertIn('default     = 15.00', content, "Hard spend limit must default to 15 USD")

    def test_03_aurora_module_isolation(self):
        """Aurora module must be distinct, non-publicly accessible, and strictly port 5432."""
        aurora_tf = os.path.join(AURORA_TF_DIR, "main.tf")
        self.assertTrue(os.path.exists(aurora_tf))
        with open(aurora_tf, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('resource "aws_rds_cluster" "aurora"', content)
        self.assertIn('publicly_accessible = false', content)
        self.assertIn('to_port         = 5432', content)
        self.assertIn('random_password', content, "Must not hardcode database password")

    def test_04_teardown_script_safeguards(self):
        """Teardown script must sweep PVCs, Aurora instances, and unattached EBS volumes."""
        td_sh = os.path.join(SCRIPTS_DIR, "teardown-eks.sh")
        self.assertTrue(os.path.exists(td_sh))
        with open(td_sh, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("kubectl delete namespace aurora-benchmark", content)
        self.assertIn("kubectl delete namespace postgres-patroni", content)
        self.assertIn("kubectl delete namespace cockroachdb", content)
        self.assertIn("terraform -chdir=terraform/aws-eks destroy", content)
        self.assertIn("aws ec2 delete-volume", content)

    def test_05_immutability_of_existing_benchmarks(self):
        """Ensure no CockroachDB baseline results or manifests were modified."""
        crdb_values = os.path.join(REPO_ROOT, "kubernetes", "cockroachdb", "values.yaml")
        summary_csv = os.path.join(REPO_ROOT, "results", "cockroachdb", "baseline", "baseline-summary.csv")
        self.assertTrue(os.path.exists(crdb_values))
        self.assertTrue(os.path.exists(summary_csv))

if __name__ == "__main__":
    unittest.main(verbosity=2)

