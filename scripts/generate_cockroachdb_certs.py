"""
CockroachDB TLS Certificate Generator for AWS EKS Deployment
Generates X.509 v3 certificates for CockroachDB secure mode:
1. Root CA Certificate and Private Key (ca.crt, ca.key)
2. Node Certificate and Private Key (node.crt, node.key)
3. Client Root Certificate and Private Key (client.root.crt, client.root.key)

Conforms to CockroachDB v26.x / Helm chart cockroachdb-22.0.4 requirements.
Target Namespace: cockroachdb
StatefulSet: cockroachdb (3 replicas)
Headless Service: cockroachdb
Public Service: cockroachdb-public
Cluster Domain: cluster.local
"""

import os
import sys
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key(key_size=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

def save_private_key(key, file_path):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(file_path, "wb") as f:
        f.write(pem)
    # Set restrictive file permissions where supported (Windows Best Effort / POSIX 0600)
    try:
        os.chmod(file_path, 0o600)
    except Exception:
        pass

def save_certificate(cert, file_path):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(file_path, "wb") as f:
        f.write(pem)
    try:
        os.chmod(file_path, 0o644)
    except Exception:
        pass

def create_ca(output_dir):
    ca_key = generate_rsa_key(2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cockroach"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Cockroach CA"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=1825) # 5 years
    
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    ca_key_path = os.path.join(output_dir, "ca.key")
    ca_crt_path = os.path.join(output_dir, "ca.crt")
    
    save_private_key(ca_key, ca_key_path)
    save_certificate(ca_cert, ca_crt_path)
    
    return ca_key, ca_cert

def create_node_certificate(ca_key, ca_cert, output_dir):
    node_key = generate_rsa_key(2048)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cockroach"),
        x509.NameAttribute(NameOID.COMMON_NAME, "node"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=365) # 1 year
    
    # Exact SAN list for CockroachDB headless & public services in EKS
    sans = [
        # Loopback
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        # Headless service DNS
        x509.DNSName("cockroachdb"),
        x509.DNSName("cockroachdb.cockroachdb"),
        x509.DNSName("cockroachdb.cockroachdb.svc.cluster.local"),
        # Public client service DNS
        x509.DNSName("cockroachdb-public"),
        x509.DNSName("cockroachdb-public.cockroachdb"),
        x509.DNSName("cockroachdb-public.cockroachdb.svc.cluster.local"),
        # Wildcard service DNS
        x509.DNSName("*.cockroachdb"),
        x509.DNSName("*.cockroachdb.cockroachdb"),
        x509.DNSName("*.cockroachdb.cockroachdb.svc.cluster.local"),
        # Pod specific short names
        x509.DNSName("cockroachdb-0"),
        x509.DNSName("cockroachdb-1"),
        x509.DNSName("cockroachdb-2"),
        # Pod specific namespace-qualified names
        x509.DNSName("cockroachdb-0.cockroachdb"),
        x509.DNSName("cockroachdb-1.cockroachdb"),
        x509.DNSName("cockroachdb-2.cockroachdb"),
        # Pod specific FQDNs
        x509.DNSName("cockroachdb-0.cockroachdb.cockroachdb.svc.cluster.local"),
        x509.DNSName("cockroachdb-1.cockroachdb.cockroachdb.svc.cluster.local"),
        x509.DNSName("cockroachdb-2.cockroachdb.cockroachdb.svc.cluster.local"),
    ]
    
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(node_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    node_key_path = os.path.join(output_dir, "node.key")
    node_crt_path = os.path.join(output_dir, "node.crt")
    
    save_private_key(node_key, node_key_path)
    save_certificate(node_cert, node_crt_path)
    
    return node_key, node_cert

def create_client_certificate(ca_key, ca_cert, output_dir, username="root"):
    client_key = generate_rsa_key(2048)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cockroach"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=365) # 1 year
    
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    client_key_path = os.path.join(output_dir, f"client.{username}.key")
    client_crt_path = os.path.join(output_dir, f"client.{username}.crt")
    
    save_private_key(client_key, client_key_path)
    save_certificate(client_cert, client_crt_path)
    
    return client_key, client_cert

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_dir = os.path.join(repo_root, "certs", "cockroach-tls-stage2")
    os.makedirs(out_dir, exist_ok=True)
    
    print(f"Generating CockroachDB TLS Certificates in: {out_dir}")
    
    # 1. CA
    ca_key, ca_cert = create_ca(out_dir)
    print(f"[OK] Generated CA Certificate: ca.crt, ca.key (Serial: {hex(ca_cert.serial_number)})")
    
    # 2. Node
    node_key, node_cert = create_node_certificate(ca_key, ca_cert, out_dir)
    print(f"[OK] Generated Node Certificate: node.crt, node.key (Serial: {hex(node_cert.serial_number)})")
    
    # 3. Client (root)
    client_key, client_cert = create_client_certificate(ca_key, ca_cert, out_dir, username="root")
    print(f"[OK] Generated Client Root Certificate: client.root.crt, client.root.key (Serial: {hex(client_cert.serial_number)})")
    
    print("\nSummary of Generated Artifacts (Public Cert Info Only):")
    for fname in ["ca.crt", "node.crt", "client.root.crt"]:
        p = os.path.join(out_dir, fname)
        with open(p, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        print(f"  {fname}:")
        print(f"    Subject: {c.subject.rfc4514_string()}")
        print(f"    Issuer:  {c.issuer.rfc4514_string()}")
        print(f"    Valid:   {c.not_valid_before_utc} to {c.not_valid_after_utc}")
        print(f"    Serial:  {hex(c.serial_number)}")

if __name__ == "__main__":
    main()

