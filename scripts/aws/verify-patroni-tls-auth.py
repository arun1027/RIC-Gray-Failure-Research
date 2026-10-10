import subprocess
import json
import base64
import sys

def main():
    # Ingest secret strictly in memory
    out_sec = subprocess.check_output(
        ['kubectl', 'get', 'secret', 'patroni-credentials', '-n', 'postgres-patroni', '-o', 'json']
    )
    sec = json.loads(out_sec)
    enc_pwd = sec['data']['superuser-password']
    raw_pwd = base64.b64decode(enc_pwd).decode('utf-8')

    # Run in patroni-0 testing verify-full TLS over 172.20.33.66 using pg_stat_ssl
    verify_tls_script = """
import os, sys, psycopg2
try:
    conn = psycopg2.connect(
        host="spilo.example.org",
        hostaddr="172.20.33.66",
        port=5432,
        user="postgres",
        password=sys.stdin.read().strip(),
        dbname="benchdb",
        sslmode="verify-full",
        sslrootcert="/run/certs/server.crt"
    )
    cur = conn.cursor()
    cur.execute("SELECT pg_is_in_recovery(), (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), (SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()), (SELECT cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid());")
    rec, ssl_status, ssl_ver, ssl_cipher = cur.fetchone()
    conn.close()
    print(f"VERIFY_FULL_SUCCESS: recovery={rec}, ssl={ssl_status}, version={ssl_ver}, cipher={ssl_cipher}")
    sys.exit(0)
except Exception as e:
    print("VERIFY_FULL_FAIL:", type(e).__name__, str(e))
    sys.exit(1)
"""

    cmd = ['kubectl', 'exec', '-i', '-n', 'postgres-patroni', 'patroni-0', '--', 'python3', '-c', verify_tls_script]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = p.communicate(input=raw_pwd)
    raw_pwd = None

    print('ReturnCode:', p.returncode)
    print('Stdout:', stdout.strip())
    if stderr.strip():
        print('Stderr:', stderr.strip())

    if p.returncode != 0:
        sys.exit(1)

if __name__ == '__main__':
    main()

