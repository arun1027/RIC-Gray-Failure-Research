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

    # Construct secure container-side execution without exposing password in shell arguments
    # Using python script on target container to connect via libpq
    verify_script = """
import os, sys, psycopg2
try:
    conn = psycopg2.connect(
        host="127.0.0.1",
        port=5432,
        user="postgres",
        password=sys.stdin.read().strip(),
        dbname="benchdb"
    )
    cur = conn.cursor()
    cur.execute("SELECT 1 AS tcp_auth_ok;")
    res = cur.fetchone()[0]
    conn.close()
    print("TCP_AUTH_SUCCESS:", res)
    sys.exit(0)
except Exception as e:
    print("TCP_AUTH_FAIL:", type(e).__name__, str(e))
    sys.exit(1)
"""

    cmd = ['kubectl', 'exec', '-i', '-n', 'postgres-patroni', 'patroni-0', '--', 'python3', '-c', verify_script]
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

