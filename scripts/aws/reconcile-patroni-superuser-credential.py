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

    if not raw_pwd:
        raise ValueError('Secret superuser-password is empty!')

    # Escape single quotes and suppress statement logging in session
    escaped_pwd = raw_pwd.replace("'", "''")
    sql_payload = "SET log_statement = 'none';\nALTER ROLE postgres WITH PASSWORD '" + escaped_pwd + "';\n"

    # Pipe to psql stdin
    cmd = ['kubectl', 'exec', '-i', '-n', 'postgres-patroni', 'patroni-0', '--', 'psql', '-U', 'postgres', '-d', 'postgres', '-f', '-']
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = p.communicate(input=sql_payload)

    # Clean memory
    raw_pwd = None
    escaped_pwd = None
    sql_payload = None

    print('ReturnCode:', p.returncode)
    print('ALTER ROLE in stdout:', 'ALTER ROLE' in stdout)
    summary = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    print('Stdout summary:', summary)
    if p.returncode != 0:
        print('Stderr:', stderr.strip() if stderr else 'NONE')
        sys.exit(1)

if __name__ == '__main__':
    main()

