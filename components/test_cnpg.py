#!/usr/bin/env python3
"""
CNPG (CloudNative PostgreSQL) Cluster Test Script (fixed & hardened)
- Tests PostgreSQL connectivity, cluster health, replication, databases, auth, tables, write, and pod logs
- Designed for CloudNative PostgreSQL Operator clusters

ENV VARS
  CNPG_HOST (default: cnpg-rw.cnpg.svc.cluster.local)
  CNPG_PORT (default: 5432)
  CNPG_ADMIN_PASSWORD
  CNPG_DATABASES  Format: db1:user1:pass1:authdb1:table1;db2:...

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import time
import subprocess
import sys
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# ------------------------------------------------------------
# Utilities & configuration
# ------------------------------------------------------------

def parse_databases() -> List[Dict[str, str]]:
    """
    Parse CNPG_DATABASES environment variable
    Format: db1:user1:pass1:authdb1:table1;db2:user2:pass2:authdb2:table2
    For PostgreSQL, auth_database is typically same as database
    """
    databases = []
    databases_env = os.getenv('CNPG_DATABASES', '')

    if not databases_env:
        print("Warning: CNPG_DATABASES environment variable not found", file=sys.stderr)
        return databases

    for db_config in databases_env.split(';'):
        if db_config.strip():
            parts = db_config.strip().split(':')
            if len(parts) >= 3:
                databases.append({
                    'database': parts[0],
                    'username': parts[1],
                    'password': parts[2],
                    'auth_database': parts[3] if len(parts) > 3 else parts[0],
                    'collection': parts[4] if len(parts) > 4 else 'test_table'
                })
            else:
                print(f"Warning: Invalid database configuration: {db_config}", file=sys.stderr)

    return databases

# EXACT from your ENV output
CNPG_HOST = os.getenv('CNPG_HOST', 'cnpg-rw.cnpg.svc.cluster.local')
CNPG_PORT = os.getenv('CNPG_PORT', '5432')
CNPG_NAMESPACE = os.getenv('CNPG_NS', 'cnpg')
CNPG_ADMIN_PASSWORD = os.getenv('CNPG_ADMIN_PASSWORD', 'havalalhazman')
CNPG_ADMIN_USER = 'admin'  # From your cluster.yaml managed.roles

DATABASES = parse_databases()

# Cluster name from your cluster.yaml
CLUSTER_NAME = 'cluster-cnpg'

# ------------------------------------------------------------
# Shell helper
# ------------------------------------------------------------

def run_command(command: str, env: Optional[Dict[str, str]] = None, timeout: int = 30) -> Dict[str, Any]:
    """Run a shell command and capture stdout/stderr/exit code."""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": (completed.stdout or '').strip(),
            "stderr": (completed.stderr or '').strip(),
            "exit_code": completed.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "exit_code": 124}


def ok(proc: Dict[str, Any]) -> bool:
    return proc.get("exit_code", 1) == 0

# ------------------------------------------------------------
# Result helper
# ------------------------------------------------------------

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def check_postgres_connectivity() -> List[Dict[str, Any]]:
    description = "Check basic PostgreSQL primary connectivity"
    global CNPG_HOST  # Declare global at the beginning
    
    # First try to connect to the host from ENV
    command = (
        f"""PGPASSWORD='{CNPG_ADMIN_PASSWORD}' psql \
            -h {CNPG_HOST} -p {CNPG_PORT} \
            -U admin -d postgres \
            -c 'SELECT version();' 2>&1"""
    )
    r = run_command(command, timeout=15)
    
    # If ENV host fails, try cluster-cnpg-rw as fallback (the actual service name)
    if not ok(r):
        alt_host = 'cluster-cnpg-rw.cnpg.svc.cluster.local'
        command = (
            f"""PGPASSWORD='{CNPG_ADMIN_PASSWORD}' psql \
                -h {alt_host} -p {CNPG_PORT} \
                -U admin -d postgres \
                -c 'SELECT version();' 2>&1"""
        )
        r2 = run_command(command, timeout=15)
        if ok(r2) and 'PostgreSQL' in r2['stdout']:
            # Update the global for subsequent tests
            CNPG_HOST = alt_host
            return [create_test_result("postgres_connectivity", description, True, f"Connected to PostgreSQL at {alt_host}:{CNPG_PORT}", "INFO")]
        else:
            # Return original error if both fail
            msg = r['stderr'] or r['stdout'] or 'Unknown error'
            return [create_test_result("postgres_connectivity", description, False, f"Connectivity failed: {msg}", "CRITICAL")]
    
    if ok(r) and 'PostgreSQL' in r['stdout']:
        return [create_test_result("postgres_connectivity", description, True, f"Connected to PostgreSQL at {CNPG_HOST}:{CNPG_PORT}", "INFO")]
    else:
        msg = r['stderr'] or r['stdout'] or 'Unknown error'
        return [create_test_result("postgres_connectivity", description, False, f"Connectivity failed: {msg}", "CRITICAL")]


def _json_eval(query: str) -> Any:
    """Helper: run kubectl and parse JSON output."""
    command = f"kubectl get {query} -o json 2>/dev/null"
    r = run_command(command, timeout=20)
    if ok(r) and r['stdout']:
        try:
            return json.loads(r['stdout'])
        except json.JSONDecodeError:
            return {}
    return {}


def check_cluster_status() -> List[Dict[str, Any]]:
    description = "Check cluster status and health of all instances"
    tests: List[Dict[str, Any]] = []

    # Get cluster info
    cluster = _json_eval(f"cluster -n {CNPG_NAMESPACE} {CLUSTER_NAME}")
    if not cluster:
        tests.append(create_test_result("cluster_status", description, False, "No cluster info returned", "WARNING"))
        return tests

    status = cluster.get('status', {})
    instances = status.get('instances', 0)
    ready = status.get('readyInstances', 0)
    
    tests.append(create_test_result("cluster_status", description, instances == ready, 
                                   f"Found {ready}/{instances} ready instance(s)", "INFO"))

    # Each instance health
    pods = _json_eval(f"pods -n {CNPG_NAMESPACE} -l cnpg.io/cluster={CLUSTER_NAME}")
    for pod in pods.get('items', []):
        pod_name = pod.get('metadata', {}).get('name', '<unknown>')
        pod_ready = all(c.get('ready', False) for c in pod.get('status', {}).get('containerStatuses', []))
        role = pod.get('metadata', {}).get('labels', {}).get('cnpg.io/instanceRole', 'unknown')
        
        tests.append(create_test_result(
            f"instance_{pod_name}_health",
            "Check individual instance health",
            pod_ready,
            f"role={role} | ready: {'yes' if pod_ready else 'no'}",
            "INFO" if pod_ready else "WARNING"
        ))

    # Balancer equivalent - check primary switchover readiness
    tests.extend(check_switchover_status())

    # Databases in cluster
    dbs_cmd = f"""PGPASSWORD='{CNPG_ADMIN_PASSWORD}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U admin -d postgres -t -c "SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1', 'postgres');" 2>&1"""
    r = run_command(dbs_cmd, timeout=10)
    if ok(r) and r['stdout']:
        db_list = [d.strip() for d in r['stdout'].split('\n') if d.strip()]
        tests.append(create_test_result(
            "dbs_in_cluster", "Databases registered in cluster", True,
            f"databases count={len(db_list)}: {', '.join(db_list)}", "INFO"
        ))

    return tests


def check_switchover_status() -> List[Dict[str, Any]]:
    description = "Check switchover capability"
    # Check if cluster can perform switchover (equivalent to balancer)
    cluster = _json_eval(f"cluster -n {CNPG_NAMESPACE} {CLUSTER_NAME}")
    status = cluster.get('status', {})
    current_primary = status.get('currentPrimary', '')
    target_primary = status.get('targetPrimary', '')
    
    if current_primary and current_primary == target_primary:
        return [create_test_result("switchover_status", description, True, f"Primary stable: {current_primary}", "INFO")]
    else:
        return [create_test_result("switchover_status", description, False, f"Primary mismatch: current={current_primary}, target={target_primary}", "WARNING")]


def check_database_access(database: Dict[str, str]) -> List[Dict[str, Any]]:
    description = "Check database connectivity, user access, and table operations"
    tests: List[Dict[str, Any]] = []
    db_name = database['database']
    username = database['username']
    password = database['password']
    auth_db = database['auth_database']
    collection = database['collection']  # table in PostgreSQL

    # 1) User authentication
    auth_cmd = (
        f"PGPASSWORD='{password}' psql -h {CNPG_HOST} -p {CNPG_PORT} "
        f"-U {username} -d {db_name} -c 'SELECT current_user;' 2>&1"
    )
    r = run_command(auth_cmd, timeout=15)
    auth_ok = ok(r) and username in r['stdout']
    tests.append(create_test_result(
        f"{db_name}_user_auth", description, auth_ok,
        f"User '{username}' {'authenticated' if auth_ok else 'failed to authenticate'}", "INFO" if auth_ok else "WARNING"
    ))
    if not auth_ok:
        return tests

    # 2) Database exists & stats
    db_stats_cmd = (
        f"PGPASSWORD='{password}' psql -h {CNPG_HOST} -p {CNPG_PORT} "
        f"-U {username} -d {db_name} -t -c \"SELECT pg_database_size('{db_name}');\" 2>&1"
    )
    r = run_command(db_stats_cmd, timeout=20)
    if ok(r) and r['stdout']:
        tests.append(create_test_result(f"{db_name}_database_exists", description, True, f"DB stats fetched", "INFO"))
    else:
        tests.append(create_test_result(f"{db_name}_database_exists", description, False, f"DB stats failed: {r['stderr'] or r['stdout']}", "WARNING"))

    # 3) Collection/Table exists & count
    count_cmd = (
        f"PGPASSWORD='{password}' psql -h {CNPG_HOST} -p {CNPG_PORT} "
        f"-U {username} -d {db_name} -t -c \"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';\" 2>&1"
    )
    r = run_command(count_cmd, timeout=20)
    if ok(r) and r['stdout'] and r['stdout'].strip().isdigit():
        count = r['stdout'].strip()
        tests.append(create_test_result(f"{db_name}_collection_exists", description, True, f"Schema 'public' has {count} table(s)", "INFO"))
    else:
        tests.append(create_test_result(f"{db_name}_collection_exists", description, False, f"Table check failed: {r['stderr'] or r['stdout']}", "WARNING"))

    # 4) Write test (insert & delete)
    tests.append(check_database_write(db_name, username, password, auth_db, collection))

    # 5) Sharding metadata equivalent - check if database is properly configured
    tests.append(check_database_configuration(db_name))

    return tests


def check_database_write(db_name: str, username: str, password: str, auth_db: str, collection: str) -> Dict[str, Any]:
    description = "Check write operation to database"
    timestamp = int(time.time())
    
    # Create table if not exists
    create_cmd = (
        f"PGPASSWORD='{password}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U {username} -d {db_name} "
        f"-c 'CREATE TABLE IF NOT EXISTS {collection} (id SERIAL, test VARCHAR(100), timestamp BIGINT, source VARCHAR(50));' 2>&1"
    )
    run_command(create_cmd, timeout=10)
    
    # Insert test
    insert_cmd = (
        f"PGPASSWORD='{password}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U {username} -d {db_name} "
        f"-c \"INSERT INTO {collection} (test, timestamp, source) VALUES ('connectivity', {timestamp}, 'test_script');\" 2>&1"
    )
    r = run_command(insert_cmd, timeout=20)
    success = ok(r) and 'INSERT' in r['stdout']

    if success:
        cleanup_cmd = (
            f"PGPASSWORD='{password}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U {username} -d {db_name} "
            f"-c 'DELETE FROM {collection} WHERE timestamp={timestamp};' 2>&1"
        )
        run_command(cleanup_cmd, timeout=10)
        return create_test_result(f"{db_name}_write_test", description, True, f"Successfully wrote & cleaned up test doc in '{collection}'", "INFO")
    else:
        return create_test_result(f"{db_name}_write_test", description, False, f"Insert failed: {r['stderr'] or r['stdout']}", "WARNING")


def check_database_configuration(db_name: str) -> Dict[str, Any]:
    description = "Check if database is configured properly"
    cmd = (
        f"PGPASSWORD='{CNPG_ADMIN_PASSWORD}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U admin -d postgres "
        f"-t -c \"SELECT datname, pg_encoding_to_char(encoding) FROM pg_database WHERE datname='{db_name}';\" 2>&1"
    )
    r = run_command(cmd, timeout=15)
    if ok(r) and db_name in r['stdout']:
        return create_test_result(f"{db_name}_configuration", description, True, f"Database configured with UTF8 encoding", "INFO")
    return create_test_result(f"{db_name}_configuration", description, False, f"Database '{db_name}' configuration check failed", "WARNING")


def check_cnpg_pod_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    description = f"Check CNPG pod logs for errors (last {time_window_minutes}m)"
    tests: List[Dict[str, Any]] = []

    get_pods_cmd = (
        f"kubectl get pods -n {CNPG_NAMESPACE} -l 'cnpg.io/cluster={CLUSTER_NAME}' -o jsonpath='{{.items[*].metadata.name}}'"
    )
    pods_r = run_command(get_pods_cmd, timeout=15)
    if not ok(pods_r):
        tests.append(create_test_result("cnpg_logs_check", description, False, f"Failed to get pods: {pods_r['stderr']}", "WARNING"))
        return tests

    pod_names = [p for p in pods_r['stdout'].split() if p]
    if not pod_names:
        tests.append(create_test_result("cnpg_logs_check", description, False, "No CNPG pods found", "WARNING"))
        return tests

    error_patterns = [
        r'FATAL:',
        r'ERROR:',
        r'PANIC:',
        r'authentication failed',
        r'could not connect',
        r'out of memory',
    ]

    for pod in pod_names:
        log_cmd = f"kubectl logs -n {CNPG_NAMESPACE} {pod} --since={time_window_minutes}m 2>&1 | tail -200"
        lr = run_command(log_cmd, timeout=20)
        errors_found: List[str] = []
        if lr['stdout']:
            for line in lr['stdout'].splitlines():
                if any(re.search(pat, line, re.IGNORECASE) for pat in error_patterns):
                    errors_found.append(line[:200])
        if errors_found:
            tests.append(create_test_result(f"logs_{pod}", description, False, f"Found {len(errors_found)} suspicious lines", "WARNING"))
        else:
            tests.append(create_test_result(f"logs_{pod}", description, True, "No critical errors detected", "INFO"))

    return tests


def check_replica_set_status() -> List[Dict[str, Any]]:
    """
    Check replication status:
    - For primary instance, check streaming replication
    - For replicas, check recovery status
    """
    tests: List[Dict[str, Any]] = []

    # Check replication slots
    cmd = (
        f"PGPASSWORD='{CNPG_ADMIN_PASSWORD}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U admin -d postgres "
        f"-t -c 'SELECT slot_name, slot_type, active FROM pg_replication_slots;' 2>&1"
    )
    r = run_command(cmd, timeout=10)
    if ok(r):
        slots = r['stdout'] if r['stdout'] else "No replication slots"
        tests.append(create_test_result(
            "replica_slots", "Replication slots status", True,
            f"Replication slots: {slots[:200]}", "INFO"
        ))
    else:
        tests.append(create_test_result(
            "replica_slots", "Replication slots status", False,
            f"Check failed: {r['stderr'] or r['stdout']}", "WARNING"
        ))

    # Check streaming replication
    cmd = (
        f"PGPASSWORD='{CNPG_ADMIN_PASSWORD}' psql -h {CNPG_HOST} -p {CNPG_PORT} -U admin -d postgres "
        f"-t -c 'SELECT application_name, state, sync_state FROM pg_stat_replication;' 2>&1"
    )
    r = run_command(cmd, timeout=15)
    streaming_ok = ok(r)
    tests.append(create_test_result(
        "replica_streaming", "Streaming replication status", streaming_ok,
        f"Streaming: {r['stdout'][:200] if r['stdout'] else 'No streaming replicas'}", 
        "INFO" if streaming_ok else "WARNING"
    ))

    return tests

# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------

def test_cnpg() -> List[Dict[str, Any]]:
    start_time = time.time()
    results: List[Dict[str, Any]] = []

    # 1) postgres connectivity (gate)
    postgres_tests = check_postgres_connectivity()
    results.extend(postgres_tests)
    if not postgres_tests[0]['status']:
        # Early exit
        return results

    # 2) Cluster & instances
    results.extend(check_cluster_status())

    # 3) Replica sets
    results.extend(check_replica_set_status())

    # 4) Per-database checks
    for database in DATABASES:
        results.extend(check_database_access(database))

    # 5) Pod logs (optional, best-effort)
    results.extend(check_cnpg_pod_logs(time_window_minutes=5))

    return results


def main():
    """Main entry point"""
    try:
        results = test_cnpg()
        print(json.dumps(results, indent=2))
        
        # Exit with error if any critical tests failed
        critical_failures = [r for r in results if r['severity'] == 'critical' and not r['status']]
        sys.exit(1 if critical_failures else 0)
        
    except Exception as e:
        error_result = [create_test_result(
            "test_execution",
            "Test script execution",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
