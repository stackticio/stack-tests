#!/usr/bin/env python3
"""
MongoDB Sharded Cluster Test Script (fixed & hardened)
- Tests mongos connectivity, sharding, balancer, replica sets (best-effort), DB auth, collections, write, and pod logs
- Designed for Percona Server for MongoDB / general MongoDB sharded clusters

ENV VARS
  MONGODB_HOST (default: mongodb-mongos.mongodb.svc.cluster.local)
  MONGODB_PORT (default: 27017)
  MONGODB_MONGODB_CLUSTER_ADMIN_PASSWORD
  MONGODB_MONGODB_DATABASE_ADMIN_PASSWORD  (optional, not directly used)
  MONGODB_DATABASES  Format: db1:user1:pass1:authdb1:collection1;db2:...

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
    Parse MONGODB_DATABASES environment variable
    Format: db1:user1:pass1:authdb1:collection1;db2:user2:pass2:authdb2:collection2
    """
    databases = []
    databases_env = os.getenv('MONGODB_DATABASES', '')

    if not databases_env:
        print("Warning: MONGODB_DATABASES environment variable not found", file=sys.stderr)
        return databases

    for db_config in databases_env.split(';'):
        if db_config.strip():
            parts = db_config.strip().split(':')
            if len(parts) >= 5:
                databases.append({
                    'database': parts[0],
                    'username': parts[1],
                    'password': parts[2],
                    'auth_database': parts[3],
                    'collection': parts[4]
                })
            else:
                print(f"Warning: Invalid database configuration: {db_config}", file=sys.stderr)

    return databases

MONGO_HOST = os.getenv('MONGODB_HOST', 'mongodb-mongos.mongodb.svc.cluster.local')
MONGO_PORT = os.getenv('MONGODB_PORT', '27017')

CLUSTER_ADMIN_PASSWORD = os.getenv('MONGODB_MONGODB_CLUSTER_ADMIN_PASSWORD', 'default_password')
DATABASE_ADMIN_PASSWORD = os.getenv('MONGODB_MONGODB_DATABASE_ADMIN_PASSWORD', 'default_password')

DATABASES = parse_databases()

NAMESPACE = os.getenv('MONGODB_NAMESPACE', 'mongodb')

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

def check_mongos_connectivity() -> List[Dict[str, Any]]:
    description = "Check basic MongoDB mongos connectivity"
    command = (
        f"""mongosh --host {MONGO_HOST}:{MONGO_PORT} \
            --authenticationDatabase admin \
            -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' \
            --eval 'db.adminCommand(\"ping\")' --quiet"""
    )
    r = run_command(command, timeout=15)
    if ok(r) and ("ok: 1" in r['stdout'] or '"ok" : 1' in r['stdout'] or '"ok": 1' in r['stdout']):
        return [create_test_result("mongos_connectivity", description, True, f"Connected to mongos at {MONGO_HOST}:{MONGO_PORT}", "INFO")]
    else:
        msg = r['stderr'] or r['stdout'] or 'Unknown error'
        return [create_test_result("mongos_connectivity", description, False, f"Connectivity failed: {msg}", "CRITICAL")]


def _json_eval(js: str) -> Dict[str, Any]:
    """Helper: run a mongosh JS snippet that JSON.stringify()'s a value and returns parsed JSON."""
    command = (
        f"""mongosh --host {MONGO_HOST}:{MONGO_PORT} \
            --authenticationDatabase admin \
            -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' \
            --eval 'console.log(JSON.stringify({js}))' --quiet"""
    )
    r = run_command(command, timeout=20)
    if ok(r) and r['stdout']:
        try:
            return json.loads(r['stdout'].splitlines()[-1])
        except json.JSONDecodeError:
            return {}
    return {}


def check_sharding_status() -> List[Dict[str, Any]]:
    description = "Check sharding status and health of all shards"
    tests: List[Dict[str, Any]] = []

    # List shards via config (reliable JSON)
    shards = _json_eval('db.getSiblingDB("config").shards.find().toArray()')
    if not shards:
        tests.append(create_test_result("sharding_status", description, False, "No shards returned from config.shards", "WARNING"))
        return tests

    tests.append(create_test_result("sharding_status", description, True, f"Found {len(shards)} shard(s)", "INFO"))

    # Each shard health: presence in config + reachable member (best-effort)
    for s in shards:
        shard_id = s.get('_id', '<unknown>')
        host = s.get('host', '')  # e.g. rs0/host1:27017,host2:27017
        primary_host = host.split('/')[-1].split(',')[0] if host else ''

        # Best-effort: connect directly to the first member and run rs.status().ok
        if primary_host:
            cmd = (
                f"mongosh --host {primary_host} --authenticationDatabase admin -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' "
                f"--eval 'var s=rs.status(); print(s.ok===1?1:0)' --quiet"
            )
            r = run_command(cmd, timeout=10)
            healthy = ok(r) and r['stdout'].strip().endswith('1')
        else:
            r = {"stderr": "Missing shard host"}
            healthy = False

        tests.append(create_test_result(
            f"shard_{shard_id}_health",
            "Check individual shard health (rs.status best-effort)",
            healthy,
            f"host={host} | rs.status(): {'ok' if healthy else 'not ok'} | detail: {(r.get('stderr') or r.get('stdout') or '').strip()}",
            "INFO" if healthy else "WARNING"
        ))

    # Balancer
    tests.extend(check_balancer_status())

    # Databases sharding metadata
    dbs = _json_eval('db.getSiblingDB("config").databases.find().toArray()')
    if dbs:
        part = sum(1 for d in dbs if d.get('partitioned'))
        tests.append(create_test_result(
            "dbs_in_config", "Databases registered in config", True,
            f"config.databases count={len(dbs)}, partitioned={part}", "INFO"
        ))

    return tests


def check_balancer_status() -> List[Dict[str, Any]]:
    description = "Check balancer status"
    # sh.getBalancerState() returns bool; sh.isBalancerRunning() returns bool
    state = _json_eval('sh.getBalancerState()') if False else None  # placeholder to keep helper symmetric

    # We just call via mongosh and read stdout as string for booleans
    cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase admin -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' "
        f"--eval 'print(sh.getBalancerState())' --quiet"
    )
    r = run_command(cmd, timeout=10)
    if ok(r):
        enabled = r['stdout'].strip().lower() == 'true'
        return [create_test_result("balancer_status", description, True, f"Balancer {'ENABLED' if enabled else 'DISABLED'}", "INFO")]
    else:
        return [create_test_result("balancer_status", description, False, f"Failed to get balancer status: {r['stderr']}", "WARNING")]


def check_database_access(database: Dict[str, str]) -> List[Dict[str, Any]]:
    description = "Check database connectivity, user access, and collection operations"
    tests: List[Dict[str, Any]] = []
    db_name = database['database']
    username = database['username']
    password = database['password']
    auth_db = database['auth_database']
    collection = database['collection']

    # 1) User authentication
    auth_cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase {auth_db} -u {username} -p '{password}' "
        f"--eval 'db.adminCommand(\"ping\")' --quiet"
    )
    r = run_command(auth_cmd, timeout=15)
    auth_ok = ok(r) and ('ok: 1' in r['stdout'] or '"ok" : 1' in r['stdout'] or '"ok": 1' in r['stdout'])
    tests.append(create_test_result(
        f"{db_name}_user_auth", description, auth_ok,
        f"User '{username}' {'authenticated' if auth_ok else 'failed to authenticate'}", "INFO" if auth_ok else "WARNING"
    ))
    if not auth_ok:
        return tests

    # 2) Database exists & stats
    db_stats_cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase {auth_db} -u {username} -p '{password}' "
        f"--eval 'var s=db.getSiblingDB(\"{db_name}\").stats(); print(JSON.stringify(s))' --quiet"
    )
    r = run_command(db_stats_cmd, timeout=20)
    if ok(r) and r['stdout']:
        tests.append(create_test_result(f"{db_name}_database_exists", description, True, f"DB stats fetched", "INFO"))
    else:
        tests.append(create_test_result(f"{db_name}_database_exists", description, False, f"DB stats failed: {r['stderr'] or r['stdout']}", "WARNING"))

    # 3) Collection exists & count
    count_cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase {auth_db} -u {username} -p '{password}' "
        f"--eval 'var c=db.getSiblingDB(\"{db_name}\").getCollection(\"{collection}\").countDocuments({{}}); print(c)' --quiet"
    )
    r = run_command(count_cmd, timeout=20)
    if ok(r) and r['stdout'] and r['stdout'].strip().isdigit():
        count = r['stdout'].strip()
        tests.append(create_test_result(f"{db_name}_collection_exists", description, True, f"Collection '{collection}' exists with {count} documents", "INFO"))
    else:
        tests.append(create_test_result(f"{db_name}_collection_exists", description, False, f"Collection '{collection}' check failed: {r['stderr'] or r['stdout']}", "WARNING"))

    # 4) Write test (insert & delete)
    tests.append(check_database_write(db_name, username, password, auth_db, collection))

    # 5) Sharding metadata for this DB
    tests.append(check_database_sharding(db_name))

    return tests


def check_database_write(db_name: str, username: str, password: str, auth_db: str, collection: str) -> Dict[str, Any]:
    description = "Check write operation to database"
    timestamp = int(time.time())
    test_doc = f'{{"test":"connectivity","timestamp":{timestamp},"source":"test_script"}}'

    insert_cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase {auth_db} -u {username} -p '{password}' "
        f"--eval 'printjson(db.getSiblingDB(\"{db_name}\").getCollection(\"{collection}\").insertOne({test_doc}))' --quiet"
    )
    r = run_command(insert_cmd, timeout=20)
    success = ok(r) and ('acknowledged' in r['stdout'].lower())

    if success:
        cleanup_cmd = (
            f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase {auth_db} -u {username} -p '{password}' "
            f"--eval 'db.getSiblingDB(\"{db_name}\").getCollection(\"{collection}\").deleteOne({{timestamp:{timestamp}}})' --quiet"
        )
        run_command(cleanup_cmd, timeout=10)
        return create_test_result(f"{db_name}_write_test", description, True, f"Successfully wrote & cleaned up test doc in '{collection}'", "INFO")
    else:
        return create_test_result(f"{db_name}_write_test", description, False, f"Insert failed: {r['stderr'] or r['stdout']}", "WARNING")


def check_database_sharding(db_name: str) -> Dict[str, Any]:
    description = "Check if database is configured for sharding"
    cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase admin -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' "
        f"--eval 'var d=db.getSiblingDB(\"config\").databases.findOne({{_id: \"{db_name}\"}}); print(JSON.stringify(d||{{}}))' --quiet"
    )
    r = run_command(cmd, timeout=15)
    if ok(r) and r['stdout']:
        try:
            d = json.loads(r['stdout'])
        except Exception:
            d = {}
        if d.get('_id') == db_name:
            primary_shard = d.get('primary', 'unknown')
            partitioned = d.get('partitioned', False)
            return create_test_result(f"{db_name}_sharding_config", description, True, f"primary={primary_shard}, partitioned={partitioned}", "INFO")
    return create_test_result(f"{db_name}_sharding_config", description, False, f"Database '{db_name}' not found in config.databases", "WARNING")


def check_mongodb_pod_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    description = f"Check MongoDB pod logs for errors (last {time_window_minutes}m)"
    tests: List[Dict[str, Any]] = []

    get_pods_cmd = (
        f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=percona-server-mongodb' -o jsonpath='{{.items[*].metadata.name}}'"
    )
    pods_r = run_command(get_pods_cmd, timeout=15)
    if not ok(pods_r):
        tests.append(create_test_result("mongodb_logs_check", description, False, f"Failed to get pods: {pods_r['stderr']}", "WARNING"))
        return tests

    pod_names = [p for p in pods_r['stdout'].split() if p]
    if not pod_names:
        tests.append(create_test_result("mongodb_logs_check", description, False, "No MongoDB pods found", "WARNING"))
        return tests

    error_patterns = [
        r'STORAGE\s+\[.*?\]\s+exception',
        r'SHARDING\s+\[.*?\]\s+Failed',
        r'REPL\s+\[.*?\]\s+Error',
        r'Fatal assertion',
        r'BadValue:',
        r'AuthenticationFailed',
    ]

    for pod in pod_names:
        log_cmd = f"kubectl logs -n {NAMESPACE} {pod} --since={time_window_minutes}m --all-containers=true 2>&1 | tail -200"
        lr = run_command(log_cmd, timeout=20)
        errors_found: List[str] = []
        if lr['stdout']:
            for line in lr['stdout'].splitlines():
                if any(re.search(pat, line) for pat in error_patterns):
                    errors_found.append(line[:200])
        if errors_found:
            tests.append(create_test_result(f"logs_{pod}", description, False, f"Found {len(errors_found)} suspicious lines", "WARNING"))
        else:
            tests.append(create_test_result(f"logs_{pod}", description, True, "No critical errors detected", "INFO"))

    return tests


def check_replica_set_status() -> List[Dict[str, Any]]:
    """
    Best-effort replica set checks:
    - For each shard listed in config.shards, connect to the first host and run rs.status().ok
    - For config servers, try db.serverStatus().repl via mongos (limited) and mark informational
    """
    tests: List[Dict[str, Any]] = []

    shards = _json_eval('db.getSiblingDB("config").shards.find().toArray()')
    for s in shards or []:
        shard_id = s.get('_id', '<unknown>')
        host = s.get('host', '')
        primary_host = host.split('/')[-1].split(',')[0] if host else ''
        if primary_host:
            cmd = (
                f"mongosh --host {primary_host} --authenticationDatabase admin -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' "
                f"--eval 'var s=rs.status(); print(s.ok===1?1:0)' --quiet"
            )
            r = run_command(cmd, timeout=10)
            healthy = ok(r) and r['stdout'].strip().endswith('1')
            tests.append(create_test_result(
                f"replica_set_{shard_id}", "Replica set health (direct member check)", healthy,
                f"host={host} | rs.status(): {'ok' if healthy else 'not ok'} | detail: {(r.get('stderr') or r.get('stdout') or '').strip()}",
                "INFO" if healthy else "WARNING"
            ))
        else:
            tests.append(create_test_result(
                f"replica_set_{shard_id}", "Replica set health (direct member check)", False,
                f"No member host parsed from '{host}'", "WARNING"
            ))

    # Config server (informational via mongos)
    cmd = (
        f"mongosh --host {MONGO_HOST}:{MONGO_PORT} --authenticationDatabase admin -u clusterAdmin -p '{CLUSTER_ADMIN_PASSWORD}' "
        f"--eval 'var r=db.getSiblingDB(\"config\").runCommand({{serverStatus:1}}).repl; print(r?1:0)' --quiet"
    )
    r = run_command(cmd, timeout=15)
    cfg_ok = ok(r) and r['stdout'].strip().endswith('1')
    tests.append(create_test_result("replica_set_config", "Config server replica set (serverStatus presence)", cfg_ok, "serverStatus().repl present" if cfg_ok else f"Check failed: {r['stderr'] or r['stdout']}", "INFO" if cfg_ok else "WARNING"))

    return tests

# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------

def test_mongo_db() -> List[Dict[str, Any]]:
    start_time = time.time()
    results: List[Dict[str, Any]] = []

    # 1) mongos connectivity (gate)
    mongos_tests = check_mongos_connectivity()
    results.extend(mongos_tests)
    if not mongos_tests[0]['status']:
        # Early exit
        return results

    # 2) Sharding & shards
    results.extend(check_sharding_status())

    # 3) Replica sets
    results.extend(check_replica_set_status())

    # 4) Per-database checks
    for database in DATABASES:
        results.extend(check_database_access(database))

    # 5) Pod logs (optional, best-effort)
    results.extend(check_mongodb_pod_logs(time_window_minutes=5))

    return results
