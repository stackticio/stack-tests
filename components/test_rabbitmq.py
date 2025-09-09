#!/usr/bin/env python3
"""
RabbitMQ Cluster Test Script
- Tests connectivity, vhost access, exchanges, queues, bindings, user auth, message publish/consume, and cluster health
- Designed for RabbitMQ clusters with management API

ENV VARS
  RABBITMQ_HOST (default: rabbitmq.rabbitmq-system.svc.cluster.local)
  RABBITMQ_PORT (default: 5672)
  RABBITMQ_ADMIN_PASSWORD (admin password for rabbitmqadmin)
  RABBITMQ_USER (default: user)
  RABBITMQ_PASSWORD (default password)
  RABBITMQ_VHOST (default: /)
  RABBITMQ_EXCHANGES  Format: exchange1,exchange2,exchange3
  RABBITMQ_QUEUES  Format: queue1,queue2,queue3
  RABBITMQ_NS (default: rabbitmq-system)

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
from typing import Dict, List, Any, Optional
from datetime import datetime

# ------------------------------------------------------------
# Utilities & configuration
# ------------------------------------------------------------

def parse_exchanges() -> List[str]:
    """Parse RABBITMQ_EXCHANGES environment variable"""
    exchanges_env = os.getenv('RABBITMQ_EXCHANGES', '')
    if not exchanges_env:
        print("Warning: RABBITMQ_EXCHANGES environment variable not found", file=sys.stderr)
        return []
    return [e.strip() for e in exchanges_env.split(',') if e.strip()]

def parse_queues() -> List[str]:
    """Parse RABBITMQ_QUEUES environment variable"""
    queues_env = os.getenv('RABBITMQ_QUEUES', '')
    if not queues_env:
        print("Warning: RABBITMQ_QUEUES environment variable not found", file=sys.stderr)
        return []
    return [q.strip() for q in queues_env.split(',') if q.strip()]

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq.rabbitmq-system.svc.cluster.local')
RABBITMQ_PORT = os.getenv('RABBITMQ_PORT', '5672')
RABBITMQ_MGMT_PORT = '15672'  # Standard management port

RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'user')
RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD', 'default_pass1')
RABBITMQ_ADMIN_PASSWORD = os.getenv('RABBITMQ_ADMIN_PASSWORD', 'default_password')
RABBITMQ_VHOST = os.getenv('RABBITMQ_VHOST', '/')

EXCHANGES = parse_exchanges()
QUEUES = parse_queues()

NAMESPACE = os.getenv('RABBITMQ_NS', 'rabbitmq-system')

# Track which user works for admin operations
ADMIN_USER = None
ADMIN_PASS = None

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

def check_rabbitmq_connectivity() -> List[Dict[str, Any]]:
    """Check basic RabbitMQ connectivity using rabbitmqadmin"""
    global ADMIN_USER, ADMIN_PASS
    description = "Check basic RabbitMQ management API connectivity"
    
    # Try different user combinations
    user_pass_combos = [
        ('admin', RABBITMQ_ADMIN_PASSWORD),
        (RABBITMQ_USER, RABBITMQ_PASSWORD),
        ('guest', RABBITMQ_ADMIN_PASSWORD),
    ]
    
    for username, password in user_pass_combos:
        command = (
            f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
            f"--username={username} --password='{password}' "
            f"show overview"
        )
        
        r = run_command(command, timeout=15)
        if ok(r) and ('rabbitmq_version' in r['stdout'] or 'node' in r['stdout']):
            ADMIN_USER = username
            ADMIN_PASS = password
            return [create_test_result(
                "rabbitmq_connectivity", 
                description, 
                True, 
                f"Connected to RabbitMQ management API at {RABBITMQ_HOST}:{RABBITMQ_MGMT_PORT} as user '{username}'", 
                "INFO"
            )]
    
    msg = r['stderr'] or r['stdout'] or 'Unknown error'
    return [create_test_result(
        "rabbitmq_connectivity", 
        description, 
        False, 
        f"Connectivity failed: {msg}", 
        "CRITICAL"
    )]

def check_cluster_status() -> List[Dict[str, Any]]:
    """Check RabbitMQ cluster status and health of all nodes"""
    description = "Check cluster status and health of all nodes"
    tests: List[Dict[str, Any]] = []
    
    # Use the admin user that worked
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"list nodes name type running"
    )
    
    r = run_command(command, timeout=20)
    if ok(r) and r['stdout']:
        lines = r['stdout'].split('\n')
        # Parse table output to count nodes
        node_count = 0
        running_count = 0
        for line in lines:
            if '|' in line and 'name' not in line.lower() and '---' not in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 4:
                    node_count += 1
                    if parts[3].lower() == 'true':
                        running_count += 1
        
        tests.append(create_test_result(
            "cluster_status",
            description,
            running_count > 0,
            f"Found {node_count} node(s), {running_count} running",
            "INFO" if running_count > 0 else "CRITICAL"
        ))
        
        # Check if cluster is properly formed (all nodes running)
        tests.append(create_test_result(
            "cluster_health",
            "Check if all cluster nodes are running",
            node_count == running_count,
            f"{running_count}/{node_count} nodes running",
            "INFO" if node_count == running_count else "WARNING"
        ))
    else:
        tests.append(create_test_result(
            "cluster_status",
            description,
            False,
            f"Failed to get cluster status: {r['stderr'] or r['stdout']}",
            "CRITICAL"
        ))
    
    return tests

def check_vhost_access() -> List[Dict[str, Any]]:
    """Check vhost access and permissions"""
    description = "Check vhost access and user permissions"
    tests: List[Dict[str, Any]] = []
    
    # Check if vhost exists using admin user
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"list vhosts name"
    )
    
    r = run_command(command, timeout=15)
    if ok(r) and RABBITMQ_VHOST in r['stdout']:
        tests.append(create_test_result(
            "vhost_exists",
            "Check if vhost exists",
            True,
            f"Vhost '{RABBITMQ_VHOST}' exists",
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "vhost_exists",
            "Check if vhost exists",
            False,
            f"Vhost '{RABBITMQ_VHOST}' not found",
            "CRITICAL"
        ))
        return tests
    
    # Check user permissions on vhost
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' list permissions"
    )
    
    r = run_command(command, timeout=15)
    if ok(r):
        tests.append(create_test_result(
            "user_permissions",
            "Check user permissions on vhost",
            True,
            f"Permissions listed for vhost '{RABBITMQ_VHOST}'",
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "user_permissions",
            "Check user permissions on vhost",
            False,
            f"Failed to verify permissions: {r['stderr'] or r['stdout']}",
            "WARNING"
        ))
    
    return tests

def check_exchange_operations(exchange: str) -> List[Dict[str, Any]]:
    """Check exchange existence and operations"""
    description = f"Check exchange '{exchange}' operations"
    tests: List[Dict[str, Any]] = []
    
    # Check if exchange exists - list all exchanges and check
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' list exchanges name type"
    )
    
    r = run_command(command, timeout=15)
    exchange_exists = False
    exchange_type = "topic"  # default type
    
    if ok(r) and r['stdout']:
        # Parse the output to find our exchange
        lines = r['stdout'].split('\n')
        for line in lines:
            if '|' in line and exchange in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2 and parts[1] == exchange:
                    exchange_exists = True
                    if len(parts) >= 3:
                        exchange_type = parts[2] or "topic"
                    break
    
    if exchange_exists:
        tests.append(create_test_result(
            f"exchange_{exchange}_exists",
            f"Check exchange '{exchange}' existence",
            True,
            f"Exchange '{exchange}' exists (type: {exchange_type})",
            "INFO"
        ))
    else:
        # Try to declare the exchange
        declare_cmd = (
            f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
            f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
            f"--vhost='{RABBITMQ_VHOST}' declare exchange name={exchange} type=topic"
        )
        dr = run_command(declare_cmd, timeout=15)
        if ok(dr):
            tests.append(create_test_result(
                f"exchange_{exchange}_create",
                f"Create exchange '{exchange}'",
                True,
                f"Exchange '{exchange}' created successfully (type: topic)",
                "INFO"
            ))
            exchange_exists = True
        else:
            tests.append(create_test_result(
                f"exchange_{exchange}_create",
                f"Create exchange '{exchange}'",
                False,
                f"Failed to create exchange: {dr['stderr'] or dr['stdout']}",
                "WARNING"
            ))
    
    # Test publishing to exchange
    if exchange_exists:
        tests.extend(check_exchange_publish(exchange))
    
    return tests

def check_queue_operations(queue: str) -> List[Dict[str, Any]]:
    """Check queue existence and operations"""
    description = f"Check queue '{queue}' operations"
    tests: List[Dict[str, Any]] = []
    
    # Check if queue exists - list all queues
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' list queues name messages"
    )
    
    r = run_command(command, timeout=15)
    queue_exists = False
    msg_count = "0"
    
    if ok(r) and r['stdout']:
        # Parse the output to find our queue
        lines = r['stdout'].split('\n')
        for line in lines:
            if '|' in line and queue in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2 and parts[1] == queue:
                    queue_exists = True
                    if len(parts) >= 3:
                        msg_count = parts[2] or "0"
                    break
    
    if queue_exists:
        tests.append(create_test_result(
            f"queue_{queue}_exists",
            f"Check queue '{queue}' existence",
            True,
            f"Queue '{queue}' exists with {msg_count} messages",
            "INFO"
        ))
    else:
        # Try to declare the queue
        declare_cmd = (
            f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
            f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
            f"--vhost='{RABBITMQ_VHOST}' declare queue name={queue} durable=true"
        )
        dr = run_command(declare_cmd, timeout=15)
        if ok(dr):
            tests.append(create_test_result(
                f"queue_{queue}_create",
                f"Create queue '{queue}'",
                True,
                f"Queue '{queue}' created successfully",
                "INFO"
            ))
            queue_exists = True
        else:
            tests.append(create_test_result(
                f"queue_{queue}_create",
                f"Create queue '{queue}'",
                False,
                f"Failed to create queue: {dr['stderr'] or dr['stdout']}",
                "WARNING"
            ))
    
    # Test message operations on queue
    if queue_exists:
        tests.extend(check_queue_message_operations(queue))
    
    return tests

def check_exchange_publish(exchange: str) -> List[Dict[str, Any]]:
    """Test publishing a message to an exchange"""
    description = f"Test message publish to exchange '{exchange}'"
    timestamp = int(time.time())
    test_message = f'{{"test":"connectivity","timestamp":{timestamp},"exchange":"{exchange}"}}'
    
    # Create a temporary queue for testing
    temp_queue = f"test_queue_{exchange}_{timestamp}"
    
    # Declare temporary queue
    declare_queue_cmd = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' declare queue name={temp_queue} auto_delete=true"
    )
    qr = run_command(declare_queue_cmd, timeout=15)
    
    if not ok(qr):
        return [create_test_result(
            f"exchange_{exchange}_publish_test",
            description,
            False,
            f"Failed to create test queue: {qr['stderr'] or qr['stdout']}",
            "WARNING"
        )]
    
    # Bind queue to exchange with a wildcard routing key for topic exchange
    bind_cmd = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' declare binding source={exchange} "
        f"destination={temp_queue} routing_key='#'"
    )
    br = run_command(bind_cmd, timeout=15)
    
    # Publish message
    publish_cmd = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' publish exchange={exchange} "
        f"routing_key=test.message payload='{test_message}'"
    )
    pr = run_command(publish_cmd, timeout=15)
    
    # Clean up - delete the temporary queue
    cleanup_cmd = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' delete queue name={temp_queue}"
    )
    run_command(cleanup_cmd, timeout=10)
    
    if ok(pr):
        return [create_test_result(
            f"exchange_{exchange}_publish_test",
            description,
            True,
            f"Successfully published test message to exchange '{exchange}'",
            "INFO"
        )]
    else:
        return [create_test_result(
            f"exchange_{exchange}_publish_test",
            description,
            False,
            f"Publish failed: {pr['stderr'] or pr['stdout']}",
            "WARNING"
        )]

def check_queue_message_operations(queue: str) -> List[Dict[str, Any]]:
    """Test message publish and consume operations on a queue"""
    description = f"Test message operations on queue '{queue}'"
    timestamp = int(time.time())
    test_message = f'{{"test":"connectivity","timestamp":{timestamp},"queue":"{queue}"}}'
    
    # Publish message directly to queue
    publish_cmd = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' publish routing_key={queue} "
        f"payload='{test_message}'"
    )
    
    pr = run_command(publish_cmd, timeout=15)
    if not ok(pr):
        return [create_test_result(
            f"queue_{queue}_message_test",
            description,
            False,
            f"Failed to publish message: {pr['stderr'] or pr['stdout']}",
            "WARNING"
        )]
    
    # Small delay to ensure message is available
    time.sleep(1)
    
    # Get message (without acking to preserve it)
    get_cmd = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' get queue={queue} ackmode=ack_requeue_true count=1"
    )
    
    gr = run_command(get_cmd, timeout=15)
    if ok(gr):
        # Check if we got a message (rabbitmqadmin returns success even if no messages)
        if 'No messages' in gr['stdout'] or not gr['stdout']:
            return [create_test_result(
                f"queue_{queue}_message_test",
                description,
                False,
                f"No messages found in queue (might be consumed by another process)",
                "WARNING"
            )]
        elif str(timestamp) in gr['stdout'] or 'payload' in gr['stdout']:
            return [create_test_result(
                f"queue_{queue}_message_test",
                description,
                True,
                f"Successfully published and retrieved test message from queue '{queue}'",
                "INFO"
            )]
        else:
            # Message exists but might be from another source
            return [create_test_result(
                f"queue_{queue}_message_test",
                description,
                True,
                f"Retrieved a message from queue '{queue}' (may not be test message)",
                "INFO"
            )]
    else:
        return [create_test_result(
            f"queue_{queue}_message_test",
            description,
            False,
            f"Message retrieval failed: {gr['stderr'] or gr['stdout']}",
            "WARNING"
        )]

def check_rabbitmq_pod_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Check RabbitMQ pod logs for errors"""
    description = f"Check RabbitMQ pod logs for errors (last {time_window_minutes}m)"
    tests: List[Dict[str, Any]] = []
    
    # Get RabbitMQ pods
    get_pods_cmd = (
        f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=rabbitmq' "
        f"-o jsonpath='{{.items[*].metadata.name}}'"
    )
    
    pods_r = run_command(get_pods_cmd, timeout=15)
    if not ok(pods_r):
        # Try alternative label
        get_pods_cmd = (
            f"kubectl get pods -n {NAMESPACE} -l 'app=rabbitmq' "
            f"-o jsonpath='{{.items[*].metadata.name}}'"
        )
        pods_r = run_command(get_pods_cmd, timeout=15)
    
    if not ok(pods_r):
        tests.append(create_test_result(
            "rabbitmq_logs_check",
            description,
            False,
            f"Failed to get pods: {pods_r['stderr']}",
            "WARNING"
        ))
        return tests
    
    pod_names = [p for p in pods_r['stdout'].split() if p]
    if not pod_names:
        tests.append(create_test_result(
            "rabbitmq_logs_check",
            description,
            False,
            "No RabbitMQ pods found",
            "WARNING"
        ))
        return tests
    
    error_patterns = [
        r'CRASH REPORT',
        r'Error in process',
        r'Failed to start',
        r'Connection refused',
        r'Authentication failed',
        r'AMQP connection .* closed',
        r'Channel error',
        r'failed to sync',
    ]
    
    for pod in pod_names:
        log_cmd = (
            f"kubectl logs -n {NAMESPACE} {pod} "
            f"--since={time_window_minutes}m --all-containers=true 2>&1 | tail -200"
        )
        lr = run_command(log_cmd, timeout=20)
        errors_found: List[str] = []
        
        if lr['stdout']:
            for line in lr['stdout'].splitlines():
                if any(re.search(pat, line, re.IGNORECASE) for pat in error_patterns):
                    errors_found.append(line[:200])
        
        if errors_found:
            tests.append(create_test_result(
                f"logs_{pod}",
                description,
                False,
                f"Found {len(errors_found)} error lines",
                "WARNING"
            ))
        else:
            tests.append(create_test_result(
                f"logs_{pod}",
                description,
                True,
                "No critical errors detected",
                "INFO"
            ))
    
    return tests

def check_message_rates() -> List[Dict[str, Any]]:
    """Check message rates and queue statistics"""
    description = "Check message rates and queue statistics"
    
    # Get overview including message rates
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"show overview | grep -E 'messages|publish|deliver|ack'"
    )
    
    r = run_command(command, timeout=15)
    if ok(r) and r['stdout']:
        return [create_test_result(
            "message_rates",
            description,
            True,
            "Message rate statistics retrieved",
            "INFO"
        )]
    else:
        return [create_test_result(
            "message_rates",
            description,
            False,
            "Failed to retrieve message rates",
            "WARNING"
        )]

def check_bindings() -> List[Dict[str, Any]]:
    """Check bindings between exchanges and queues"""
    description = "Check bindings configuration"
    tests: List[Dict[str, Any]] = []
    
    # List all bindings
    command = (
        f"rabbitmqadmin --host={RABBITMQ_HOST} --port={RABBITMQ_MGMT_PORT} "
        f"--username={ADMIN_USER} --password='{ADMIN_PASS}' "
        f"--vhost='{RABBITMQ_VHOST}' list bindings source destination routing_key"
    )
    
    r = run_command(command, timeout=15)
    if ok(r):
        # Count bindings (excluding header lines)
        lines = r['stdout'].split('\n')
        binding_count = sum(1 for line in lines if '|' in line and 'source' not in line.lower() and '---' not in line)
        
        tests.append(create_test_result(
            "bindings_check",
            description,
            True,
            f"Found {binding_count} binding(s) in vhost '{RABBITMQ_VHOST}'",
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "bindings_check",
            description,
            False,
            f"Failed to list bindings: {r['stderr'] or r['stdout']}",
            "WARNING"
        ))
    
    return tests

# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------

def test_rabbitmq() -> List[Dict[str, Any]]:
    """Main test runner for RabbitMQ"""
    start_time = time.time()
    results: List[Dict[str, Any]] = []
    
    # 1) RabbitMQ connectivity (gate)
    connectivity_tests = check_rabbitmq_connectivity()
    results.extend(connectivity_tests)
    if not connectivity_tests[0]['status']:
        # Early exit if can't connect
        return results
    
    # 2) Cluster status
    results.extend(check_cluster_status())
    
    # 3) Vhost access
    results.extend(check_vhost_access())
    
    # 4) Exchange checks
    for exchange in EXCHANGES:
        results.extend(check_exchange_operations(exchange))
    
    # 5) Queue checks
    for queue in QUEUES:
        results.extend(check_queue_operations(queue))
    
    # 6) Bindings check
    results.extend(check_bindings())
    
    # 7) Message rates
    results.extend(check_message_rates())
    
    # 8) Pod logs (optional, best-effort)
    results.extend(check_rabbitmq_pod_logs(time_window_minutes=5))
    
    return results

# ------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------

if __name__ == "__main__":
    try:
        # Run tests
        test_results = test_rabbitmq()
        
        # Output as JSON
        print(json.dumps(test_results, indent=2))
        
        # Exit with appropriate code
        has_critical = any(r['severity'] == 'critical' and not r['status'] for r in test_results)
        sys.exit(1 if has_critical else 0)
        
    except Exception as e:
        # Handle unexpected errors
        error_result = [create_test_result(
            "test_execution_error",
            "Test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
