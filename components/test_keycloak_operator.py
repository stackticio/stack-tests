#!/usr/bin/env python3
"""
Keycloak Health Check Script - Structured version
Tests Keycloak configuration dynamically with JSON output format

ENV VARS:
  KEYCLOAK_OPERATOR_NS (default: keycloak)
  KEYCLOAK_OPERATOR_HOST (default: keycloak-operator.keycloak.svc.cluster.local)
  KEYCLOAK_OPERATOR_PORT (default: 8080)
  KEYCLOAK_OPERATOR_ADMIN_PASSWORD (default: password_default1)
  KEYCLOAK_OPERATOR_REALM (default: my-realm)
  KEYCLOAK_LOG_TIME_WINDOW (default: 5m)

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import subprocess
import sys
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

NAMESPACE = os.getenv('KEYCLOAK_OPERATOR_NS', 'keycloak')
KEYCLOAK_OPERATOR_HOST = os.getenv('KEYCLOAK_OPERATOR_HOST', 'keycloak-operator.keycloak.svc.cluster.local')
KEYCLOAK_OPERATOR_PORT = os.getenv('KEYCLOAK_OPERATOR_PORT', '8080')
KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_OPERATOR_ADMIN_PASSWORD', 'password_default1')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_OPERATOR_REALM', 'my-realm')
LOG_TIME_WINDOW = os.getenv('KEYCLOAK_LOG_TIME_WINDOW', '5m')

# Actual service names from cluster
KEYCLOAK_SERVICE_HOST = f"kc-server-service.{NAMESPACE}.svc.cluster.local"
KEYCLOAK_DB_HOST = f"keycloak-operator-postgresql-db.{NAMESPACE}.svc.cluster.local"

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def run_command(command: str, env: Optional[Dict[str, str]] = None, timeout: int = 10) -> Dict[str, Any]:
    """Run shell command and return results"""
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
    """Check if command executed successfully"""
    return proc.get("exit_code", 1) == 0


def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }


def get_keycloak_pod(namespace: str) -> Optional[str]:
    """Get Keycloak pod name"""
    cmd = f"kubectl get pods -n {namespace} -l 'app=keycloak' --field-selector=status.phase=Running -o name | head -1 | cut -d'/' -f2"
    result = run_command(cmd)
    return result['stdout'] if ok(result) and result['stdout'] else None


# ------------------------------------------------------------
# Test Functions
# ------------------------------------------------------------

def test_keycloak_connectivity() -> List[Dict[str, Any]]:
    """Test Keycloak API connectivity"""
    description = "Check Keycloak API connectivity"
    tests = []
    
    # Test the main Keycloak service (port 8080)
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/health"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 300:
            output = f"Keycloak API is accessible (HTTP {http_code})"
            tests.append(create_test_result("keycloak_api_connectivity", description, True, output, "INFO"))
            return tests
        elif code == 404:
            # Try alternate health endpoint
            url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/health/ready"
            command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
            result = run_command(command)
            http_code = result['stdout'].strip()
            if http_code and http_code.isdigit() and 200 <= int(http_code) < 300:
                output = f"Keycloak API is accessible via /health/ready (HTTP {http_code})"
                tests.append(create_test_result("keycloak_api_connectivity", description, True, output, "INFO"))
                return tests
    
    # If health endpoints fail, try the root endpoint
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 500:
            output = f"Keycloak service is responding (HTTP {http_code})"
            tests.append(create_test_result("keycloak_api_connectivity", description, True, output, "INFO"))
            return tests
    
    output = f"Keycloak API connectivity failed (HTTP {http_code if http_code else 'no response'})"
    tests.append(create_test_result("keycloak_api_connectivity", description, False, output, "CRITICAL"))
    return tests


def test_keycloak_health() -> List[Dict[str, Any]]:
    """Test Keycloak health endpoints"""
    description = "Check Keycloak health status"
    tests = []
    
    # Test readiness
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/health/ready"
    command = f"curl -s --connect-timeout 5 {url}"
    result = run_command(command)
    
    if result['stdout'] and '{' in result['stdout']:
        try:
            health_data = json.loads(result['stdout'])
            status = health_data.get('status', 'unknown')
            
            if status == 'UP':
                output = "Keycloak readiness check passed (status: UP)"
                tests.append(create_test_result("keycloak_readiness", "Check Keycloak readiness", 
                                                 True, output, "INFO"))
            else:
                output = f"Keycloak readiness check failed (status: {status})"
                tests.append(create_test_result("keycloak_readiness", "Check Keycloak readiness",
                                                 False, output, "WARNING"))
        except json.JSONDecodeError:
            pass
    
    # Test liveness
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/health/live"
    command = f"curl -s --connect-timeout 5 {url}"
    result = run_command(command)
    
    if result['stdout'] and '{' in result['stdout']:
        try:
            health_data = json.loads(result['stdout'])
            status = health_data.get('status', 'unknown')
            
            if status == 'UP':
                output = "Keycloak liveness check passed (status: UP)"
                tests.append(create_test_result("keycloak_liveness", "Check Keycloak liveness",
                                                 True, output, "INFO"))
            else:
                output = f"Keycloak liveness check failed (status: {status})"
                tests.append(create_test_result("keycloak_liveness", "Check Keycloak liveness",
                                                 False, output, "CRITICAL"))
        except json.JSONDecodeError:
            pass
    
    if not tests:
        # Fallback to HTTP status check
        url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/"
        command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
        result = run_command(command)
        http_code = result['stdout'].strip()
        
        if http_code and http_code.isdigit() and 200 <= int(http_code) < 400:
            output = f"Keycloak is responding (HTTP {http_code})"
            tests.append(create_test_result("keycloak_health", description, True, output, "INFO"))
        else:
            output = f"Keycloak health check failed (HTTP {http_code if http_code else 'no response'})"
            tests.append(create_test_result("keycloak_health", description, False, output, "CRITICAL"))
    
    return tests


def test_keycloak_pods() -> List[Dict[str, Any]]:
    """Check Keycloak pod status"""
    description = "Check Keycloak pod health and readiness"
    tests = []
    
    # Check Keycloak server pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=keycloak' -o json"
    result = run_command(command)
    
    if ok(result) and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            pods = data.get('items', [])
            
            total_pods = len(pods)
            ready_pods = 0
            not_ready = []
            
            for pod in pods:
                pod_name = pod['metadata']['name']
                conditions = pod.get('status', {}).get('conditions', [])
                
                is_ready = any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in conditions)
                if is_ready:
                    ready_pods += 1
                else:
                    not_ready.append(pod_name)
            
            if total_pods == ready_pods and total_pods > 0:
                output = f"All {total_pods} Keycloak server pods are ready"
                severity = "INFO"
                passed = True
            elif ready_pods > 0:
                output = f"Keycloak server pods: {ready_pods}/{total_pods} ready"
                if not_ready:
                    output += f" (Not ready: {', '.join(not_ready)})"
                severity = "WARNING"
                passed = False
            else:
                output = f"No Keycloak server pods are ready ({total_pods} total)"
                severity = "CRITICAL"
                passed = False
            
            tests.append(create_test_result("keycloak_server_pods", "Check Keycloak server pods",
                                             passed, output, severity))
        except json.JSONDecodeError:
            tests.append(create_test_result("keycloak_server_pods", "Check Keycloak server pods",
                                             False, "Failed to parse pod data", "WARNING"))
    else:
        tests.append(create_test_result("keycloak_server_pods", "Check Keycloak server pods",
                                        False, f"Failed to get pods: {result['stderr']}", "CRITICAL"))
    
    # Check PostgreSQL pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=postgresql-db' -o json"
    result = run_command(command)
    
    if ok(result) and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            pods = data.get('items', [])
            
            total_pods = len(pods)
            ready_pods = sum(1 for pod in pods 
                           if any(c.get('type') == 'Ready' and c.get('status') == 'True' 
                                 for c in pod.get('status', {}).get('conditions', [])))
            
            if total_pods == ready_pods and total_pods > 0:
                output = f"PostgreSQL pods: {ready_pods}/{total_pods} ready"
                passed = True
                severity = "INFO"
            else:
                output = f"PostgreSQL pods: {ready_pods}/{total_pods} ready"
                passed = False
                severity = "WARNING"
            
            tests.append(create_test_result("keycloak_db_pods", "Check Keycloak database pods",
                                             passed, output, severity))
        except json.JSONDecodeError:
            pass
    
    # Check Operator pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=keycloak' -o json"
    result = run_command(command)
    
    if ok(result) and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            pods = data.get('items', [])
            
            total_pods = len(pods)
            ready_pods = sum(1 for pod in pods 
                           if any(c.get('type') == 'Ready' and c.get('status') == 'True' 
                                 for c in pod.get('status', {}).get('conditions', [])))
            
            if total_pods > 0:
                output = f"Keycloak operator pods: {ready_pods}/{total_pods} ready"
                passed = ready_pods == total_pods
                severity = "INFO" if passed else "WARNING"
                tests.append(create_test_result("keycloak_operator_pods", "Check Keycloak operator pods",
                                                 passed, output, severity))
        except json.JSONDecodeError:
            pass
    
    return tests


def test_keycloak_database() -> List[Dict[str, Any]]:
    """Test PostgreSQL database connectivity"""
    description = "Check Keycloak database connectivity"
    tests = []
    
    # Test database port connectivity
    command = f"timeout 2 bash -c 'cat < /dev/null > /dev/tcp/{KEYCLOAK_DB_HOST}/5432' 2>/dev/null && echo 'success' || echo 'failed'"
    result = run_command(command)
    
    if result['stdout'] == 'success':
        output = "PostgreSQL database is accessible on port 5432"
        tests.append(create_test_result("keycloak_database", description, True, output, "INFO"))
    else:
        output = "PostgreSQL database connection failed on port 5432"
        tests.append(create_test_result("keycloak_database", description, False, output, "CRITICAL"))
    
    return tests


def test_keycloak_realms() -> List[Dict[str, Any]]:
    """Test Keycloak realms endpoint"""
    description = "Check Keycloak realms availability"
    tests = []
    
    # Test if we can access the realms endpoint
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/realms/{KEYCLOAK_REALM}"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 300:
            output = f"Realm '{KEYCLOAK_REALM}' is accessible (HTTP {http_code})"
            tests.append(create_test_result("keycloak_realm", description, True, output, "INFO"))
            return tests
        elif code == 404:
            output = f"Realm '{KEYCLOAK_REALM}' not found (HTTP 404) - may need to be created"
            tests.append(create_test_result("keycloak_realm", description, False, output, "WARNING"))
            return tests
    
    # Try master realm as fallback
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/realms/master"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit() and 200 <= int(http_code) < 300:
        output = f"Master realm is accessible but '{KEYCLOAK_REALM}' is not configured"
        tests.append(create_test_result("keycloak_realm", description, False, output, "WARNING"))
    else:
        output = "Keycloak realms endpoint is not accessible"
        tests.append(create_test_result("keycloak_realm", description, False, output, "CRITICAL"))
    
    return tests


def test_keycloak_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Check Keycloak logs for errors"""
    description = f"Check Keycloak logs for errors (last {LOG_TIME_WINDOW})"
    tests = []
    
    # Get Keycloak server pod names
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=keycloak' -o jsonpath='{{.items[*].metadata.name}}'"
    pod_result = run_command(command)
    
    if ok(pod_result) and pod_result['stdout']:
        pod_names = pod_result['stdout'].split()
        
        for pod_name in pod_names:
            if not pod_name:
                continue
            
            # Check for errors in logs
            command = f"kubectl logs -n {NAMESPACE} {pod_name} --since={LOG_TIME_WINDOW} 2>&1 | grep -iE 'error|exception|fatal|failed' | grep -v 'LifecycleException' | wc -l"
            result = run_command(command, timeout=15)
            
            if result['stdout'] and result['stdout'].isdigit():
                error_count = int(result['stdout'])
                
                if error_count == 0:
                    output = f"No errors in last {LOG_TIME_WINDOW}"
                    passed = True
                    severity = "INFO"
                elif error_count < 10:
                    output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                    passed = False
                    severity = "WARNING"
                else:
                    output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                    passed = False
                    severity = "CRITICAL"
                
                tests.append(create_test_result(f"keycloak_logs_{pod_name}",
                                                f"Check logs for {pod_name}",
                                                passed, output, severity))
    
    # Check database logs
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=postgresql-db' -o jsonpath='{{.items[*].metadata.name}}'"
    pod_result = run_command(command)
    
    if ok(pod_result) and pod_result['stdout']:
        pod_names = pod_result['stdout'].split()
        
        for pod_name in pod_names:
            if not pod_name:
                continue
            
            command = f"kubectl logs -n {NAMESPACE} {pod_name} --since={LOG_TIME_WINDOW} 2>&1 | grep -iE 'error|fatal|panic' | wc -l"
            result = run_command(command, timeout=15)
            
            if result['stdout'] and result['stdout'].isdigit():
                error_count = int(result['stdout'])
                
                if error_count == 0:
                    output = f"No errors in last {LOG_TIME_WINDOW}"
                    passed = True
                    severity = "INFO"
                else:
                    output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                    passed = False
                    severity = "WARNING"
                
                tests.append(create_test_result(f"keycloak_db_logs_{pod_name}",
                                                f"Check database logs for {pod_name}",
                                                passed, output, severity))
    
    if not tests:
        tests.append(create_test_result("keycloak_logs", "Check Keycloak logs",
                                         False, "Could not check logs", "WARNING"))
    
    return tests


def test_keycloak_services() -> List[Dict[str, Any]]:
    """Check Keycloak services status"""
    description = "Check Keycloak services configuration"
    tests = []
    
    # Check all services in namespace
    command = f"kubectl get svc -n {NAMESPACE} -o json"
    result = run_command(command)
    
    if ok(result) and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            services = data.get('items', [])
            
            expected_services = {
                'kc-server-service': False,
                'keycloak-operator-postgresql-db': False,
                'keycloak-operator': False
            }
            
            for svc in services:
                svc_name = svc['metadata']['name']
                if svc_name in expected_services:
                    expected_services[svc_name] = True
            
            missing_services = [name for name, found in expected_services.items() if not found]
            
            if not missing_services:
                output = f"All expected Keycloak services are present ({len(expected_services)} services)"
                tests.append(create_test_result("keycloak_services", description, True, output, "INFO"))
            else:
                output = f"Missing services: {', '.join(missing_services)}"
                tests.append(create_test_result("keycloak_services", description, False, output, "WARNING"))
        except json.JSONDecodeError:
            tests.append(create_test_result("keycloak_services", description, False,
                                             "Failed to parse services data", "WARNING"))
    else:
        tests.append(create_test_result("keycloak_services", description,
                                        False, f"Failed to get services: {result['stderr']}", "CRITICAL"))
    
    return tests


# ------------------------------------------------------------
# Main test runner
# ------------------------------------------------------------

def test_keycloak() -> List[Dict[str, Any]]:
    """Run all Keycloak health checks"""
    start_time = time.time()
    results = []
    
    # 1) Basic connectivity - gateway test
    connectivity_tests = test_keycloak_connectivity()
    results.extend(connectivity_tests)
    
    # 2) Health endpoints
    results.extend(test_keycloak_health())
    
    # 3) Infrastructure
    results.extend(test_keycloak_pods())
    results.extend(test_keycloak_services())
    
    # 4) Database
    results.extend(test_keycloak_database())
    
    # 5) Realms
    results.extend(test_keycloak_realms())
    
    # 6) Logs (always check)
    results.extend(test_keycloak_logs())
    
    # Add execution time
    execution_time = time.time() - start_time
    results.append(create_test_result(
        "execution_time",
        "Total execution time",
        True,
        f"{execution_time:.2f} seconds",
        "INFO"
    ))
    
    return results


def main():
    """Main entry point with JSON output"""
    try:
        results = test_keycloak()
        
        # Output as JSON
        print(json.dumps(results, indent=2))
        
        # Determine exit code based on severity
        critical_count = sum(1 for r in results if not r['status'] and r['severity'] == 'critical')
        warning_count = sum(1 for r in results if r['severity'] == 'warning')
        
        if critical_count > 0:
            sys.exit(1)
        elif warning_count > 0:
            sys.exit(0)
        else:
            sys.exit(0)
            
    except Exception as e:
        # Emergency fallback
        error_result = [{
            "name": "script_error",
            "description": "Script execution error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
