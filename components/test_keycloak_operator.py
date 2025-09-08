#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Keycloak Health Testing Script
Tests Keycloak health and outputs JSON results

ENV VARS from your environment:
  KEYCLOAK_OPERATOR_HOST (default: keycloak-operator.keycloak.svc.cluster.local)
  KEYCLOAK_OPERATOR_NS (default: keycloak)
  KEYCLOAK_OPERATOR_PORT (default: 8080)
  KEYCLOAK_OPERATOR_ADMIN_PASSWORD (default: password_default1)
  KEYCLOAK_OPERATOR_REALM (default: my-realm)
"""

import os
import json
import subprocess
import re
import sys
from typing import Dict, List, Any

# Use YOUR ACTUAL ENV variables
NAMESPACE = os.getenv('KEYCLOAK_OPERATOR_NS', 'keycloak')
KEYCLOAK_OPERATOR_HOST = os.getenv('KEYCLOAK_OPERATOR_HOST', 'keycloak-operator.keycloak.svc.cluster.local')
KEYCLOAK_OPERATOR_PORT = os.getenv('KEYCLOAK_OPERATOR_PORT', '8080')
KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_OPERATOR_ADMIN_PASSWORD', 'password_default1')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_OPERATOR_REALM', 'my-realm')
LOG_TIME_WINDOW = os.getenv('KEYCLOAK_LOG_TIME_WINDOW', '5m')

# Actual service names from your cluster
KEYCLOAK_SERVICE_HOST = f"kc-server-service.{NAMESPACE}.svc.cluster.local"
KEYCLOAK_DB_HOST = f"keycloak-operator-postgresql-db.{NAMESPACE}.svc.cluster.local"

def run_command(command: str, timeout: int = 10) -> Dict[str, Any]:
    """Run a shell command and capture output"""
    try:
        completed = subprocess.run(
            command,
            shell=True,
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

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "info") -> Dict[str, Any]:
    """Create a standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }

def test_keycloak_connectivity() -> List[Dict[str, Any]]:
    """Test Keycloak API connectivity"""
    description = "Test Keycloak API connectivity"
    
    # Test the main Keycloak service (port 8080)
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/health"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 300:
            output = f"Keycloak API is accessible (HTTP {http_code})"
            return [create_test_result("keycloak_api_connectivity", description, True, output, "info")]
        elif code == 404:
            # Try alternate health endpoint
            url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/health/ready"
            command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
            result = run_command(command)
            http_code = result['stdout'].strip()
            if http_code and http_code.isdigit() and 200 <= int(http_code) < 300:
                output = f"Keycloak API is accessible via /health/ready (HTTP {http_code})"
                return [create_test_result("keycloak_api_connectivity", description, True, output, "info")]
    
    # If health endpoints fail, try the root endpoint
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 500:
            output = f"Keycloak service is responding (HTTP {http_code})"
            return [create_test_result("keycloak_api_connectivity", description, True, output, "info")]
    
    output = f"Keycloak API connectivity failed (HTTP {http_code if http_code else 'no response'})"
    return [create_test_result("keycloak_api_connectivity", description, False, output, "critical")]

def test_keycloak_health() -> List[Dict[str, Any]]:
    """Test Keycloak health endpoints"""
    description = "Test Keycloak health status"
    results = []
    
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
                results.append(create_test_result("keycloak_readiness", "Check Keycloak readiness", 
                                                 True, output, "info"))
            else:
                output = f"Keycloak readiness check failed (status: {status})"
                results.append(create_test_result("keycloak_readiness", "Check Keycloak readiness",
                                                 False, output, "warning"))
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
                results.append(create_test_result("keycloak_liveness", "Check Keycloak liveness",
                                                 True, output, "info"))
            else:
                output = f"Keycloak liveness check failed (status: {status})"
                results.append(create_test_result("keycloak_liveness", "Check Keycloak liveness",
                                                 False, output, "critical"))
        except json.JSONDecodeError:
            pass
    
    if not results:
        # Fallback to HTTP status check
        url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/"
        command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
        result = run_command(command)
        http_code = result['stdout'].strip()
        
        if http_code and http_code.isdigit() and 200 <= int(http_code) < 400:
            output = f"Keycloak is responding (HTTP {http_code})"
            results.append(create_test_result("keycloak_health", description, True, output, "info"))
        else:
            output = f"Keycloak health check failed (HTTP {http_code if http_code else 'no response'})"
            results.append(create_test_result("keycloak_health", description, False, output, "critical"))
    
    return results

def test_keycloak_pods() -> List[Dict[str, Any]]:
    """Check Keycloak pod status"""
    results = []
    
    # Check Keycloak server pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=keycloak' -o json"
    result = run_command(command)
    
    if result['exit_code'] == 0 and result['stdout']:
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
                severity = "info"
                passed = True
            elif ready_pods > 0:
                output = f"Keycloak server pods: {ready_pods}/{total_pods} ready"
                if not_ready:
                    output += f" (Not ready: {', '.join(not_ready)})"
                severity = "warning"
                passed = False
            else:
                output = f"No Keycloak server pods are ready ({total_pods} total)"
                severity = "critical"
                passed = False
            
            results.append(create_test_result("keycloak_server_pods", "Check Keycloak server pods",
                                             passed, output, severity))
        except json.JSONDecodeError:
            results.append(create_test_result("keycloak_server_pods", "Check Keycloak server pods",
                                             False, "Failed to parse pod data", "warning"))
    
    # Check PostgreSQL pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=postgresql-db' -o json"
    result = run_command(command)
    
    if result['exit_code'] == 0 and result['stdout']:
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
                severity = "info"
            else:
                output = f"PostgreSQL pods: {ready_pods}/{total_pods} ready"
                passed = False
                severity = "warning"
            
            results.append(create_test_result("keycloak_db_pods", "Check Keycloak database pods",
                                             passed, output, severity))
        except json.JSONDecodeError:
            pass
    
    # Check Operator pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=keycloak' -o json"
    result = run_command(command)
    
    if result['exit_code'] == 0 and result['stdout']:
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
                severity = "info" if passed else "warning"
                results.append(create_test_result("keycloak_operator_pods", "Check Keycloak operator pods",
                                                 passed, output, severity))
        except json.JSONDecodeError:
            pass
    
    return results

def test_keycloak_database() -> List[Dict[str, Any]]:
    """Test PostgreSQL database connectivity"""
    description = "Test Keycloak database connectivity"
    
    # Test database port connectivity
    command = f"timeout 2 bash -c 'cat < /dev/null > /dev/tcp/{KEYCLOAK_DB_HOST}/5432' 2>/dev/null && echo 'success' || echo 'failed'"
    result = run_command(command)
    
    if result['stdout'] == 'success':
        output = "PostgreSQL database is accessible on port 5432"
        return [create_test_result("keycloak_database", description, True, output, "info")]
    else:
        output = "PostgreSQL database connection failed on port 5432"
        return [create_test_result("keycloak_database", description, False, output, "critical")]

def test_keycloak_realms() -> List[Dict[str, Any]]:
    """Test Keycloak realms endpoint"""
    description = "Test Keycloak realms availability"
    
    # Test if we can access the realms endpoint
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/realms/{KEYCLOAK_REALM}"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 300:
            output = f"Realm '{KEYCLOAK_REALM}' is accessible (HTTP {http_code})"
            return [create_test_result("keycloak_realm", description, True, output, "info")]
        elif code == 404:
            output = f"Realm '{KEYCLOAK_REALM}' not found (HTTP 404) - may need to be created"
            return [create_test_result("keycloak_realm", description, False, output, "warning")]
    
    # Try master realm as fallback
    url = f"http://{KEYCLOAK_SERVICE_HOST}:8080/realms/master"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit() and 200 <= int(http_code) < 300:
        output = f"Master realm is accessible but '{KEYCLOAK_REALM}' is not configured"
        return [create_test_result("keycloak_realm", description, False, output, "warning")]
    
    output = "Keycloak realms endpoint is not accessible"
    return [create_test_result("keycloak_realm", description, False, output, "critical")]

def test_keycloak_logs() -> List[Dict[str, Any]]:
    """Check Keycloak logs for errors"""
    results = []
    
    # Get Keycloak server pod names
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=keycloak' -o jsonpath='{{.items[*].metadata.name}}'"
    pod_result = run_command(command)
    
    if pod_result['exit_code'] == 0 and pod_result['stdout']:
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
                    severity = "info"
                elif error_count < 10:
                    output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                    passed = False
                    severity = "warning"
                else:
                    output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                    passed = False
                    severity = "critical"
                
                results.append(create_test_result(f"keycloak_logs_{pod_name}",
                                                f"Check logs for {pod_name}",
                                                passed, output, severity))
    
    # Check database logs
    command = f"kubectl get pods -n {NAMESPACE} -l 'app=postgresql-db' -o jsonpath='{{.items[*].metadata.name}}'"
    pod_result = run_command(command)
    
    if pod_result['exit_code'] == 0 and pod_result['stdout']:
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
                    severity = "info"
                else:
                    output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                    passed = False
                    severity = "warning"
                
                results.append(create_test_result(f"keycloak_db_logs_{pod_name}",
                                                f"Check database logs for {pod_name}",
                                                passed, output, severity))
    
    if not results:
        results.append(create_test_result("keycloak_logs", "Check Keycloak logs",
                                         False, "Could not check logs", "warning"))
    
    return results

def test_keycloak_services() -> List[Dict[str, Any]]:
    """Check Keycloak services status"""
    description = "Check Keycloak services"
    results = []
    
    # Check all services in namespace
    command = f"kubectl get svc -n {NAMESPACE} -o json"
    result = run_command(command)
    
    if result['exit_code'] == 0 and result['stdout']:
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
                results.append(create_test_result("keycloak_services", description, True, output, "info"))
            else:
                output = f"Missing services: {', '.join(missing_services)}"
                results.append(create_test_result("keycloak_services", description, False, output, "warning"))
        except json.JSONDecodeError:
            results.append(create_test_result("keycloak_services", description, False,
                                             "Failed to parse services data", "warning"))
    
    return results

def test_keycloak() -> List[Dict[str, Any]]:
    """Run all Keycloak tests"""
    results = []
    
    # Basic connectivity
    results.extend(test_keycloak_connectivity())
    results.extend(test_keycloak_health())
    
    # Infrastructure
    results.extend(test_keycloak_pods())
    results.extend(test_keycloak_services())
    
    # Database
    results.extend(test_keycloak_database())
    
    # Realms
    results.extend(test_keycloak_realms())
    
    # Logs
    results.extend(test_keycloak_logs())
    
    return results

def main():
    """Main entry point"""
    try:
        results = test_keycloak()
        print(json.dumps(results, indent=2))
        
        # Exit with error if any critical failures
        critical_failures = [r for r in results if not r['status'] and r.get('severity') == 'critical']
        return 1 if critical_failures else 0
    except Exception as e:
        error_result = [{
            "name": "keycloak_test_error",
            "description": "Keycloak test script error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        return 1

if __name__ == "__main__":
    sys.exit(main())
