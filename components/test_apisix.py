#!/usr/bin/env python3
"""
APISIX Route Testing Script
Tests all APISIX routes for connectivity, SSL certificates, and checks logs for errors
"""

import os
import json
import subprocess
import re
from typing import Dict, List, Any

def run_command(command: str, env: Dict = None, timeout: int = 10) -> Dict:
    """Helper to run a shell command and capture stdout/stderr/exit code"""
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
            "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "Timeout"}


def test_apisix_health() -> List[Dict]:
    """Test APISIX gateway health endpoint"""
    host = os.getenv('APISIX_HOST', 'apisix-gateway.ingress-apisix.svc.cluster.local')
    port = os.getenv('APISIX_PORT', '80')
    
    health_url = f"http://{host}:{port}/apisix/status"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {health_url}"
    result = run_command(command, timeout=10)
    
    passed = result["stdout"] == "200"
    
    if passed:
        output = f"APISIX gateway health check passed (HTTP {result['stdout']})"
    else:
        output = f"APISIX gateway health check failed (HTTP {result['stdout']})"
    
    return [{
        "name": "apisix_gateway_health",
        "description": "Test APISIX gateway health endpoint",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def test_apisix_admin_connectivity() -> List[Dict]:
    """Test APISIX Admin API connectivity"""
    admin_host = os.getenv('APISIX_ADMIN_HOST', 'apisix-admin.ingress-apisix.svc.cluster.local')
    admin_port = os.getenv('APISIX_ADMIN_PORT', '9180')
    
    admin_url = f"http://{admin_host}:{admin_port}/apisix/admin/routes"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {admin_url}"
    result = run_command(command, timeout=10)
    
    passed = result["stdout"] in ["200", "401", "403"]
    
    if passed:
        output = f"APISIX Admin API is accessible (HTTP {result['stdout']})"
    else:
        output = f"APISIX Admin API connectivity failed (HTTP {result['stdout']})"
    
    return [{
        "name": "apisix_admin_connectivity",
        "description": "Test APISIX Admin API connectivity",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def _get_routes() -> List[Dict]:
    """Discover all APISIX routes from Kubernetes"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    command = f"kubectl get ApisixRoute -n {namespace} -o json"
    result = run_command(command)
    
    routes = []
    
    if result['exit_code'] == 0:
        try:
            data = json.loads(result['stdout'])
            for item in data.get('items', []):
                route_name = item['metadata']['name']
                spec = item.get('spec', {})
                http_rules = spec.get('http', [])
                
                for rule in http_rules:
                    hosts = rule.get('match', {}).get('hosts', [])
                    paths = rule.get('match', {}).get('paths', ['/*'])
                    
                    for host in hosts:
                        routes.append({
                            'name': route_name,
                            'host': host,
                            'paths': paths,
                            'namespace': namespace
                        })
        except json.JSONDecodeError:
            pass
    
    return routes


def test_routes() -> List[Dict]:
    """Test all discovered routes"""
    routes = _get_routes()
    results = []
    
    if not routes:
        results.append({
            "name": "apisix_route_discovery",
            "description": "Discover APISIX routes",
            "passed": False,
            "output": "No routes found to test",
            "severity": "LOW"
        })
        return results
    
    for route in routes:
        results.append(apisix_route_http_connectivity(route))
        results.append(apisix_route_https_connectivity(route))
        results.append(apisix_route_ssl_certificate(route))
    
    return results


def apisix_route_http_connectivity(route: Dict) -> Dict:
    """Test HTTP connectivity for a specific route"""
    host = route['host']
    route_name = route['name']
    
    url = f"http://{host}/"
    command = f"curl -k -I -s -o /dev/null -w '%{{http_code}}:%{{time_total}}' --connect-timeout 5 {url}"
    result = run_command(command, timeout=10)
    
    passed = False
    output = f"No response from {url}"
    
    if result['stdout']:
        parts = result['stdout'].split(':')
        if len(parts) >= 1:
            http_code = parts[0]
            response_time = parts[1] if len(parts) > 1 else "N/A"
            
            if http_code and http_code[0] in ['2', '3', '4']:
                passed = True
                output = f"HTTP connectivity successful to {host} (HTTP {http_code}, Response time: {response_time}s)"
            else:
                output = f"HTTP connectivity failed to {host} (HTTP {http_code})"
    
    return {
        "name": f"apisix_{route_name}_http_connectivity",
        "description": f"Test HTTP connectivity for route {route_name} ({host})",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }


def apisix_route_https_connectivity(route: Dict) -> Dict:
    """Test HTTPS connectivity for a specific route"""
    host = route['host']
    route_name = route['name']
    
    url = f"https://{host}/"
    command = f"curl -k -I -s -o /dev/null -w '%{{http_code}}:%{{time_total}}' --connect-timeout 5 {url}"
    result = run_command(command, timeout=10)
    
    passed = False
    output = f"No response from {url}"
    
    if result['stdout']:
        parts = result['stdout'].split(':')
        if len(parts) >= 1:
            http_code = parts[0]
            response_time = parts[1] if len(parts) > 1 else "N/A"
            
            if http_code and http_code[0] in ['2', '3', '4']:
                passed = True
                output = f"HTTPS connectivity successful to {host} (HTTP {http_code}, Response time: {response_time}s)"
            else:
                output = f"HTTPS connectivity failed to {host} (HTTP {http_code})"
    
    return {
        "name": f"apisix_{route_name}_https_connectivity",
        "description": f"Test HTTPS connectivity for route {route_name} ({host})",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }


def apisix_route_ssl_certificate(route: Dict) -> Dict:
    """Test SSL certificate validity for a specific route"""
    host = route['host']
    route_name = route['name']
    port = 443
    
    command = f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null"
    result = run_command(command, timeout=10)
    
    passed = result['exit_code'] == 0 and 'notAfter' in result['stdout']
    
    if passed:
        # Extract expiry date
        for line in result['stdout'].split('\n'):
            if 'notAfter=' in line:
                expiry = line.split('notAfter=')[1].strip()
                output = f"SSL certificate valid for {host} (Expires: {expiry})"
                break
        else:
            output = f"SSL certificate valid for {host}"
    else:
        # Try alternative verification
        verify_command = f"curl -s -o /dev/null -w '%{{ssl_verify_result}}' https://{host}/"
        verify_result = run_command(verify_command, timeout=5)
        
        if verify_result['stdout'] == '0':
            passed = True
            output = f"SSL certificate verification passed for {host}"
        else:
            output = f"SSL certificate verification failed for {host} (code: {verify_result.get('stdout', 'unknown')})"
    
    return {
        "name": f"apisix_{route_name}_ssl_certificate",
        "description": f"Test SSL certificate for route {route_name} ({host})",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }


def test_apisix_pods() -> List[Dict]:
    """Check APISIX pod status"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    
    command = f"kubectl get pods -n {namespace} -l 'app.kubernetes.io/name=apisix' -o json"
    result = run_command(command)
    
    passed = False
    pod_count = 0
    ready_count = 0
    output = "Failed to get pod status"
    
    if result['exit_code'] == 0:
        try:
            data = json.loads(result['stdout'])
            pods = data.get('items', [])
            pod_count = len(pods)
            
            for pod in pods:
                pod_status = pod.get('status', {})
                conditions = pod_status.get('conditions', [])
                for condition in conditions:
                    if condition.get('type') == 'Ready' and condition.get('status') == 'True':
                        ready_count += 1
                        break
            
            passed = pod_count > 0 and pod_count == ready_count
            output = f"Total pods: {pod_count}, Ready: {ready_count}"
            
            if not passed:
                output += " - Some pods are not ready"
        except json.JSONDecodeError:
            output = "Failed to parse pod data"
    
    return [{
        "name": "apisix_pods_status",
        "description": "Check APISIX pod status",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def test_apisix_logs() -> List[Dict]:
    """Check APISIX logs for errors"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    time_window = os.getenv('APISIX_LOG_TIME_WINDOW', '5m')
    
    get_pods_command = f"kubectl get pods -n {namespace} -l 'app.kubernetes.io/name=apisix' -o jsonpath='{{.items[*].metadata.name}}'"
    pods_result = run_command(get_pods_command)
    
    results = []
    
    if pods_result['exit_code'] == 0:
        pod_names = pods_result['stdout'].split()
        
        for pod_name in pod_names:
            if not pod_name:
                continue
            
            log_command = f"kubectl logs -n {namespace} {pod_name} --since={time_window} 2>&1"
            log_result = run_command(log_command, timeout=15)
            
            error_count = 0
            warning_count = 0
            sample_error = ""
            
            if log_result['stdout']:
                lines = log_result['stdout'].split('\n')
                for line in lines:
                    if re.search(r'error|ERROR|failed|FAILED|exception|Exception|panic|PANIC|fatal|FATAL', line, re.IGNORECASE):
                        if not any(exclude in line.lower() for exclude in ['error_log', 'error_page', 'no error']):
                            error_count += 1
                            if not sample_error and len(line) < 200:
                                sample_error = line
                    
                    if re.search(r'warn|WARN|warning|WARNING', line, re.IGNORECASE):
                        warning_count += 1
            
            passed = error_count == 0
            
            if error_count > 0:
                output = f"Found {error_count} errors in last {time_window}"
                if sample_error:
                    output += f". Sample: {sample_error[:100]}"
            else:
                output = f"No errors found in last {time_window}"
                if warning_count > 0:
                    output += f" ({warning_count} warnings)"
            
            results.append({
                "name": f"apisix_logs_{pod_name}",
                "description": "Check APISIX logs for errors",
                "passed": passed,
                "output": output,
                "severity": "LOW"
            })
    else:
        results.append({
            "name": "apisix_logs_check",
            "description": "Check APISIX logs for errors",
            "passed": False,
            "output": "Failed to get APISIX pods",
            "severity": "LOW"
        })
    
    return results


def test_apisix_route_count() -> List[Dict]:
    """Count total APISIX routes"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    
    command = f"kubectl get ApisixRoute -n {namespace} -o json"
    result = run_command(command)
    
    passed = False
    output = "Failed to count routes"
    
    if result['exit_code'] == 0:
        try:
            data = json.loads(result['stdout'])
            count = len(data.get('items', []))
            passed = count > 0
            output = f"Total APISIX routes configured: {count}"
        except json.JSONDecodeError:
            output = "Failed to parse route data"
    
    return [{
        "name": "apisix_route_count",
        "description": "Count total APISIX routes",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def test_apisix_upstreams() -> List[Dict]:
    """Check APISIX upstreams status"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    
    command = f"kubectl get ApisixUpstream -n {namespace} -o json"
    result = run_command(command)
    
    passed = False
    output = "Failed to get upstreams"
    
    if result['exit_code'] == 0:
        try:
            data = json.loads(result['stdout'])
            upstreams = data.get('items', [])
            upstream_count = len(upstreams)
            passed = True
            
            upstream_names = [u.get('metadata', {}).get('name', 'unknown') for u in upstreams]
            if upstream_names:
                output = f"Total upstreams: {upstream_count} ({', '.join(upstream_names[:5])}{', ...' if upstream_count > 5 else ''})"
            else:
                output = f"Total upstreams: {upstream_count}"
        except json.JSONDecodeError:
            output = "Failed to parse upstream data"
    
    return [{
        "name": "apisix_upstreams",
        "description": "Check APISIX upstreams status",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def test_apisix_plugins() -> List[Dict]:
    """List enabled APISIX plugins"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    
    command = f"kubectl get configmap -n {namespace} apisix -o jsonpath='{{.data.config\\.yaml}}' | grep -A 50 'plugins:'"
    result = run_command(command)
    
    passed = result['exit_code'] == 0 and 'plugins:' in result['stdout']
    
    if passed:
        # Count and list plugins
        plugin_lines = [line.strip() for line in result['stdout'].split('\n') if line.strip().startswith('- ')]
        plugin_count = len(plugin_lines)
        plugin_names = [line.replace('- ', '').replace(':', '') for line in plugin_lines[:10]]
        
        output = f"Enabled plugins: {plugin_count}"
        if plugin_names:
            output += f" ({', '.join(plugin_names[:5])}{', ...' if plugin_count > 5 else ''})"
    else:
        output = "Failed to retrieve APISIX plugins configuration"
    
    return [{
        "name": "apisix_plugins",
        "description": "List enabled APISIX plugins",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def test_apisix_certificates() -> List[Dict]:
    """Check APISIX SSL certificates"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    
    command = f"kubectl get ApisixTls -n {namespace} -o json"
    result = run_command(command)
    
    passed = False
    output = "Failed to get SSL certificates"
    
    if result['exit_code'] == 0:
        try:
            data = json.loads(result['stdout'])
            certs = data.get('items', [])
            cert_count = len(certs)
            passed = True
            
            cert_names = [c.get('metadata', {}).get('name', 'unknown') for c in certs]
            if cert_names:
                output = f"Total SSL certificates: {cert_count} ({', '.join(cert_names[:5])}{', ...' if cert_count > 5 else ''})"
            else:
                output = f"Total SSL certificates: {cert_count}"
        except json.JSONDecodeError:
            output = "Failed to parse certificate data"
    
    return [{
        "name": "apisix_certificates",
        "description": "Check APISIX SSL certificates",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]
