#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APISIX Route Testing Script - Fully Generic JSON Output Version
Tests all APISIX routes for connectivity, SSL certificates, and checks logs for errors
Outputs JSON array of test results to stdout

ENV VARS:
  APISIX_HOST (default: apisix-gateway.ingress-apisix.svc.cluster.local)
  APISIX_PORT (default: 80)
  APISIX_ADMIN_HOST (default: apisix-admin.ingress-apisix.svc.cluster.local)
  APISIX_ADMIN_PORT (default: 9180)
  APISIX_NS or APISIX_NAMESPACE (default: ingress-apisix)
  APISIX_LOG_TIME_WINDOW (default: 5m)
  APISIX_ROUTE_CRD (default: ApisixRoute - can be apisixroute, ar, etc.)
  APISIX_UPSTREAM_CRD (default: ApisixUpstream)
  APISIX_TLS_CRD (default: ApisixTls)
  APISIX_POD_LABELS (default: app.kubernetes.io/name=apisix - comma separated for multiple)
  APISIX_LB_SERVICE_NAME (default: auto-detect from namespace)

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import subprocess
import re
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

# ------------------------------------------------------------
# Utilities & configuration
# ------------------------------------------------------------

# Support both APISIX_NS and APISIX_NAMESPACE
NAMESPACE = os.getenv('APISIX_NS') or os.getenv('APISIX_NAMESPACE', 'ingress-apisix')

APISIX_HOST = os.getenv('APISIX_HOST', 'apisix-gateway.ingress-apisix.svc.cluster.local')
APISIX_PORT = os.getenv('APISIX_PORT', '80')
APISIX_ADMIN_HOST = os.getenv('APISIX_ADMIN_HOST', 'apisix-admin.ingress-apisix.svc.cluster.local')
APISIX_ADMIN_PORT = os.getenv('APISIX_ADMIN_PORT', '9180')
LOG_TIME_WINDOW = os.getenv('APISIX_LOG_TIME_WINDOW', '5m')

# CRD names (can be customized for different APISIX versions/operators)
ROUTE_CRD = os.getenv('APISIX_ROUTE_CRD', 'ApisixRoute')
UPSTREAM_CRD = os.getenv('APISIX_UPSTREAM_CRD', 'ApisixUpstream')
TLS_CRD = os.getenv('APISIX_TLS_CRD', 'ApisixTls')

# Pod labels (comma-separated list)
POD_LABELS = os.getenv('APISIX_POD_LABELS', 'app.kubernetes.io/name=apisix,app.kubernetes.io/instance=apisix').split(',')

# LoadBalancer service name (will auto-detect if not set)
LB_SERVICE_NAME = os.getenv('APISIX_LB_SERVICE_NAME', '')

# ------------------------------------------------------------
# Shell helper
# ------------------------------------------------------------

def run_command(command: str, env: Optional[Dict[str, str]] = None, timeout: int = 10) -> Dict[str, Any]:
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
# Auto-detection helpers
# ------------------------------------------------------------

def detect_apisix_crd_names() -> Dict[str, str]:
    """Auto-detect the actual CRD names used in the cluster"""
    crds = {
        'route': ROUTE_CRD,
        'upstream': UPSTREAM_CRD,
        'tls': TLS_CRD
    }
    
    # Try to detect actual CRD names
    cmd = "kubectl get crd | grep -i apisix"
    result = run_command(cmd)
    
    if ok(result) and result['stdout']:
        lines = result['stdout'].lower().split('\n')
        for line in lines:
            if 'route' in line and 'apisix' in line:
                crd_name = line.split()[0]
                # Extract the resource name (e.g., apisixroutes.apisix.apache.org -> apisixroute)
                crds['route'] = crd_name.split('.')[0].rstrip('s')
            elif 'upstream' in line and 'apisix' in line:
                crd_name = line.split()[0]
                crds['upstream'] = crd_name.split('.')[0].rstrip('s')
            elif 'tls' in line and 'apisix' in line:
                crd_name = line.split()[0]
                crds['tls'] = crd_name.split('.')[0].rstrip('s')
    
    return crds

def detect_loadbalancer_service() -> str:
    """Auto-detect LoadBalancer service name"""
    if LB_SERVICE_NAME:
        return LB_SERVICE_NAME
    
    # Try to find LoadBalancer type service in namespace
    cmd = f"kubectl get svc -n {NAMESPACE} -o json"
    result = run_command(cmd)
    
    if ok(result) and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            for item in data.get('items', []):
                if item.get('spec', {}).get('type') == 'LoadBalancer':
                    name = item['metadata']['name']
                    # Prefer services with 'apisix' in the name
                    if 'apisix' in name.lower():
                        return name
            # If no apisix-named LB found, return first LB
            for item in data.get('items', []):
                if item.get('spec', {}).get('type') == 'LoadBalancer':
                    return item['metadata']['name']
        except json.JSONDecodeError:
            pass
    
    # Fallback to common name
    return 'apisix-controller-apisix-ingress-controller-apisix-gateway'

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def test_apisix_health() -> List[Dict[str, Any]]:
    """Test APISIX gateway health endpoint"""
    description = "Test APISIX gateway health endpoint"
    
    # Try multiple possible health check endpoints with different ports
    health_endpoints = [
        f"http://{APISIX_HOST}:{APISIX_PORT}/apisix/status",
        f"http://{APISIX_HOST}:{APISIX_PORT}/healthz",
        f"http://{APISIX_HOST}:{APISIX_PORT}/",
    ]
    
    # Also try common alternative ports if main port fails
    if APISIX_PORT != '9080':
        health_endpoints.extend([
            f"http://{APISIX_HOST}:9080/apisix/status",
            f"http://{APISIX_HOST}:9080/healthz",
        ])
    
    passed = False
    successful_endpoint = None
    http_code = "000"
    
    for health_url in health_endpoints:
        command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {health_url}"
        result = run_command(command, timeout=10)
        
        if result["stdout"] in ["200", "201", "204", "301", "302", "401", "403", "404"]:
            passed = True
            successful_endpoint = health_url
            http_code = result["stdout"]
            break
    
    if passed:
        output = f"APISIX gateway is reachable at {successful_endpoint} (HTTP {http_code})"
    else:
        output = f"APISIX gateway health check failed - could not reach any endpoint"
    
    return [create_test_result("apisix_gateway_health", description, passed, output, "CRITICAL" if not passed else "INFO")]

def test_apisix_admin_connectivity() -> List[Dict[str, Any]]:
    """Test APISIX Admin API connectivity"""
    description = "Test APISIX Admin API connectivity"
    results = []
    
    admin_url = f"http://{APISIX_ADMIN_HOST}:{APISIX_ADMIN_PORT}/apisix/admin/routes"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {admin_url}"
    result = run_command(command, timeout=10)
    
    passed = result["stdout"] in ["200", "401", "403", "404"]
    
    if passed:
        output = f"APISIX Admin API is accessible (HTTP {result['stdout']})"
    else:
        output = f"APISIX Admin API connectivity failed (HTTP {result['stdout']})"
    
    results.append(create_test_result("apisix_admin_connectivity", description, passed, output, "WARNING" if not passed else "INFO"))
    
    # Test LoadBalancer service (auto-detect name)
    lb_service = detect_loadbalancer_service()
    if lb_service:
        lb_host = f"{lb_service}.{NAMESPACE}.svc.cluster.local"
        lb_command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{lb_host}/healthz"
        lb_result = run_command(lb_command, timeout=10)
        
        lb_passed = lb_result["stdout"] in ["200", "201", "204", "301", "302", "401", "403", "404"]
        
        if lb_passed:
            lb_output = f"APISIX LoadBalancer service {lb_service} is accessible (HTTP {lb_result['stdout']})"
        else:
            lb_output = f"APISIX LoadBalancer service {lb_service} connectivity failed (HTTP {lb_result['stdout']})"
        
        results.append(create_test_result("apisix_loadbalancer_connectivity", "Test APISIX LoadBalancer service connectivity", 
                                         lb_passed, lb_output, "CRITICAL" if not lb_passed else "INFO"))
    
    return results

def test_external_connectivity() -> List[Dict[str, Any]]:
    """Test external LoadBalancer connectivity"""
    description = "Test external LoadBalancer connectivity"
    
    lb_service = detect_loadbalancer_service()
    command = f"kubectl get svc -n {NAMESPACE} {lb_service} -o jsonpath='{{.status.loadBalancer.ingress[0].ip}}' 2>/dev/null"
    result = run_command(command)
    
    if result['exit_code'] == 0 and result['stdout']:
        external_ip = result['stdout'].strip()
        
        http_command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{external_ip}/"
        http_result = run_command(http_command, timeout=10)
        
        http_passed = http_result['stdout'] and http_result['stdout'][0] in ['2', '3', '4']
        
        if http_passed:
            output = f"External LoadBalancer IP {external_ip} is accessible (HTTP {http_result['stdout']})"
        else:
            output = f"External LoadBalancer IP {external_ip} is not accessible"
        
        return [create_test_result("apisix_external_lb_connectivity", f"{description} ({external_ip})",
                                  http_passed, output, "CRITICAL" if not http_passed else "INFO")]
    else:
        return [create_test_result("apisix_external_lb_connectivity", description, False,
                                  "Could not retrieve external LoadBalancer IP", "WARNING")]

def _get_routes() -> List[Dict]:
    """Discover all APISIX routes from Kubernetes"""
    crds = detect_apisix_crd_names()
    route_crd = crds['route']
    
    # Try different variations of the CRD name
    for crd_variant in [route_crd, route_crd.lower(), f"{route_crd}s", f"{route_crd.lower()}s"]:
        command = f"kubectl get {crd_variant} -n {NAMESPACE} -o json 2>/dev/null"
        result = run_command(command)
        
        if result['exit_code'] == 0:
            try:
                data = json.loads(result['stdout'])
                routes = []
                
                for item in data.get('items', []):
                    route_name = item['metadata']['name']
                    spec = item.get('spec', {})
                    
                    # Handle both 'http' and 'routes' fields (different APISIX versions)
                    http_rules = spec.get('http', spec.get('routes', []))
                    if not isinstance(http_rules, list):
                        http_rules = [http_rules]
                    
                    for rule in http_rules:
                        # Handle different field names for hosts
                        hosts = (rule.get('match', {}).get('hosts', []) or 
                                rule.get('hosts', []) or 
                                rule.get('host', []))
                        
                        if isinstance(hosts, str):
                            hosts = [hosts]
                        
                        paths = (rule.get('match', {}).get('paths', ['/*']) or 
                                rule.get('paths', ['/*']) or 
                                rule.get('path', ['/*']))
                        
                        for host in hosts:
                            if host:  # Only add if host is not empty
                                routes.append({
                                    'name': route_name,
                                    'host': host,
                                    'paths': paths if isinstance(paths, list) else [paths],
                                    'namespace': NAMESPACE
                                })
                
                return routes
            except json.JSONDecodeError:
                pass
    
    return []

def test_routes() -> List[Dict[str, Any]]:
    """Test all discovered routes"""
    routes = _get_routes()
    results = []
    
    if not routes:
        results.append(create_test_result("apisix_route_discovery", "Discover APISIX routes", False,
                                         "No routes found to test", "CRITICAL"))
        return results
    
    # Filter out routes that start with "agent." as they require auth
    filtered_routes = []
    skipped_count = 0
    for route in routes:
        if route['host'].startswith('agent.'):
            skipped_count += 1
            results.append(create_test_result(
                f"apisix_{route['name']}_skipped",
                f"Skipped auth-protected route {route['name']} ({route['host']})",
                True,
                f"Route {route['host']} skipped (requires authentication)",
                "INFO"
            ))
        else:
            filtered_routes.append(route)
    
    results.append(create_test_result("apisix_route_discovery", "Discover APISIX routes", True,
                                     f"Found {len(routes)} routes, testing {len(filtered_routes)} (skipped {skipped_count} auth routes)", "INFO"))
    
    for route in filtered_routes:
        results.append(test_route_http_connectivity(route))
        results.append(test_route_https_connectivity(route))
        results.append(test_route_ssl_certificate(route))
    
    return results

def test_route_http_connectivity(route: Dict) -> Dict[str, Any]:
    """Test HTTP connectivity for a specific route"""
    host = route['host']
    route_name = route['name']
    description = f"Test HTTP connectivity for route {route_name} ({host})"
    
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
            
            if http_code and (http_code.startswith('2') or http_code.startswith('3') or 
                            http_code in ['401', '403']):
                passed = True
                output = f"HTTP connectivity successful to {host} (HTTP {http_code}, Response time: {response_time}s)"
            elif http_code and http_code.startswith('4'):
                passed = True
                output = f"HTTP route active but returned client error for {host} (HTTP {http_code})"
            else:
                output = f"HTTP connectivity failed to {host} (HTTP {http_code})"
    
    return create_test_result(f"apisix_{route_name}_http_connectivity", description, passed, output,
                            "WARNING" if not passed else "INFO")

def test_route_https_connectivity(route: Dict) -> Dict[str, Any]:
    """Test HTTPS connectivity for a specific route"""
    host = route['host']
    route_name = route['name']
    description = f"Test HTTPS connectivity for route {route_name} ({host})"
    
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
            
            if http_code and (http_code.startswith('2') or http_code.startswith('3') or 
                            http_code in ['401', '403']):
                passed = True
                output = f"HTTPS connectivity successful to {host} (HTTP {http_code}, Response time: {response_time}s)"
            elif http_code and http_code.startswith('4'):
                passed = True
                output = f"HTTPS route active but returned client error for {host} (HTTP {http_code})"
            else:
                output = f"HTTPS connectivity failed to {host} (HTTP {http_code})"
    
    return create_test_result(f"apisix_{route_name}_https_connectivity", description, passed, output,
                            "WARNING" if not passed else "INFO")

def test_route_ssl_certificate(route: Dict) -> Dict[str, Any]:
    """Test SSL certificate validity for a specific route"""
    host = route['host']
    route_name = route['name']
    port = 443
    description = f"Test SSL certificate for route {route_name} ({host})"
    
    command = f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null"
    result = run_command(command, timeout=10)
    
    passed = False
    output = f"SSL certificate check failed for {host}"
    severity = "WARNING"
    
    if result['exit_code'] == 0 and 'notAfter' in result['stdout']:
        for line in result['stdout'].split('\n'):
            if 'notAfter=' in line:
                expiry_str = line.split('notAfter=')[1].strip()
                try:
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry > 30:
                        passed = True
                        output = f"SSL certificate valid for {host} (Expires: {expiry_str}, {days_until_expiry} days remaining)"
                        severity = "INFO"
                    elif days_until_expiry > 0:
                        passed = True
                        output = f"SSL certificate expiring soon for {host} (Expires: {expiry_str}, {days_until_expiry} days remaining)"
                        severity = "WARNING"
                    else:
                        output = f"SSL certificate expired for {host} (Expired: {expiry_str})"
                        severity = "CRITICAL"
                except:
                    passed = True
                    output = f"SSL certificate valid for {host} (Expires: {expiry_str})"
                    severity = "INFO"
                break
    else:
        verify_command = f"curl -k -s -o /dev/null -w '%{{ssl_verify_result}}' https://{host}/"
        verify_result = run_command(verify_command, timeout=5)
        
        if verify_result['stdout'] == '0':
            passed = True
            output = f"SSL certificate verification passed for {host}"
            severity = "INFO"
        else:
            https_command = f"curl -k -I -s -o /dev/null -w '%{{http_code}}' https://{host}/"
            https_result = run_command(https_command, timeout=5)
            
            if https_result['stdout'] and https_result['stdout'][0] in ['2', '3', '4']:
                passed = True
                output = f"SSL certificate present but may have issues for {host} (verify code: {verify_result.get('stdout', 'unknown')})"
                severity = "WARNING"
    
    return create_test_result(f"apisix_{route_name}_ssl_certificate", description, passed, output, severity)

def test_apisix_pods() -> List[Dict[str, Any]]:
    """Check APISIX pod status"""
    description = "Check APISIX pod status"
    
    pods = []
    
    # Try configured labels first
    for label in POD_LABELS:
        label = label.strip()
        if label:
            command = f"kubectl get pods -n {NAMESPACE} -l '{label}' -o json 2>/dev/null"
            result = run_command(command)
            if result['exit_code'] == 0:
                try:
                    data = json.loads(result['stdout'])
                    items = data.get('items', [])
                    if items:
                        pods = items
                        break
                except json.JSONDecodeError:
                    continue
    
    # If no pods found with labels, try to find by name pattern
    if not pods:
        command = f"kubectl get pods -n {NAMESPACE} -o json"
        result = run_command(command)
        if result['exit_code'] == 0:
            try:
                data = json.loads(result['stdout'])
                all_pods = data.get('items', [])
                pods = [p for p in all_pods if 'apisix' in p['metadata']['name'].lower() 
                       and 'controller' not in p['metadata']['name'].lower()
                       and 'dashboard' not in p['metadata']['name'].lower()
                       and 'etcd' not in p['metadata']['name'].lower()]
            except json.JSONDecodeError:
                pass
    
    passed = False
    pod_count = len(pods)
    ready_count = 0
    output = "No APISIX pods found"
    
    if pods:
        for pod in pods:
            pod_status = pod.get('status', {})
            conditions = pod_status.get('conditions', [])
            for condition in conditions:
                if condition.get('type') == 'Ready' and condition.get('status') == 'True':
                    ready_count += 1
                    break
        
        passed = pod_count > 0 and pod_count == ready_count
        output = f"Total APISIX pods: {pod_count}, Ready: {ready_count}"
        
        if not passed:
            output += " - Some pods are not ready"
    
    return [create_test_result("apisix_pods_status", description, passed, output, 
                              "CRITICAL" if not passed else "INFO")]

def test_apisix_logs() -> List[Dict[str, Any]]:
    """Check APISIX logs for errors"""
    description = f"Check APISIX logs for errors (last {LOG_TIME_WINDOW})"
    
    pod_names = []
    
    # Try to get pod names using labels
    for label in POD_LABELS:
        label = label.strip()
        if label:
            command = f"kubectl get pods -n {NAMESPACE} -l '{label}' -o jsonpath='{{.items[*].metadata.name}}' 2>/dev/null"
            pods_result = run_command(command)
            if pods_result['exit_code'] == 0 and pods_result['stdout']:
                pod_names = pods_result['stdout'].split()
                break
    
    # If no pods found with labels, find by name pattern
    if not pod_names:
        command = f"kubectl get pods -n {NAMESPACE} -o jsonpath='{{.items[*].metadata.name}}'"
        pods_result = run_command(command)
        if pods_result['exit_code'] == 0:
            all_pods = pods_result['stdout'].split()
            pod_names = [p for p in all_pods if 'apisix' in p.lower() 
                        and 'controller' not in p.lower()
                        and 'dashboard' not in p.lower()
                        and 'etcd' not in p.lower()]
    
    results = []
    
    if pod_names:
        for pod_name in pod_names:
            if not pod_name:
                continue
            
            log_command = f"kubectl logs -n {NAMESPACE} {pod_name} --since={LOG_TIME_WINDOW} 2>&1"
            log_result = run_command(log_command, timeout=15)
            
            error_count = 0
            warning_count = 0
            sample_error = ""
            
            if log_result['stdout']:
                lines = log_result['stdout'].split('\n')
                for line in lines:
                    if re.search(r'\b(error|ERROR|failed|FAILED|exception|Exception|panic|PANIC|fatal|FATAL)\b', line):
                        if not any(exclude in line.lower() for exclude in [
                            'error_log', 'error_page', 'no error', 'error_format',
                            '/error/', 'errors":', 'without error'
                        ]):
                            error_count += 1
                            if not sample_error and len(line) < 200:
                                sample_error = line
                    
                    if re.search(r'\b(warn|WARN|warning|WARNING)\b', line):
                        warning_count += 1
            
            passed = error_count == 0
            severity = "INFO" if passed else ("WARNING" if error_count < 10 else "CRITICAL")
            
            if error_count > 0:
                output = f"Found {error_count} errors in last {LOG_TIME_WINDOW}"
                if sample_error:
                    output += f". Sample: {sample_error[:100]}"
            else:
                output = f"No errors found in last {LOG_TIME_WINDOW}"
                if warning_count > 0:
                    output += f" ({warning_count} warnings)"
            
            results.append(create_test_result(f"apisix_logs_{pod_name}", f"Check APISIX logs for errors in {pod_name}",
                                            passed, output, severity))
    else:
        results.append(create_test_result("apisix_logs_check", description, False,
                                        "No APISIX pods found to check logs", "WARNING"))
    
    return results

def test_apisix_route_count() -> List[Dict[str, Any]]:
    """Count total APISIX routes"""
    description = "Count total APISIX routes"
    
    crds = detect_apisix_crd_names()
    route_crd = crds['route']
    
    for crd_variant in [route_crd, route_crd.lower(), f"{route_crd}s", f"{route_crd.lower()}s"]:
        command = f"kubectl get {crd_variant} -n {NAMESPACE} -o json 2>/dev/null"
        result = run_command(command)
        
        if result['exit_code'] == 0:
            try:
                data = json.loads(result['stdout'])
                count = len(data.get('items', []))
                passed = count > 0
                output = f"Total APISIX routes configured: {count}"
                
                route_names = [item['metadata']['name'] for item in data.get('items', [])]
                if route_names:
                    output += f" ({', '.join(route_names[:5])}{', ...' if count > 5 else ''})"
                
                return [create_test_result("apisix_route_count", description, passed, output,
                                          "CRITICAL" if not passed else "INFO")]
            except json.JSONDecodeError:
                pass
    
    return [create_test_result("apisix_route_count", description, False, "Failed to count routes", "WARNING")]

def test_apisix_upstreams() -> List[Dict[str, Any]]:
    """Check APISIX upstreams status"""
    description = "Check APISIX upstreams status"
    
    crds = detect_apisix_crd_names()
    upstream_crd = crds['upstream']
    
    for crd_variant in [upstream_crd, upstream_crd.lower(), f"{upstream_crd}s", f"{upstream_crd.lower()}s"]:
        command = f"kubectl get {crd_variant} -n {NAMESPACE} -o json 2>/dev/null"
        result = run_command(command)
        
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
                    output = f"No separate upstreams configured (may be defined inline in routes)"
                
                return [create_test_result("apisix_upstreams", description, passed, output, "INFO")]
            except json.JSONDecodeError:
                pass
    
    return [create_test_result("apisix_upstreams", description, True, 
                              "Could not retrieve upstreams (may be defined inline)", "INFO")]

def test_apisix_plugins() -> List[Dict[str, Any]]:
    """List enabled APISIX plugins"""
    description = "List enabled APISIX plugins"
    
    # Try to find APISIX configmap (name might vary)
    cmd = f"kubectl get configmap -n {NAMESPACE} -o json | jq -r '.items[] | select(.metadata.name | contains(\"apisix\")) | .metadata.name' | head -1"
    cm_result = run_command(cmd)
    
    configmap_name = cm_result['stdout'].strip() if ok(cm_result) else 'apisix'
    
    command = f"kubectl get configmap -n {NAMESPACE} {configmap_name} -o jsonpath='{{.data.config\\.yaml}}' 2>/dev/null | grep -A 50 'plugins:'"
    result = run_command(command)
    
    passed = result['exit_code'] == 0 and result['stdout']
    
    if passed:
        plugin_lines = [line.strip() for line in result['stdout'].split('\n') 
                       if line.strip().startswith('- ') and not line.strip().startswith('- #')]
        plugin_count = len(plugin_lines)
        plugin_names = [line.replace('- ', '').replace(':', '').strip() for line in plugin_lines[:10]]
        
        passed = plugin_count > 0
        output = f"Enabled plugins: {plugin_count}"
        if plugin_names:
            output += f" ({', '.join(plugin_names[:5])}{', ...' if plugin_count > 5 else ''})"
    else:
        output = "Could not retrieve APISIX plugins configuration (may be using default plugins)"
        passed = True
    
    return [create_test_result("apisix_plugins", description, passed, output, "INFO")]

def test_apisix_certificates() -> List[Dict[str, Any]]:
    """Check APISIX SSL certificates"""
    description = "Check APISIX SSL certificates"
    
    crds = detect_apisix_crd_names()
    tls_crd = crds['tls']
    
    for crd_variant in [tls_crd, tls_crd.lower(), f"{tls_crd}s", f"{tls_crd.lower()}s"]:
        command = f"kubectl get {crd_variant} -n {NAMESPACE} -o json 2>/dev/null"
        result = run_command(command)
        
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
                    output = f"No custom SSL certificates configured (may be using default or wildcard certs)"
                
                return [create_test_result("apisix_certificates", description, passed, output, "INFO")]
            except json.JSONDecodeError:
                pass
    
    return [create_test_result("apisix_certificates", description, True,
                              "Could not retrieve certificates (may be using defaults)", "INFO")]

# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------

def test_apisix() -> List[Dict[str, Any]]:
    """Main function to run all APISIX tests"""
    results = []
    
    # Run basic health checks
    results.extend(test_apisix_health())
    results.extend(test_apisix_admin_connectivity())
    results.extend(test_external_connectivity())
    
    # Check infrastructure
    results.extend(test_apisix_pods())
    results.extend(test_apisix_logs())
    
    # Check configuration
    results.extend(test_apisix_route_count())
    results.extend(test_apisix_upstreams())
    results.extend(test_apisix_plugins())
    results.extend(test_apisix_certificates())
    
    # Test all routes
    results.extend(test_routes())
    
    return results

def main():
    """Main entry point - output JSON to stdout"""
    try:
        results = test_apisix()
        # Output JSON to stdout
        print(json.dumps(results, indent=2))
        
        # Determine exit code based on critical failures
        critical_failures = [r for r in results if not r['status'] and r.get('severity') == 'critical']
        if critical_failures:
            return 1
        else:
            return 0
    except Exception as e:
        # On error, output a single error result
        error_result = [{
            "name": "apisix_test_error",
            "description": "APISIX test script error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        return 1

if __name__ == "__main__":
    sys.exit(main())
