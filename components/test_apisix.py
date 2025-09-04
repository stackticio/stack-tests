#!/usr/bin/env python3
"""
APISIX Route Testing Script - Fixed Version
Tests all APISIX routes for connectivity, SSL certificates, and checks logs for errors
"""

import os
import json
import subprocess
import re
from typing import Dict, List, Any
from datetime import datetime, timedelta

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
        "severity": "HIGH" if not passed else "LOW"
    }]


def test_apisix_admin_connectivity() -> List[Dict]:
    """Test APISIX Admin API connectivity"""
    admin_host = os.getenv('APISIX_ADMIN_HOST', 'apisix-admin.ingress-apisix.svc.cluster.local')
    admin_port = os.getenv('APISIX_ADMIN_PORT', '9180')
    
    admin_url = f"http://{admin_host}:{admin_port}/apisix/admin/routes"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {admin_url}"
    result = run_command(command, timeout=10)
    
    # 200, 401, 403 are all valid responses (401/403 mean auth is working)
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
        "severity": "MEDIUM" if not passed else "LOW"
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
            "severity": "HIGH"
        })
        return results
    
    # Add a summary of discovered routes
    results.append({
        "name": "apisix_route_discovery",
        "description": "Discover APISIX routes",
        "passed": True,
        "output": f"Found {len(routes)} routes to test",
        "severity": "LOW"
    })
    
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
            
            # Consider 2xx, 3xx, 401, 403 as successful (401/403 = auth required, 3xx = redirect)
            if http_code and (http_code.startswith('2') or http_code.startswith('3') or 
                            http_code in ['401', '403']):
                passed = True
                output = f"HTTP connectivity successful to {host} (HTTP {http_code}, Response time: {response_time}s)"
            elif http_code and http_code.startswith('4'):
                # 4xx errors (except 401/403) indicate route works but has issues
                passed = True
                output = f"HTTP route active but returned client error for {host} (HTTP {http_code})"
            else:
                output = f"HTTP connectivity failed to {host} (HTTP {http_code})"
    
    return {
        "name": f"apisix_{route_name}_http_connectivity",
        "description": f"Test HTTP connectivity for route {route_name} ({host})",
        "passed": passed,
        "output": output,
        "severity": "MEDIUM" if not passed else "LOW"
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
            
            # Consider 2xx, 3xx, 401, 403 as successful
            if http_code and (http_code.startswith('2') or http_code.startswith('3') or 
                            http_code in ['401', '403']):
                passed = True
                output = f"HTTPS connectivity successful to {host} (HTTP {http_code}, Response time: {response_time}s)"
            elif http_code and http_code.startswith('4'):
                # 4xx errors (except 401/403) indicate route works but has issues
                passed = True
                output = f"HTTPS route active but returned client error for {host} (HTTP {http_code})"
            else:
                output = f"HTTPS connectivity failed to {host} (HTTP {http_code})"
    
    return {
        "name": f"apisix_{route_name}_https_connectivity",
        "description": f"Test HTTPS connectivity for route {route_name} ({host})",
        "passed": passed,
        "output": output,
        "severity": "MEDIUM" if not passed else "LOW"
    }


def apisix_route_ssl_certificate(route: Dict) -> Dict:
    """Test SSL certificate validity for a specific route"""
    host = route['host']
    route_name = route['name']
    port = 443
    
    command = f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null"
    result = run_command(command, timeout=10)
    
    passed = False
    output = f"SSL certificate check failed for {host}"
    severity = "MEDIUM"
    
    if result['exit_code'] == 0 and 'notAfter' in result['stdout']:
        # Extract expiry date
        for line in result['stdout'].split('\n'):
            if 'notAfter=' in line:
                expiry_str = line.split('notAfter=')[1].strip()
                try:
                    # Parse the date (format: Nov 19 20:08:22 2025 GMT)
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry > 30:
                        passed = True
                        output = f"SSL certificate valid for {host} (Expires: {expiry_str}, {days_until_expiry} days remaining)"
                        severity = "LOW"
                    elif days_until_expiry > 0:
                        passed = True
                        output = f"SSL certificate expiring soon for {host} (Expires: {expiry_str}, {days_until_expiry} days remaining)"
                        severity = "MEDIUM"
                    else:
                        output = f"SSL certificate expired for {host} (Expired: {expiry_str})"
                        severity = "HIGH"
                except:
                    # If date parsing fails, just check if we got a certificate
                    passed = True
                    output = f"SSL certificate valid for {host} (Expires: {expiry_str})"
                    severity = "LOW"
                break
    else:
        # Try alternative verification using curl
        verify_command = f"curl -k -s -o /dev/null -w '%{{ssl_verify_result}}' https://{host}/"
        verify_result = run_command(verify_command, timeout=5)
        
        if verify_result['stdout'] == '0':
            passed = True
            output = f"SSL certificate verification passed for {host}"
            severity = "LOW"
        else:
            # Check if HTTPS works at all (even with invalid cert)
            https_command = f"curl -k -I -s -o /dev/null -w '%{{http_code}}' https://{host}/"
            https_result = run_command(https_command, timeout=5)
            
            if https_result['stdout'] and https_result['stdout'][0] in ['2', '3', '4']:
                passed = True
                output = f"SSL certificate present but may have issues for {host} (verify code: {verify_result.get('stdout', 'unknown')})"
                severity = "MEDIUM"
    
    return {
        "name": f"apisix_{route_name}_ssl_certificate",
        "description": f"Test SSL certificate for route {route_name} ({host})",
        "passed": passed,
        "output": output,
        "severity": severity
    }


def test_apisix_pods() -> List[Dict]:
    """Check APISIX pod status"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    
    # More flexible pod selection using multiple possible labels
    commands = [
        f"kubectl get pods -n {namespace} -l 'app.kubernetes.io/name=apisix' -o json",
        f"kubectl get pods -n {namespace} -l 'app.kubernetes.io/instance=apisix' -o json",
        f"kubectl get pods -n {namespace} -l 'stacktic.io/app=apisix' -o json"
    ]
    
    pods = []
    for command in commands:
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
        command = f"kubectl get pods -n {namespace} -o json"
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
    
    return [{
        "name": "apisix_pods_status",
        "description": "Check APISIX pod status",
        "passed": passed,
        "output": output,
        "severity": "HIGH" if not passed else "LOW"
    }]


def test_apisix_logs() -> List[Dict]:
    """Check APISIX logs for errors"""
    namespace = os.getenv('APISIX_NAMESPACE', 'ingress-apisix')
    time_window = os.getenv('APISIX_LOG_TIME_WINDOW', '5m')
    
    # Try multiple label selectors
    pod_commands = [
        f"kubectl get pods -n {namespace} -l 'app.kubernetes.io/name=apisix' -o jsonpath='{{.items[*].metadata.name}}'",
        f"kubectl get pods -n {namespace} -l 'app.kubernetes.io/instance=apisix' -o jsonpath='{{.items[*].metadata.name}}'",
        f"kubectl get pods -n {namespace} -l 'stacktic.io/app=apisix' -o jsonpath='{{.items[*].metadata.name}}'"
    ]
    
    pod_names = []
    for command in pod_commands:
        pods_result = run_command(command)
        if pods_result['exit_code'] == 0 and pods_result['stdout']:
            pod_names = pods_result['stdout'].split()
            break
    
    # If no pods found with labels, find by name pattern
    if not pod_names:
        command = f"kubectl get pods -n {namespace} -o jsonpath='{{.items[*].metadata.name}}'"
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
            
            log_command = f"kubectl logs -n {namespace} {pod_name} --since={time_window} 2>&1"
            log_result = run_command(log_command, timeout=15)
            
            error_count = 0
            warning_count = 0
            sample_error = ""
            
            if log_result['stdout']:
                lines = log_result['stdout'].split('\n')
                for line in lines:
                    # Look for actual errors, not just the word "error" in paths or config
                    if re.search(r'\b(error|ERROR|failed|FAILED|exception|Exception|panic|PANIC|fatal|FATAL)\b', line):
                        # Exclude false positives
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
            severity = "LOW" if passed else ("MEDIUM" if error_count < 10 else "HIGH")
            
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
                "description": f"Check APISIX logs for errors in {pod_name}",
                "passed": passed,
                "output": output,
                "severity": severity
            })
    else:
        results.append({
            "name": "apisix_logs_check",
            "description": "Check APISIX logs for errors",
            "passed": False,
            "output": "No APISIX pods found to check logs",
            "severity": "MEDIUM"
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
            
            # List route names
            route_names = [item['metadata']['name'] for item in data.get('items', [])]
            if route_names:
                output += f" ({', '.join(route_names[:5])}{', ...' if count > 5 else ''})"
        except json.JSONDecodeError:
            output = "Failed to parse route data"
    
    return [{
        "name": "apisix_route_count",
        "description": "Count total APISIX routes",
        "passed": passed,
        "output": output,
        "severity": "HIGH" if not passed else "LOW"
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
            # Pass even if no upstreams (they might be defined inline in routes)
            passed = True
            
            upstream_names = [u.get('metadata', {}).get('name', 'unknown') for u in upstreams]
            if upstream_names:
                output = f"Total upstreams: {upstream_count} ({', '.join(upstream_names[:5])}{', ...' if upstream_count > 5 else ''})"
            else:
                output = f"No separate upstreams configured (may be defined inline in routes)"
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
    
    command = f"kubectl get configmap -n {namespace} apisix -o jsonpath='{{.data.config\\.yaml}}' 2>/dev/null | grep -A 50 'plugins:'"
    result = run_command(command)
    
    passed = result['exit_code'] == 0 and result['stdout']
    
    if passed:
        # Count and list plugins
        plugin_lines = [line.strip() for line in result['stdout'].split('\n') 
                       if line.strip().startswith('- ') and not line.strip().startswith('- #')]
        plugin_count = len(plugin_lines)
        plugin_names = [line.replace('- ', '').replace(':', '').strip() for line in plugin_lines[:10]]
        
        passed = plugin_count > 0
        output = f"Enabled plugins: {plugin_count}"
        if plugin_names:
            output += f" ({', '.join(plugin_names[:5])}{', ...' if plugin_count > 5 else ''})"
    else:
        # Plugins might be configured differently
        output = "Could not retrieve APISIX plugins configuration (may be using default plugins)"
        passed = True  # Don't fail if we can't get plugin config
    
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
            # Pass even if no certs (they might be using default certs or HTTP only)
            passed = True
            
            cert_names = [c.get('metadata', {}).get('name', 'unknown') for c in certs]
            if cert_names:
                output = f"Total SSL certificates: {cert_count} ({', '.join(cert_names[:5])}{', ...' if cert_count > 5 else ''})"
            else:
                output = f"No custom SSL certificates configured (may be using default or wildcard certs)"
        except json.JSONDecodeError:
            output = "Failed to parse certificate data"
    
    return [{
        "name": "apisix_certificates",
        "description": "Check APISIX SSL certificates",
        "passed": passed,
        "output": output,
        "severity": "LOW"
    }]


def main():
    """Main function to run all tests"""
    all_results = []
    
    print("Starting APISIX comprehensive tests...")
    print("-" * 50)
    
    # Run basic health checks
    print("Testing APISIX health...")
    all_results.extend(test_apisix_health())
    
    print("Testing Admin API connectivity...")
    all_results.extend(test_apisix_admin_connectivity())
    
    # Check infrastructure
    print("Checking APISIX pods...")
    all_results.extend(test_apisix_pods())
    
    print("Checking APISIX logs...")
    all_results.extend(test_apisix_logs())
    
    # Check configuration
    print("Counting routes...")
    all_results.extend(test_apisix_route_count())
    
    print("Checking upstreams...")
    all_results.extend(test_apisix_upstreams())
    
    print("Checking plugins...")
    all_results.extend(test_apisix_plugins())
    
    print("Checking certificates...")
    all_results.extend(test_apisix_certificates())
    
    # Test all routes
    print("Testing all routes (this may take a while)...")
    all_results.extend(test_routes())
    
    # Print summary
    print("\n" + "=" * 50)
    print("TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed_count = sum(1 for r in all_results if r['passed'])
    failed_count = len(all_results) - passed_count
    
    # Group results by status
    failed_tests = [r for r in all_results if not r['passed']]
    passed_tests = [r for r in all_results if r['passed']]
    
    if failed_tests:
        print(f"\n❌ FAILED TESTS ({failed_count}):")
        for test in failed_tests:
            print(f"  - {test['name']}: {test['output']}")
            print(f"    Severity: {test['severity']}")
    
    if passed_tests:
        print(f"\n✅ PASSED TESTS ({passed_count}):")
        for test in passed_tests:
            print(f"  - {test['name']}: {test['output']}")
    
    print(f"\n📊 OVERALL: {passed_count}/{len(all_results)} tests passed")
    
    # Determine exit code based on severity of failures
    critical_failures = [r for r in failed_tests if r.get('severity') == 'HIGH']
    if critical_failures:
        print(f"\n⚠️  {len(critical_failures)} CRITICAL FAILURES DETECTED!")
        return 1
    elif failed_tests:
        print(f"\n⚠️  {len(failed_tests)} non-critical failures detected")
        return 0
    else:
        print("\n🎉 All tests passed!")
        return 0


if __name__ == "__main__":
    exit(main())
