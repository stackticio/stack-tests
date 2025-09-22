#!/usr/bin/env python3
"""
Istio Service Mesh Test Script
- Tests Istio control plane health, data plane status, configuration, and traffic management
- Designed to be completely generic and environment-agnostic
- Auto-discovers Istio configuration from the cluster

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import subprocess
import sys
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# ------------------------------------------------------------
# Utilities & helpers
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
    """Check if command executed successfully."""
    return proc.get("exit_code", 1) == 0

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized test result."""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }

def detect_istio_namespace() -> str:
    """Auto-detect Istio namespace."""
    # Try common Istio namespaces
    namespaces = ["istio-system", "istio", "service-mesh"]
    
    for ns in namespaces:
        cmd = f"kubectl get namespace {ns} -o name 2>/dev/null"
        r = run_command(cmd, timeout=5)
        if ok(r):
            return ns
    
    # Try to find namespace with istiod deployment
    cmd = "kubectl get deployments --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.metadata.name==\"istiod\") | .metadata.namespace' | head -1"
    r = run_command(cmd, timeout=10)
    if ok(r) and r['stdout']:
        return r['stdout']
    
    return "istio-system"  # Default fallback

# Global variable for Istio namespace (will be set dynamically)
ISTIO_NAMESPACE = ""

# ------------------------------------------------------------
# Core Istio Tests
# ------------------------------------------------------------

def check_istio_version() -> List[Dict[str, Any]]:
    """Check Istio version and compatibility."""
    description = "Check Istio version and client/server compatibility"
    
    cmd = "istioctl version --short 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        version_info = r['stdout']
        # Parse client and control plane versions
        client_version = ""
        control_version = ""
        
        for line in version_info.split('\n'):
            if 'client' in line.lower():
                client_version = line.split(':')[-1].strip() if ':' in line else line
            elif 'control' in line.lower() or 'pilot' in line.lower():
                control_version = line.split(':')[-1].strip() if ':' in line else line
        
        if not control_version and not client_version:
            # Fallback parsing for different formats
            client_version = version_info.split('\n')[0] if version_info else "unknown"
        
        output = f"Istio version info:\n  Client: {client_version or 'detected'}"
        if control_version:
            output += f"\n  Control Plane: {control_version}"
        
        return [create_test_result("istio_version", description, True, output, "INFO")]
    else:
        return [create_test_result("istio_version", description, False, 
                                  f"Failed to get Istio version: {r['stderr'] or 'istioctl not found'}", "WARNING")]

def check_control_plane_health() -> List[Dict[str, Any]]:
    """Check Istio control plane components health."""
    description = "Check health of Istio control plane components"
    tests: List[Dict[str, Any]] = []
    
    # Check istiod deployment
    cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} istiod -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        try:
            deployment = json.loads(r['stdout'])
            replicas = deployment.get('spec', {}).get('replicas', 0)
            ready = deployment.get('status', {}).get('readyReplicas', 0)
            
            tests.append(create_test_result(
                "istiod_deployment",
                description,
                replicas == ready and ready > 0,
                f"Istiod: {ready}/{replicas} replicas ready",
                "CRITICAL" if ready == 0 else ("WARNING" if ready < replicas else "INFO")
            ))
        except json.JSONDecodeError:
            tests.append(create_test_result("istiod_deployment", description, False, 
                                          "Failed to parse istiod deployment status", "WARNING"))
    else:
        tests.append(create_test_result("istiod_deployment", description, False,
                                       "Istiod deployment not found", "CRITICAL"))
    
    # Check other control plane components
    components = ["istio-ingressgateway", "istio-egressgateway"]
    for component in components:
        cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} {component} -o json 2>/dev/null"
        r = run_command(cmd, timeout=10)
        
        if ok(r) and r['stdout']:
            try:
                deployment = json.loads(r['stdout'])
                replicas = deployment.get('spec', {}).get('replicas', 0)
                ready = deployment.get('status', {}).get('readyReplicas', 0)
                
                tests.append(create_test_result(
                    f"{component}_deployment",
                    f"Check {component} deployment",
                    replicas == ready,
                    f"{component}: {ready}/{replicas} replicas ready",
                    "WARNING" if ready < replicas else "INFO"
                ))
            except json.JSONDecodeError:
                pass  # Component might not exist, which is okay
    
    # Check control plane pods
    cmd = f"kubectl get pods -n {ISTIO_NAMESPACE} -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        try:
            pods = json.loads(r['stdout'])
            control_plane_pods = []
            unhealthy_pods = []
            
            for pod in pods.get('items', []):
                pod_name = pod.get('metadata', {}).get('name', '')
                if any(cp in pod_name for cp in ['istiod', 'pilot', 'galley', 'citadel', 'ingressgateway', 'egressgateway']):
                    control_plane_pods.append(pod_name)
                    
                    # Check if pod is ready
                    containers = pod.get('status', {}).get('containerStatuses', [])
                    if not all(c.get('ready', False) for c in containers):
                        unhealthy_pods.append(pod_name)
            
            tests.append(create_test_result(
                "control_plane_pods",
                "Check control plane pod health",
                len(unhealthy_pods) == 0,
                f"Control plane pods: {len(control_plane_pods)} total, {len(unhealthy_pods)} unhealthy",
                "WARNING" if unhealthy_pods else "INFO"
            ))
        except json.JSONDecodeError:
            pass
    
    return tests

def check_data_plane_status() -> List[Dict[str, Any]]:
    """Check Istio data plane (Envoy sidecars) status."""
    description = "Check data plane proxy status"
    tests: List[Dict[str, Any]] = []
    
    # Use istioctl proxy-status to check all Envoy proxies
    cmd = "istioctl proxy-status 2>&1"
    r = run_command(cmd, timeout=20)
    
    if ok(r) and r['stdout']:
        lines = r['stdout'].split('\n')
        total_proxies = 0
        synced_proxies = 0
        stale_proxies = 0
        not_sent_proxies = 0
        
        for line in lines[1:]:  # Skip header
            if line.strip() and not line.startswith('NAME'):
                parts = line.split()
                if len(parts) >= 3:
                    total_proxies += 1
                    status = ' '.join(parts[2:])
                    
                    if 'SYNCED' in status:
                        synced_proxies += 1
                    elif 'STALE' in status:
                        stale_proxies += 1
                    elif 'NOT SENT' in status:
                        not_sent_proxies += 1
        
        output = f"Envoy proxy status:\n"
        output += f"  Total: {total_proxies}\n"
        output += f"  Synced: {synced_proxies}\n"
        if stale_proxies > 0:
            output += f"  Stale: {stale_proxies}\n"
        if not_sent_proxies > 0:
            output += f"  Not Sent: {not_sent_proxies}"
        
        all_synced = (synced_proxies == total_proxies) and total_proxies > 0
        tests.append(create_test_result(
            "envoy_proxy_status",
            description,
            all_synced,
            output,
            "WARNING" if stale_proxies > 0 or not_sent_proxies > 0 else "INFO"
        ))
    else:
        tests.append(create_test_result(
            "envoy_proxy_status",
            description,
            False,
            f"Failed to get proxy status: {r['stderr'] or 'No proxies found'}",
            "WARNING"
        ))
    
    # Check for proxy readiness
    cmd = "istioctl proxy-status --short 2>&1 | grep -c 'SYNCED'"
    r = run_command(cmd, timeout=10)
    if ok(r) and r['stdout'].isdigit():
        synced_count = int(r['stdout'])
        tests.append(create_test_result(
            "proxy_readiness",
            "Check proxy configuration sync",
            synced_count > 0,
            f"{synced_count} proxies with synced configuration",
            "INFO"
        ))
    
    return tests

def check_istio_configuration() -> List[Dict[str, Any]]:
    """Validate Istio configuration for errors."""
    description = "Validate Istio configuration"
    tests: List[Dict[str, Any]] = []
    
    # Analyze configuration
    cmd = "istioctl analyze --all-namespaces 2>&1"
    r = run_command(cmd, timeout=30)
    
    if ok(r):
        output_lines = r['stdout'].split('\n') if r['stdout'] else []
        errors = []
        warnings = []
        info = []
        
        for line in output_lines:
            if 'Error' in line or 'ERROR' in line:
                errors.append(line[:200])  # Truncate long lines
            elif 'Warning' in line or 'WARN' in line:
                warnings.append(line[:200])
            elif 'Info' in line or 'INFO' in line:
                info.append(line[:200])
        
        if 'No validation issues found' in r['stdout']:
            tests.append(create_test_result(
                "config_validation",
                description,
                True,
                "No configuration issues found",
                "INFO"
            ))
        else:
            output = f"Configuration analysis:\n"
            if errors:
                output += f"  Errors: {len(errors)}\n"
                output += f"    Example: {errors[0]}\n" if errors else ""
            if warnings:
                output += f"  Warnings: {len(warnings)}\n"
                output += f"    Example: {warnings[0]}" if warnings else ""
            
            tests.append(create_test_result(
                "config_validation",
                description,
                len(errors) == 0,
                output,
                "CRITICAL" if errors else ("WARNING" if warnings else "INFO")
            ))
    else:
        tests.append(create_test_result(
            "config_validation",
            description,
            False,
            f"Configuration analysis failed: {r['stderr']}",
            "WARNING"
        ))
    
    return tests

def check_istio_injection() -> List[Dict[str, Any]]:
    """Check sidecar injection status."""
    description = "Check sidecar injection configuration"
    tests: List[Dict[str, Any]] = []
    
    # Check namespaces with injection enabled
    cmd = "kubectl get namespaces -l istio-injection=enabled -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    injection_enabled_namespaces = []
    if ok(r) and r['stdout']:
        try:
            namespaces = json.loads(r['stdout'])
            for ns in namespaces.get('items', []):
                injection_enabled_namespaces.append(ns.get('metadata', {}).get('name', ''))
        except json.JSONDecodeError:
            pass
    
    # Check namespaces with revision label
    cmd = "kubectl get namespaces -l istio.io/rev -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    revision_namespaces = []
    if ok(r) and r['stdout']:
        try:
            namespaces = json.loads(r['stdout'])
            for ns in namespaces.get('items', []):
                revision_namespaces.append(ns.get('metadata', {}).get('name', ''))
        except json.JSONDecodeError:
            pass
    
    all_injection_namespaces = list(set(injection_enabled_namespaces + revision_namespaces))
    
    if all_injection_namespaces:
        output = f"Sidecar injection enabled in {len(all_injection_namespaces)} namespace(s):\n"
        output += f"  Namespaces: {', '.join(all_injection_namespaces[:10])}"
        if len(all_injection_namespaces) > 10:
            output += f" (+{len(all_injection_namespaces)-10} more)"
        
        tests.append(create_test_result(
            "sidecar_injection",
            description,
            True,
            output,
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "sidecar_injection",
            description,
            False,
            "No namespaces found with sidecar injection enabled",
            "WARNING"
        ))
    
    # Check mutating webhook
    cmd = "kubectl get mutatingwebhookconfigurations -o json 2>/dev/null | jq '.items[] | select(.metadata.name | contains(\"istio\")) | .metadata.name' -r"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        webhooks = r['stdout'].split('\n')
        tests.append(create_test_result(
            "injection_webhook",
            "Check injection webhook",
            True,
            f"Injection webhook(s) found: {', '.join(webhooks[:3])}",
            "INFO"
        ))
    
    return tests

def check_istio_services() -> List[Dict[str, Any]]:
    """Check Istio services and virtual services."""
    description = "Check Istio services configuration"
    tests: List[Dict[str, Any]] = []
    
    # Count VirtualServices
    cmd = "kubectl get virtualservices --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    vs_count = 0
    if ok(r) and r['stdout'].isdigit():
        vs_count = int(r['stdout'])
    
    # Count DestinationRules
    cmd = "kubectl get destinationrules --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    dr_count = 0
    if ok(r) and r['stdout'].isdigit():
        dr_count = int(r['stdout'])
    
    # Count Gateways
    cmd = "kubectl get gateways --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    gw_count = 0
    if ok(r) and r['stdout'].isdigit():
        gw_count = int(r['stdout'])
    
    # Count ServiceEntries
    cmd = "kubectl get serviceentries --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    se_count = 0
    if ok(r) and r['stdout'].isdigit():
        se_count = int(r['stdout'])
    
    output = "Istio resources:\n"
    output += f"  VirtualServices: {vs_count}\n"
    output += f"  DestinationRules: {dr_count}\n"
    output += f"  Gateways: {gw_count}\n"
    output += f"  ServiceEntries: {se_count}"
    
    tests.append(create_test_result(
        "istio_resources",
        description,
        True,
        output,
        "INFO"
    ))
    
    return tests

def check_istio_certificates() -> List[Dict[str, Any]]:
    """Check Istio certificate status."""
    description = "Check Istio certificates and mTLS"
    tests: List[Dict[str, Any]] = []
    
    # Check root certificate
    cmd = f"kubectl get secret -n {ISTIO_NAMESPACE} istio-ca-secret -o json 2>/dev/null | jq -r '.data[\"ca-cert.pem\"]' | base64 -d | openssl x509 -noout -dates 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and 'notAfter' in r['stdout']:
        lines = r['stdout'].split('\n')
        expiry_info = ""
        for line in lines:
            if 'notAfter' in line:
                expiry_info = line.split('=')[1] if '=' in line else line
                break
        
        tests.append(create_test_result(
            "root_certificate",
            "Check root certificate",
            True,
            f"Root certificate valid until: {expiry_info}",
            "INFO"
        ))
    else:
        # Try alternative certificate location
        cmd = f"kubectl get secret -n {ISTIO_NAMESPACE} cacerts -o json 2>/dev/null | jq -r '.data[\"root-cert.pem\"]' | base64 -d | openssl x509 -noout -dates 2>&1"
        r = run_command(cmd, timeout=10)
        
        if ok(r) and 'notAfter' in r['stdout']:
            lines = r['stdout'].split('\n')
            expiry_info = ""
            for line in lines:
                if 'notAfter' in line:
                    expiry_info = line.split('=')[1] if '=' in line else line
                    break
            
            tests.append(create_test_result(
                "root_certificate",
                "Check root certificate",
                True,
                f"Root certificate valid until: {expiry_info}",
                "INFO"
            ))
    
    # Check mTLS configuration
    cmd = "kubectl get peerauthentications --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout'].isdigit():
        peer_auth_count = int(r['stdout'])
        tests.append(create_test_result(
            "mtls_config",
            "Check mTLS configuration",
            True,
            f"PeerAuthentication policies: {peer_auth_count}",
            "INFO"
        ))
    
    return tests

def check_istio_metrics() -> List[Dict[str, Any]]:
    """Check Istio metrics and telemetry."""
    description = "Check Istio telemetry and metrics"
    tests: List[Dict[str, Any]] = []
    
    # Check if Prometheus is deployed
    cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} prometheus -o name 2>/dev/null"
    r = run_command(cmd, timeout=5)
    prometheus_deployed = ok(r)
    
    # Check if Grafana is deployed
    cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} grafana -o name 2>/dev/null"
    r = run_command(cmd, timeout=5)
    grafana_deployed = ok(r)
    
    # Check if Kiali is deployed
    cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} kiali -o name 2>/dev/null"
    r = run_command(cmd, timeout=5)
    kiali_deployed = ok(r)
    
    # Check telemetry v2 configuration
    cmd = "kubectl get telemetry --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    telemetry_count = 0
    if ok(r) and r['stdout'].isdigit():
        telemetry_count = int(r['stdout'])
    
    output = "Observability stack:\n"
    output += f"  Prometheus: {'Deployed' if prometheus_deployed else 'Not found'}\n"
    output += f"  Grafana: {'Deployed' if grafana_deployed else 'Not found'}\n"
    output += f"  Kiali: {'Deployed' if kiali_deployed else 'Not found'}\n"
    output += f"  Telemetry configs: {telemetry_count}"
    
    tests.append(create_test_result(
        "observability_stack",
        description,
        True,
        output,
        "INFO"
    ))
    
    return tests

def check_istio_logs() -> List[Dict[str, Any]]:
    """Check Istio logs for errors."""
    description = "Check Istio control plane logs for errors"
    tests: List[Dict[str, Any]] = []
    
    # Check istiod logs
    cmd = f"kubectl logs -n {ISTIO_NAMESPACE} deployment/istiod --tail=100 2>&1 | grep -i error | wc -l"
    r = run_command(cmd, timeout=15)
    
    error_count = 0
    if ok(r) and r['stdout'].isdigit():
        error_count = int(r['stdout'])
    
    # Check for specific error patterns
    error_patterns = [
        "failed to list",
        "connection refused",
        "timeout",
        "panic:",
        "fatal:",
        "certificate.*expired"
    ]
    
    cmd = f"kubectl logs -n {ISTIO_NAMESPACE} deployment/istiod --tail=200 2>&1"
    r = run_command(cmd, timeout=15)
    
    critical_errors = []
    if ok(r) and r['stdout']:
        for line in r['stdout'].split('\n'):
            for pattern in error_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    critical_errors.append(line[:150])
                    break
    
    if critical_errors:
        output = f"Found {len(critical_errors)} critical error(s) in recent logs:\n"
        output += f"  Example: {critical_errors[0]}"
        severity = "WARNING"
        status = False
    elif error_count > 10:
        output = f"Found {error_count} error lines in recent logs (threshold: 10)"
        severity = "WARNING"
        status = False
    else:
        output = f"Log analysis: {error_count} error lines in last 100 entries"
        severity = "INFO"
        status = True
    
    tests.append(create_test_result(
        "control_plane_logs",
        description,
        status,
        output,
        severity
    ))
    
    return tests

def check_istio_security() -> List[Dict[str, Any]]:
    """Check Istio security policies."""
    description = "Check Istio security policies"
    tests: List[Dict[str, Any]] = []
    
    # Check AuthorizationPolicies
    cmd = "kubectl get authorizationpolicies --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    auth_policy_count = 0
    if ok(r) and r['stdout'].isdigit():
        auth_policy_count = int(r['stdout'])
    
    # Check RequestAuthentication
    cmd = "kubectl get requestauthentications --all-namespaces -o json 2>/dev/null | jq '.items | length'"
    r = run_command(cmd, timeout=10)
    req_auth_count = 0
    if ok(r) and r['stdout'].isdigit():
        req_auth_count = int(r['stdout'])
    
    output = "Security policies:\n"
    output += f"  Authorization Policies: {auth_policy_count}\n"
    output += f"  Request Authentications: {req_auth_count}"
    
    tests.append(create_test_result(
        "security_policies",
        description,
        True,
        output,
        "INFO"
    ))
    
    # Check default deny policy
    cmd = f"kubectl get authorizationpolicy -n {ISTIO_NAMESPACE} -o json 2>/dev/null | jq '.items[] | select(.spec.rules == null) | .metadata.name' -r"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        tests.append(create_test_result(
            "default_deny_policy",
            "Check for default deny policy",
            True,
            f"Default deny policy found: {r['stdout'].split()[0] if r['stdout'] else 'configured'}",
            "INFO"
        ))
    
    return tests

def check_istio_performance() -> List[Dict[str, Any]]:
    """Check Istio performance metrics."""
    description = "Check Istio performance indicators"
    tests: List[Dict[str, Any]] = []
    
    # Check istiod CPU and memory
    cmd = f"kubectl top pod -n {ISTIO_NAMESPACE} -l app=istiod --no-headers 2>/dev/null | head -1"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        parts = r['stdout'].split()
        if len(parts) >= 3:
            pod_name = parts[0]
            cpu = parts[1]
            memory = parts[2]
            
            output = f"Istiod resource usage:\n"
            output += f"  Pod: {pod_name}\n"
            output += f"  CPU: {cpu}\n"
            output += f"  Memory: {memory}"
            
            tests.append(create_test_result(
                "istiod_resources",
                "Check istiod resource usage",
                True,
                output,
                "INFO"
            ))
    
    # Check proxy resource usage (sample)
    cmd = "kubectl top pod --all-namespaces --no-headers 2>/dev/null | grep istio-proxy | head -5"
    r = run_command(cmd, timeout=15)
    
    if ok(r) and r['stdout']:
        lines = r['stdout'].split('\n')
        proxy_count = len([l for l in lines if l.strip()])
        
        tests.append(create_test_result(
            "proxy_resources",
            "Check proxy resource usage",
            True,
            f"Sampled {proxy_count} proxy containers with resource metrics available",
            "INFO"
        ))
    
    return tests

def check_istio_addons() -> List[Dict[str, Any]]:
    """Check Istio addon components."""
    description = "Check Istio addon components"
    tests: List[Dict[str, Any]] = []
    
    addons = {
        "jaeger": ["jaeger", "tracing"],
        "zipkin": ["zipkin"],
        "prometheus": ["prometheus"],
        "grafana": ["grafana"],
        "kiali": ["kiali"]
    }
    
    found_addons = []
    for addon_name, search_terms in addons.items():
        for term in search_terms:
            cmd = f"kubectl get deployments --all-namespaces -o json 2>/dev/null | jq '.items[] | select(.metadata.name | contains(\"{term}\")) | .metadata.name' -r | head -1"
            r = run_command(cmd, timeout=10)
            
            if ok(r) and r['stdout']:
                found_addons.append(addon_name)
                break
    
    if found_addons:
        output = f"Detected addons: {', '.join(found_addons)}"
        status = True
    else:
        output = "No standard Istio addons detected (this may be normal)"
        status = True  # Not a failure, addons are optional
    
    tests.append(create_test_result(
        "istio_addons",
        description,
        status,
        output,
        "INFO"
    ))
    
    return tests

# ------------------------------------------------------------
# Main Test Runner
# ------------------------------------------------------------

def test_istio() -> List[Dict[str, Any]]:
    """Run all Istio validation tests."""
    global ISTIO_NAMESPACE
    
    # Detect Istio namespace
    ISTIO_NAMESPACE = detect_istio_namespace()
    
    results: List[Dict[str, Any]] = []
    
    # Add namespace detection result
    results.append(create_test_result(
        "namespace_detection",
        "Detect Istio namespace",
        True,
        f"Using namespace: {ISTIO_NAMESPACE}",
        "INFO"
    ))
    
    # Run all test suites
    test_suites = [
        ("Version Check", check_istio_version),
        ("Control Plane Health", check_control_plane_health),
        ("Data Plane Status", check_data_plane_status),
        ("Configuration Validation", check_istio_configuration),
        ("Sidecar Injection", check_istio_injection),
        ("Service Mesh Resources", check_istio_services),
        ("Certificates & mTLS", check_istio_certificates),
        ("Metrics & Telemetry", check_istio_metrics),
        ("Security Policies", check_istio_security),
        ("Performance Metrics", check_istio_performance),
        ("Addon Components", check_istio_addons),
        ("Log Analysis", check_istio_logs),
    ]
    
    for suite_name, test_func in test_suites:
        try:
            suite_results = test_func()
            results.extend(suite_results)
        except Exception as e:
            results.append(create_test_result(
                f"{suite_name.lower().replace(' ', '_')}_error",
                suite_name,
                False,
                f"Test suite failed: {str(e)}",
                "WARNING"
            ))
    
    return results

def main():
    """Main entry point."""
    try:
        # Check if kubectl is available
        cmd = "kubectl version --client --short 2>/dev/null"
        r = run_command(cmd, timeout=5)
        if not ok(r):
            error_result = [create_test_result(
                "kubectl_check",
                "Check kubectl availability",
                False,
                "kubectl is not available or not configured",
                "CRITICAL"
            )]
            print(json.dumps(error_result, indent=2))
            sys.exit(1)
        
        # Check if istioctl is available
        cmd = "istioctl version --short 2>/dev/null"
        r = run_command(cmd, timeout=5)
        if not ok(r):
            error_result = [create_test_result(
                "istioctl_check",
                "Check istioctl availability",
                False,
                "istioctl is not available",
                "CRITICAL"
            )]
            print(json.dumps(error_result, indent=2))
            sys.exit(1)
        
        # Run tests
        results = test_istio()
        
        # Output JSON results
        print(json.dumps(results, indent=2))
        
        # Exit with appropriate code
        critical_failures = [r for r in results if r['severity'] == 'critical' and not r['status']]
        warnings = [r for r in results if r['severity'] == 'warning' and not r['status']]
        
        if critical_failures:
            sys.exit(2)  # Critical issues
        elif warnings:
            sys.exit(1)  # Warnings
        else:
            sys.exit(0)  # All good
        
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
