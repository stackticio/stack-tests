#!/usr/bin/env python3
"""
Istio Service Mesh Test Script - Advanced Edition
- Tests Istio control plane health, data plane status, configuration, and traffic management
- Deep traffic relationship analysis and per-Envoy diagnostics
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
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
import base64

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

# Global variables
ISTIO_NAMESPACE = ""
INJECTION_NAMESPACES = []

# ------------------------------------------------------------
# 1. Initial Setup and Basic Checks
# ------------------------------------------------------------

def check_prerequisites() -> List[Dict[str, Any]]:
    """Check prerequisites and tools availability."""
    tests: List[Dict[str, Any]] = []
    
    # Check kubectl
    cmd = "kubectl version --client --short 2>/dev/null"
    r = run_command(cmd, timeout=5)
    tests.append(create_test_result(
        "kubectl_check",
        "Check kubectl availability",
        ok(r),
        "kubectl is available" if ok(r) else "kubectl is not available or not configured",
        "CRITICAL" if not ok(r) else "INFO"
    ))
    
    # Check istioctl
    cmd = "istioctl version --short 2>/dev/null"
    r = run_command(cmd, timeout=5)
    tests.append(create_test_result(
        "istioctl_check",
        "Check istioctl availability",
        ok(r),
        "istioctl is available" if ok(r) else "istioctl is not available",
        "CRITICAL" if not ok(r) else "INFO"
    ))
    
    return tests

def check_istio_version() -> List[Dict[str, Any]]:
    """Check Istio version and compatibility."""
    description = "Check Istio version and client/server compatibility"
    
    cmd = "istioctl version 2>&1"
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
        
        output = f"Istio version info:\n"
        output += f"  Client: {client_version or 'detected'}\n"
        if control_version:
            output += f"  Control Plane: {control_version}"
        
        # Check version mismatch
        if client_version and control_version and client_version != control_version:
            output += "\n  ⚠️ Version mismatch detected"
            severity = "WARNING"
        else:
            severity = "INFO"
        
        return [create_test_result("istio_version", description, True, output, severity)]
    else:
        return [create_test_result("istio_version", description, False, 
                                  f"Failed to get Istio version: {r['stderr'] or 'istioctl not found'}", "WARNING")]

# ------------------------------------------------------------
# 2. Mesh Overview and Injection Status (EARLY PRIORITY)
# ------------------------------------------------------------

def analyze_mesh_overview() -> List[Dict[str, Any]]:
    """Provide high-level mesh overview - run early for context."""
    tests: List[Dict[str, Any]] = []
    global INJECTION_NAMESPACES
    
    # Get injection-enabled namespaces
    cmd = "kubectl get namespaces -l istio-injection=enabled -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    injection_enabled_namespaces = []
    if ok(r) and r['stdout']:
        try:
            namespaces = json.loads(r['stdout'])
            for ns in namespaces.get('items', []):
                ns_name = ns.get('metadata', {}).get('name', '')
                if ns_name:
                    injection_enabled_namespaces.append(ns_name)
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
                ns_name = ns.get('metadata', {}).get('name', '')
                if ns_name:
                    revision_namespaces.append(ns_name)
        except json.JSONDecodeError:
            pass
    
    INJECTION_NAMESPACES = list(set(injection_enabled_namespaces + revision_namespaces))
    
    # Create overview output
    output = "=" * 50 + "\n"
    output += "SERVICE MESH OVERVIEW\n"
    output += "=" * 50 + "\n"
    output += f"Istio Control Plane Namespace: {ISTIO_NAMESPACE}\n"
    output += f"Total Namespaces with Injection: {len(INJECTION_NAMESPACES)}\n"
    
    if INJECTION_NAMESPACES:
        output += "\nInjection-Enabled Namespaces:\n"
        for ns in sorted(INJECTION_NAMESPACES):
            output += f"  • {ns}\n"
    else:
        output += "\n⚠️ No namespaces with sidecar injection enabled\n"
    
    tests.append(create_test_result(
        "mesh_overview",
        "Service mesh overview and injection status",
        len(INJECTION_NAMESPACES) > 0,
        output.rstrip(),
        "WARNING" if len(INJECTION_NAMESPACES) == 0 else "INFO"
    ))
    
    return tests

def analyze_namespace_sidecars() -> List[Dict[str, Any]]:
    """Analyze sidecars per namespace - detailed breakdown."""
    tests: List[Dict[str, Any]] = []
    
    if not INJECTION_NAMESPACES:
        return [create_test_result(
            "namespace_sidecar_analysis",
            "Per-namespace sidecar analysis",
            False,
            "No injection-enabled namespaces found",
            "WARNING"
        )]
    
    output = "=" * 50 + "\n"
    output += "PER-NAMESPACE SIDECAR ANALYSIS\n"
    output += "=" * 50 + "\n"
    
    namespace_stats = {}
    total_pods_with_sidecars = 0
    total_pods_without_sidecars = 0
    
    for ns in sorted(INJECTION_NAMESPACES):
        # Get all pods in namespace
        cmd = f"kubectl get pods -n {ns} -o json 2>/dev/null"
        r = run_command(cmd, timeout=10)
        
        if ok(r) and r['stdout']:
            try:
                pods_data = json.loads(r['stdout'])
                pods = pods_data.get('items', [])
                
                ns_stats = {
                    'total_pods': len(pods),
                    'with_sidecar': 0,
                    'without_sidecar': 0,
                    'pending': 0,
                    'failed': 0,
                    'pods_without_sidecar': []
                }
                
                for pod in pods:
                    pod_name = pod.get('metadata', {}).get('name', '')
                    containers = pod.get('spec', {}).get('containers', [])
                    container_names = [c.get('name', '') for c in containers]
                    
                    # Check pod status
                    pod_phase = pod.get('status', {}).get('phase', '')
                    
                    if pod_phase == 'Pending':
                        ns_stats['pending'] += 1
                    elif pod_phase == 'Failed':
                        ns_stats['failed'] += 1
                    
                    # Check for istio-proxy container
                    if 'istio-proxy' in container_names:
                        ns_stats['with_sidecar'] += 1
                        total_pods_with_sidecars += 1
                    else:
                        ns_stats['without_sidecar'] += 1
                        total_pods_without_sidecars += 1
                        if pod_name:
                            ns_stats['pods_without_sidecar'].append(pod_name)
                
                namespace_stats[ns] = ns_stats
                
            except json.JSONDecodeError:
                namespace_stats[ns] = {'error': 'Failed to parse pod data'}
    
    # Format output for each namespace
    for ns in sorted(namespace_stats.keys()):
        stats = namespace_stats[ns]
        output += f"\n📦 Namespace: {ns}\n"
        output += "-" * 40 + "\n"
        
        if 'error' in stats:
            output += f"  ❌ {stats['error']}\n"
            continue
        
        output += f"  Total Pods: {stats['total_pods']}\n"
        output += f"  ✅ With Sidecar: {stats['with_sidecar']}\n"
        output += f"  ❌ Without Sidecar: {stats['without_sidecar']}\n"
        
        if stats['pending'] > 0:
            output += f"  ⏳ Pending: {stats['pending']}\n"
        if stats['failed'] > 0:
            output += f"  ⚠️ Failed: {stats['failed']}\n"
        
        # Show injection rate
        if stats['total_pods'] > 0:
            injection_rate = (stats['with_sidecar'] / stats['total_pods']) * 100
            output += f"  📊 Injection Rate: {injection_rate:.1f}%\n"
            
            if injection_rate < 100 and stats['pods_without_sidecar']:
                output += f"  ⚠️ Pods without sidecars:\n"
                for pod in stats['pods_without_sidecar'][:3]:
                    output += f"     - {pod}\n"
                if len(stats['pods_without_sidecar']) > 3:
                    output += f"     ... and {len(stats['pods_without_sidecar'])-3} more\n"
    
    # Summary
    output += "\n" + "=" * 50 + "\n"
    output += "SUMMARY\n"
    output += "-" * 40 + "\n"
    output += f"Total Pods with Sidecars: {total_pods_with_sidecars}\n"
    output += f"Total Pods without Sidecars: {total_pods_without_sidecars}\n"
    
    if (total_pods_with_sidecars + total_pods_without_sidecars) > 0:
        overall_injection_rate = (total_pods_with_sidecars / (total_pods_with_sidecars + total_pods_without_sidecars)) * 100
        output += f"Overall Injection Rate: {overall_injection_rate:.1f}%\n"
    
    # Determine severity
    severity = "INFO"
    if total_pods_without_sidecars > 0:
        severity = "WARNING"
    
    tests.append(create_test_result(
        "namespace_sidecar_analysis",
        "Detailed per-namespace sidecar analysis",
        total_pods_without_sidecars == 0,
        output.rstrip(),
        severity
    ))
    
    return tests

# ------------------------------------------------------------
# 3. Control Plane Health
# ------------------------------------------------------------

def check_control_plane_health() -> List[Dict[str, Any]]:
    """Check Istio control plane components health."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "CONTROL PLANE HEALTH\n"
    output += "=" * 50 + "\n"
    
    # Check istiod deployment
    cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} istiod -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    istiod_healthy = False
    if ok(r) and r['stdout']:
        try:
            deployment = json.loads(r['stdout'])
            replicas = deployment.get('spec', {}).get('replicas', 0)
            ready = deployment.get('status', {}).get('readyReplicas', 0)
            
            istiod_healthy = (replicas == ready and ready > 0)
            output += f"✅ Istiod: {ready}/{replicas} replicas ready\n" if istiod_healthy else f"❌ Istiod: {ready}/{replicas} replicas ready\n"
            
        except json.JSONDecodeError:
            output += "⚠️ Failed to parse istiod deployment status\n"
    else:
        output += "❌ Istiod deployment not found\n"
    
    # Check gateways
    components = ["istio-ingressgateway", "istio-egressgateway"]
    for component in components:
        cmd = f"kubectl get deployment -n {ISTIO_NAMESPACE} {component} -o json 2>/dev/null"
        r = run_command(cmd, timeout=10)
        
        if ok(r) and r['stdout']:
            try:
                deployment = json.loads(r['stdout'])
                replicas = deployment.get('spec', {}).get('replicas', 0)
                ready = deployment.get('status', {}).get('readyReplicas', 0)
                
                if replicas == ready and ready > 0:
                    output += f"✅ {component}: {ready}/{replicas} replicas ready\n"
                else:
                    output += f"⚠️ {component}: {ready}/{replicas} replicas ready\n"
            except json.JSONDecodeError:
                pass
        else:
            output += f"ℹ️ {component}: Not deployed (optional)\n"
    
    # Check control plane pods
    cmd = f"kubectl get pods -n {ISTIO_NAMESPACE} -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    unhealthy_pods = []
    if ok(r) and r['stdout']:
        try:
            pods = json.loads(r['stdout'])
            for pod in pods.get('items', []):
                pod_name = pod.get('metadata', {}).get('name', '')
                containers = pod.get('status', {}).get('containerStatuses', [])
                if not all(c.get('ready', False) for c in containers):
                    unhealthy_pods.append(pod_name)
        except json.JSONDecodeError:
            pass
    
    if unhealthy_pods:
        output += f"\n⚠️ Unhealthy control plane pods:\n"
        for pod in unhealthy_pods:
            output += f"  - {pod}\n"
    
    tests.append(create_test_result(
        "control_plane_health",
        "Control plane component health check",
        istiod_healthy and len(unhealthy_pods) == 0,
        output.rstrip(),
        "CRITICAL" if not istiod_healthy else ("WARNING" if unhealthy_pods else "INFO")
    ))
    
    return tests

# ------------------------------------------------------------
# 4. Data Plane Analysis (Per-Namespace)
# ------------------------------------------------------------

def analyze_data_plane_per_namespace() -> List[Dict[str, Any]]:
    """Analyze data plane health per namespace."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "DATA PLANE ANALYSIS BY NAMESPACE\n"
    output += "=" * 50 + "\n"
    
    # Get proxy status for all namespaces
    cmd = "istioctl proxy-status 2>&1"
    r = run_command(cmd, timeout=30)
    
    proxy_status_by_ns = {}
    if ok(r) and r['stdout']:
        lines = r['stdout'].split('\n')
        for line in lines[1:]:  # Skip header
            if line.strip() and not line.startswith('NAME'):
                parts = line.split()
                if len(parts) >= 3:
                    proxy_name = parts[0]
                    # Extract namespace from proxy name (format: pod-name.namespace)
                    if '.' in proxy_name:
                        ns = proxy_name.split('.')[1]
                        if ns not in proxy_status_by_ns:
                            proxy_status_by_ns[ns] = {
                                'synced': 0,
                                'stale': 0,
                                'not_sent': 0,
                                'proxies': []
                            }
                        
                        status = ' '.join(parts[2:])
                        proxy_info = {
                            'name': proxy_name.split('.')[0],
                            'status': status
                        }
                        proxy_status_by_ns[ns]['proxies'].append(proxy_info)
                        
                        if 'SYNCED' in status:
                            proxy_status_by_ns[ns]['synced'] += 1
                        elif 'STALE' in status:
                            proxy_status_by_ns[ns]['stale'] += 1
                        elif 'NOT SENT' in status:
                            proxy_status_by_ns[ns]['not_sent'] += 1
    
    # Analyze each namespace
    for ns in sorted(INJECTION_NAMESPACES):
        output += f"\n📦 Namespace: {ns}\n"
        output += "-" * 40 + "\n"
        
        if ns in proxy_status_by_ns:
            stats = proxy_status_by_ns[ns]
            total_proxies = len(stats['proxies'])
            
            output += f"  Total Proxies: {total_proxies}\n"
            output += f"  ✅ Synced: {stats['synced']}\n"
            
            if stats['stale'] > 0:
                output += f"  ⚠️ Stale: {stats['stale']}\n"
            if stats['not_sent'] > 0:
                output += f"  ❌ Not Sent: {stats['not_sent']}\n"
            
            # Show problematic proxies
            problematic = [p for p in stats['proxies'] if 'SYNCED' not in p['status']]
            if problematic:
                output += "  Problematic proxies:\n"
                for proxy in problematic[:3]:
                    output += f"    - {proxy['name']}: {proxy['status']}\n"
                if len(problematic) > 3:
                    output += f"    ... and {len(problematic)-3} more\n"
        else:
            output += "  No proxy data available\n"
    
    # Determine overall health
    total_stale = sum(stats['stale'] for stats in proxy_status_by_ns.values())
    total_not_sent = sum(stats['not_sent'] for stats in proxy_status_by_ns.values())
    
    severity = "INFO"
    if total_not_sent > 0:
        severity = "WARNING"
    elif total_stale > 0:
        severity = "WARNING"
    
    tests.append(create_test_result(
        "data_plane_per_namespace",
        "Data plane proxy status by namespace",
        total_stale == 0 and total_not_sent == 0,
        output.rstrip(),
        severity
    ))
    
    return tests

# ------------------------------------------------------------
# 5. Traffic Flow Analysis
# ------------------------------------------------------------

def analyze_traffic_relationships() -> List[Dict[str, Any]]:
    """Analyze service-to-service traffic relationships."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "TRAFFIC FLOW ANALYSIS\n"
    output += "=" * 50 + "\n"
    
    # Get VirtualServices
    cmd = "kubectl get virtualservices --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    virtual_services_by_ns = {}
    traffic_rules = []
    
    if ok(r) and r['stdout']:
        try:
            vs_data = json.loads(r['stdout'])
            for vs in vs_data.get('items', []):
                vs_name = vs.get('metadata', {}).get('name', '')
                vs_namespace = vs.get('metadata', {}).get('namespace', '')
                hosts = vs.get('spec', {}).get('hosts', [])
                
                if vs_namespace not in virtual_services_by_ns:
                    virtual_services_by_ns[vs_namespace] = []
                
                virtual_services_by_ns[vs_namespace].append({
                    'name': vs_name,
                    'hosts': hosts
                })
                
                # Check for traffic splitting
                http_rules = vs.get('spec', {}).get('http', [])
                for rule in http_rules:
                    routes = rule.get('route', [])
                    if len(routes) > 1:
                        weights = [r.get('weight', 0) for r in routes]
                        destinations = [r.get('destination', {}).get('host', '') for r in routes]
                        traffic_rules.append({
                            'namespace': vs_namespace,
                            'vs': vs_name,
                            'type': 'traffic-split',
                            'weights': weights,
                            'destinations': destinations
                        })
        except json.JSONDecodeError:
            pass
    
    # Get DestinationRules
    cmd = "kubectl get destinationrules --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    destination_rules_by_ns = {}
    if ok(r) and r['stdout']:
        try:
            dr_data = json.loads(r['stdout'])
            for dr in dr_data.get('items', []):
                dr_name = dr.get('metadata', {}).get('name', '')
                dr_namespace = dr.get('metadata', {}).get('namespace', '')
                host = dr.get('spec', {}).get('host', '')
                
                if dr_namespace not in destination_rules_by_ns:
                    destination_rules_by_ns[dr_namespace] = []
                
                destination_rules_by_ns[dr_namespace].append({
                    'name': dr_name,
                    'host': host
                })
        except json.JSONDecodeError:
            pass
    
    # Output per namespace
    for ns in sorted(INJECTION_NAMESPACES):
        output += f"\n📦 Namespace: {ns}\n"
        output += "-" * 40 + "\n"
        
        # Virtual Services
        if ns in virtual_services_by_ns:
            output += f"  Virtual Services: {len(virtual_services_by_ns[ns])}\n"
            for vs in virtual_services_by_ns[ns][:3]:
                output += f"    - {vs['name']} → {', '.join(vs['hosts'][:2])}\n"
        else:
            output += "  Virtual Services: 0\n"
        
        # Destination Rules
        if ns in destination_rules_by_ns:
            output += f"  Destination Rules: {len(destination_rules_by_ns[ns])}\n"
            for dr in destination_rules_by_ns[ns][:3]:
                output += f"    - {dr['name']} → {dr['host']}\n"
        else:
            output += "  Destination Rules: 0\n"
        
        # Traffic splitting rules
        ns_traffic_rules = [r for r in traffic_rules if r['namespace'] == ns]
        if ns_traffic_rules:
            output += "  ⚡ Traffic Management:\n"
            for rule in ns_traffic_rules[:2]:
                output += f"    - {rule['vs']}: Split {rule['weights']} to {', '.join(rule['destinations'][:2])}\n"
    
    # Summary
    output += "\n" + "=" * 50 + "\n"
    output += "TRAFFIC MANAGEMENT SUMMARY\n"
    output += "-" * 40 + "\n"
    output += f"Total VirtualServices: {sum(len(vs) for vs in virtual_services_by_ns.values())}\n"
    output += f"Total DestinationRules: {sum(len(dr) for dr in destination_rules_by_ns.values())}\n"
    output += f"Traffic Splitting Rules: {len(traffic_rules)}\n"
    
    tests.append(create_test_result(
        "traffic_flow_analysis",
        "Service-to-service traffic flow analysis",
        True,
        output.rstrip(),
        "INFO"
    ))
    
    return tests

# ------------------------------------------------------------
# 6. Security and Policy Analysis
# ------------------------------------------------------------

def analyze_security_policies() -> List[Dict[str, Any]]:
    """Analyze security policies per namespace."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "SECURITY POLICY ANALYSIS\n"
    output += "=" * 50 + "\n"
    
    # Get PeerAuthentications
    cmd = "kubectl get peerauthentications --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    peer_auth_by_ns = {}
    if ok(r) and r['stdout']:
        try:
            pa_data = json.loads(r['stdout'])
            for pa in pa_data.get('items', []):
                pa_name = pa.get('metadata', {}).get('name', '')
                pa_namespace = pa.get('metadata', {}).get('namespace', '')
                mtls_mode = pa.get('spec', {}).get('mtls', {}).get('mode', 'UNSET')
                
                if pa_namespace not in peer_auth_by_ns:
                    peer_auth_by_ns[pa_namespace] = []
                
                peer_auth_by_ns[pa_namespace].append({
                    'name': pa_name,
                    'mtls_mode': mtls_mode
                })
        except json.JSONDecodeError:
            pass
    
    # Get AuthorizationPolicies
    cmd = "kubectl get authorizationpolicies --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    auth_policies_by_ns = {}
    if ok(r) and r['stdout']:
        try:
            ap_data = json.loads(r['stdout'])
            for ap in ap_data.get('items', []):
                ap_name = ap.get('metadata', {}).get('name', '')
                ap_namespace = ap.get('metadata', {}).get('namespace', '')
                rules_count = len(ap.get('spec', {}).get('rules', []))
                action = ap.get('spec', {}).get('action', 'ALLOW')
                
                if ap_namespace not in auth_policies_by_ns:
                    auth_policies_by_ns[ap_namespace] = []
                
                auth_policies_by_ns[ap_namespace].append({
                    'name': ap_name,
                    'rules': rules_count,
                    'action': action
                })
        except json.JSONDecodeError:
            pass
    
    # Analyze per namespace
    for ns in sorted(INJECTION_NAMESPACES):
        output += f"\n📦 Namespace: {ns}\n"
        output += "-" * 40 + "\n"
        
        # mTLS settings
        if ns in peer_auth_by_ns:
            output += f"  mTLS Policies: {len(peer_auth_by_ns[ns])}\n"
            for pa in peer_auth_by_ns[ns]:
                icon = "🔒" if pa['mtls_mode'] == 'STRICT' else "🔓"
                output += f"    {icon} {pa['name']}: {pa['mtls_mode']}\n"
        else:
            output += "  mTLS Policies: None (using mesh default)\n"
        
        # Authorization policies
        if ns in auth_policies_by_ns:
            output += f"  Authorization Policies: {len(auth_policies_by_ns[ns])}\n"
            for ap in auth_policies_by_ns[ns][:3]:
                output += f"    - {ap['name']}: {ap['action']} ({ap['rules']} rules)\n"
        else:
            output += "  Authorization Policies: None\n"
    
    # Check for security issues
    namespaces_without_strict_mtls = []
    for ns in INJECTION_NAMESPACES:
        if ns not in peer_auth_by_ns or not any(pa['mtls_mode'] == 'STRICT' for pa in peer_auth_by_ns.get(ns, [])):
            namespaces_without_strict_mtls.append(ns)
    
    if namespaces_without_strict_mtls:
        output += "\n⚠️ Namespaces without STRICT mTLS:\n"
        for ns in namespaces_without_strict_mtls:
            output += f"  - {ns}\n"
    
    severity = "WARNING" if namespaces_without_strict_mtls else "INFO"
    
    tests.append(create_test_result(
        "security_policy_analysis",
        "Security policies per namespace",
        len(namespaces_without_strict_mtls) == 0,
        output.rstrip(),
        severity
    ))
    
    return tests

# ------------------------------------------------------------
# 7. Performance and Health Metrics
# ------------------------------------------------------------

def analyze_envoy_health_metrics() -> List[Dict[str, Any]]:
    """Analyze Envoy health and performance metrics."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "ENVOY HEALTH & PERFORMANCE\n"
    output += "=" * 50 + "\n"
    
    # Sample envoys from each namespace
    envoy_health_by_ns = {}
    
    for ns in INJECTION_NAMESPACES[:5]:  # Sample first 5 namespaces
        # Get pods with sidecars
        cmd = f"kubectl get pods -n {ns} -o json 2>/dev/null | jq -r '.items[] | select(.spec.containers[].name == \"istio-proxy\") | .metadata.name' | head -3"
        r = run_command(cmd, timeout=10)
        
        if not ok(r) or not r['stdout']:
            continue
        
        sample_pods = r['stdout'].split('\n')
        ns_health = {
            'healthy': 0,
            'unhealthy': 0,
            'errors': []
        }
        
        for pod in sample_pods[:2]:  # Sample 2 pods per namespace
            if not pod:
                continue
            
            # Check Envoy admin endpoint
            cmd = f"kubectl exec -n {ns} {pod} -c istio-proxy -- curl -s localhost:15000/server_info 2>/dev/null | jq -r '.state'"
            r = run_command(cmd, timeout=5)
            
            if ok(r) and r['stdout']:
                if r['stdout'] == 'LIVE':
                    ns_health['healthy'] += 1
                else:
                    ns_health['unhealthy'] += 1
            
            # Check for errors in stats
            cmd = f"kubectl exec -n {ns} {pod} -c istio-proxy -- curl -s localhost:15000/stats | grep -c 'failed\\|error\\|rejected' 2>/dev/null"
            r = run_command(cmd, timeout=5)
            
            if ok(r) and r['stdout'].isdigit():
                error_count = int(r['stdout'])
                if error_count > 100:
                    ns_health['errors'].append(f"{pod}: {error_count} errors")
        
        if ns_health['healthy'] > 0 or ns_health['unhealthy'] > 0:
            envoy_health_by_ns[ns] = ns_health
    
    # Output results
    for ns in sorted(envoy_health_by_ns.keys()):
        health = envoy_health_by_ns[ns]
        output += f"\n📦 Namespace: {ns}\n"
        output += "-" * 40 + "\n"
        output += f"  Sampled Envoys:\n"
        output += f"    ✅ Healthy: {health['healthy']}\n"
        if health['unhealthy'] > 0:
            output += f"    ❌ Unhealthy: {health['unhealthy']}\n"
        
        if health['errors']:
            output += "  ⚠️ High error counts:\n"
            for error in health['errors']:
                output += f"    - {error}\n"
    
    # Check resource usage if metrics-server is available
    cmd = "kubectl top pods --all-namespaces --containers 2>/dev/null | grep istio-proxy | head -10"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        output += "\n" + "=" * 50 + "\n"
        output += "PROXY RESOURCE USAGE (Sample)\n"
        output += "-" * 40 + "\n"
        
        lines = r['stdout'].split('\n')
        high_cpu = []
        high_memory = []
        
        for line in lines:
            if line:
                parts = line.split()
                if len(parts) >= 5:
                    namespace = parts[0]
                    pod = parts[1]
                    cpu = parts[3]
                    memory = parts[4]
                    
                    # Check for high resource usage
                    if 'm' in cpu:
                        cpu_value = int(cpu.replace('m', ''))
                        if cpu_value > 100:  # Over 100m CPU
                            high_cpu.append(f"{namespace}/{pod}: {cpu}")
                    
                    if 'Mi' in memory:
                        mem_value = int(memory.replace('Mi', ''))
                        if mem_value > 256:  # Over 256Mi memory
                            high_memory.append(f"{namespace}/{pod}: {memory}")
        
        if high_cpu:
            output += "  ⚠️ High CPU usage:\n"
            for item in high_cpu[:3]:
                output += f"    - {item}\n"
        
        if high_memory:
            output += "  ⚠️ High memory usage:\n"
            for item in high_memory[:3]:
                output += f"    - {item}\n"
        
        if not high_cpu and not high_memory:
            output += "  ✅ All sampled proxies within normal resource limits\n"
    
    tests.append(create_test_result(
        "envoy_health_metrics",
        "Envoy health and performance analysis",
        True,
        output.rstrip(),
        "INFO"
    ))
    
    return tests

# ------------------------------------------------------------
# 8. Configuration Validation
# ------------------------------------------------------------

def validate_istio_configuration() -> List[Dict[str, Any]]:
    """Validate Istio configuration for errors."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "CONFIGURATION VALIDATION\n"
    output += "=" * 50 + "\n"
    
    # Run istioctl analyze
    cmd = "istioctl analyze --all-namespaces 2>&1"
    r = run_command(cmd, timeout=30)
    
    errors_by_ns = {}
    warnings_by_ns = {}
    info_by_ns = {}
    
    if ok(r) and r['stdout']:
        lines = r['stdout'].split('\n')
        
        if 'No validation issues found' in r['stdout']:
            output += "✅ No configuration issues found\n"
        else:
            for line in lines:
                # Try to extract namespace from the line
                ns_match = None
                for ns in INJECTION_NAMESPACES:
                    if ns in line:
                        ns_match = ns
                        break
                
                if ns_match:
                    if 'Error' in line or 'ERROR' in line:
                        if ns_match not in errors_by_ns:
                            errors_by_ns[ns_match] = []
                        errors_by_ns[ns_match].append(line[:150])
                    elif 'Warning' in line or 'WARN' in line:
                        if ns_match not in warnings_by_ns:
                            warnings_by_ns[ns_match] = []
                        warnings_by_ns[ns_match].append(line[:150])
                    elif 'Info' in line or 'INFO' in line:
                        if ns_match not in info_by_ns:
                            info_by_ns[ns_match] = []
                        info_by_ns[ns_match].append(line[:150])
    
    # Output issues by namespace
    if errors_by_ns or warnings_by_ns:
        for ns in sorted(set(list(errors_by_ns.keys()) + list(warnings_by_ns.keys()))):
            output += f"\n📦 Namespace: {ns}\n"
            output += "-" * 40 + "\n"
            
            if ns in errors_by_ns:
                output += f"  ❌ Errors: {len(errors_by_ns[ns])}\n"
                for error in errors_by_ns[ns][:2]:
                    output += f"    - {error}\n"
            
            if ns in warnings_by_ns:
                output += f"  ⚠️ Warnings: {len(warnings_by_ns[ns])}\n"
                for warning in warnings_by_ns[ns][:2]:
                    output += f"    - {warning}\n"
    
    # Summary
    total_errors = sum(len(e) for e in errors_by_ns.values())
    total_warnings = sum(len(w) for w in warnings_by_ns.values())
    
    output += "\n" + "=" * 50 + "\n"
    output += "VALIDATION SUMMARY\n"
    output += "-" * 40 + "\n"
    output += f"Total Errors: {total_errors}\n"
    output += f"Total Warnings: {total_warnings}\n"
    
    severity = "CRITICAL" if total_errors > 0 else ("WARNING" if total_warnings > 0 else "INFO")
    
    tests.append(create_test_result(
        "configuration_validation",
        "Istio configuration validation",
        total_errors == 0,
        output.rstrip(),
        severity
    ))
    
    return tests

# ------------------------------------------------------------
# 9. Advanced Diagnostics
# ------------------------------------------------------------

def check_circuit_breakers_and_resilience() -> List[Dict[str, Any]]:
    """Check circuit breakers and resilience patterns."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "RESILIENCE PATTERNS\n"
    output += "=" * 50 + "\n"
    
    # Get DestinationRules for circuit breaker analysis
    cmd = "kubectl get destinationrules --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    circuit_breakers_by_ns = {}
    outlier_detection_by_ns = {}
    
    if ok(r) and r['stdout']:
        try:
            dr_data = json.loads(r['stdout'])
            for dr in dr_data.get('items', []):
                dr_name = dr.get('metadata', {}).get('name', '')
                dr_namespace = dr.get('metadata', {}).get('namespace', '')
                
                traffic_policy = dr.get('spec', {}).get('trafficPolicy', {})
                
                # Check for circuit breaker
                connection_pool = traffic_policy.get('connectionPool', {})
                if connection_pool:
                    if dr_namespace not in circuit_breakers_by_ns:
                        circuit_breakers_by_ns[dr_namespace] = []
                    
                    tcp = connection_pool.get('tcp', {})
                    http = connection_pool.get('http', {})
                    
                    cb_config = {
                        'name': dr_name,
                        'max_connections': tcp.get('maxConnections', 'default'),
                        'max_requests': http.get('http1MaxPendingRequests', 'default')
                    }
                    circuit_breakers_by_ns[dr_namespace].append(cb_config)
                
                # Check for outlier detection
                outlier = traffic_policy.get('outlierDetection', {})
                if outlier:
                    if dr_namespace not in outlier_detection_by_ns:
                        outlier_detection_by_ns[dr_namespace] = []
                    
                    od_config = {
                        'name': dr_name,
                        'consecutive_errors': outlier.get('consecutiveErrors', 'default'),
                        'ejection_time': outlier.get('baseEjectionTime', 'default')
                    }
                    outlier_detection_by_ns[dr_namespace].append(od_config)
        except json.JSONDecodeError:
            pass
    
    # Output per namespace
    for ns in sorted(INJECTION_NAMESPACES):
        has_config = ns in circuit_breakers_by_ns or ns in outlier_detection_by_ns
        
        if has_config:
            output += f"\n📦 Namespace: {ns}\n"
            output += "-" * 40 + "\n"
            
            if ns in circuit_breakers_by_ns:
                output += f"  Circuit Breakers: {len(circuit_breakers_by_ns[ns])}\n"
                for cb in circuit_breakers_by_ns[ns][:2]:
                    output += f"    - {cb['name']}: max_conn={cb['max_connections']}, max_req={cb['max_requests']}\n"
            
            if ns in outlier_detection_by_ns:
                output += f"  Outlier Detection: {len(outlier_detection_by_ns[ns])}\n"
                for od in outlier_detection_by_ns[ns][:2]:
                    output += f"    - {od['name']}: errors={od['consecutive_errors']}, ejection={od['ejection_time']}\n"
    
    # Summary
    total_cbs = sum(len(cb) for cb in circuit_breakers_by_ns.values())
    total_ods = sum(len(od) for od in outlier_detection_by_ns.values())
    
    output += "\n" + "=" * 50 + "\n"
    output += "RESILIENCE SUMMARY\n"
    output += "-" * 40 + "\n"
    output += f"Total Circuit Breakers: {total_cbs}\n"
    output += f"Total Outlier Detection Policies: {total_ods}\n"
    
    if total_cbs == 0 and total_ods == 0:
        output += "\n⚠️ No resilience patterns configured - consider adding circuit breakers\n"
    
    tests.append(create_test_result(
        "resilience_patterns",
        "Circuit breakers and outlier detection",
        True,
        output.rstrip(),
        "WARNING" if total_cbs == 0 and total_ods == 0 else "INFO"
    ))
    
    return tests

def check_observability_stack() -> List[Dict[str, Any]]:
    """Check observability and telemetry components."""
    tests: List[Dict[str, Any]] = []
    
    output = "=" * 50 + "\n"
    output += "OBSERVABILITY STACK\n"
    output += "=" * 50 + "\n"
    
    # Check for common observability components
    components = {
        "prometheus": ["prometheus"],
        "grafana": ["grafana"],
        "kiali": ["kiali"],
        "jaeger": ["jaeger", "tracing"],
        "zipkin": ["zipkin"]
    }
    
    found_components = {}
    
    for component_name, search_terms in components.items():
        for term in search_terms:
            cmd = f"kubectl get deployments --all-namespaces 2>/dev/null | grep -i {term} | head -1"
            r = run_command(cmd, timeout=5)
            
            if ok(r) and r['stdout']:
                parts = r['stdout'].split()
                if parts:
                    namespace = parts[0]
                    deployment = parts[1]
                    found_components[component_name] = f"{namespace}/{deployment}"
                    break
    
    if found_components:
        output += "Detected Components:\n"
        for component, location in found_components.items():
            output += f"  ✅ {component.capitalize()}: {location}\n"
    else:
        output += "⚠️ No standard observability components detected\n"
    
    # Check Telemetry configuration
    cmd = "kubectl get telemetry --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    telemetry_configs = []
    if ok(r) and r['stdout']:
        try:
            telemetry_data = json.loads(r['stdout'])
            for telemetry in telemetry_data.get('items', []):
                t_name = telemetry.get('metadata', {}).get('name', '')
                t_namespace = telemetry.get('metadata', {}).get('namespace', '')
                telemetry_configs.append(f"{t_namespace}/{t_name}")
        except json.JSONDecodeError:
            pass
    
    if telemetry_configs:
        output += f"\nTelemetry Configurations: {len(telemetry_configs)}\n"
        for config in telemetry_configs[:3]:
            output += f"  - {config}\n"
    
    tests.append(create_test_result(
        "observability_stack",
        "Observability and telemetry components",
        len(found_components) > 0,
        output.rstrip(),
        "WARNING" if len(found_components) == 0 else "INFO"
    ))
    
    return tests

# ------------------------------------------------------------
# Main Test Runner
# ------------------------------------------------------------

def test_istio() -> List[Dict[str, Any]]:
    """Run all Istio validation tests in organized order."""
    global ISTIO_NAMESPACE, INJECTION_NAMESPACES
    
    # Detect Istio namespace
    ISTIO_NAMESPACE = detect_istio_namespace()
    
    results: List[Dict[str, Any]] = []
    
    # Test suite execution order - organized for better readability
    test_suites = [
        # 1. Prerequisites and Setup
        ("Prerequisites", check_prerequisites),
        ("Istio Version", check_istio_version),
        
        # 2. Mesh Overview (EARLY - provides context)
        ("Mesh Overview", analyze_mesh_overview),
        ("Namespace Sidecar Analysis", analyze_namespace_sidecars),
        
        # 3. Control Plane
        ("Control Plane Health", check_control_plane_health),
        
        # 4. Data Plane (Per-Namespace)
        ("Data Plane by Namespace", analyze_data_plane_per_namespace),
        
        # 5. Traffic Management
        ("Traffic Flow Analysis", analyze_traffic_relationships),
        
        # 6. Security
        ("Security Policies", analyze_security_policies),
        
        # 7. Performance
        ("Envoy Health & Metrics", analyze_envoy_health_metrics),
        
        # 8. Configuration
        ("Configuration Validation", validate_istio_configuration),
        
        # 9. Advanced Features
        ("Resilience Patterns", check_circuit_breakers_and_resilience),
        ("Observability Stack", check_observability_stack),
    ]
    
    print("", file=sys.stderr)  # Empty line for better formatting
    print("=" * 60, file=sys.stderr)
    print("ISTIO SERVICE MESH DIAGNOSTIC", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"Timestamp: {datetime.now().isoformat()}", file=sys.stderr)
    print(f"Control Plane Namespace: {ISTIO_NAMESPACE}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    
    for suite_name, test_func in test_suites:
        print(f"Running: {suite_name}...", file=sys.stderr)
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
        # Run tests
        results = test_istio()
        
        # Output JSON results
        print(json.dumps(results, indent=2))
        
        # Print summary to stderr
        print("\n" + "=" * 60, file=sys.stderr)
        print("SUMMARY", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        
        critical_failures = [r for r in results if r['severity'] == 'critical' and not r['status']]
        warnings = [r for r in results if r['severity'] == 'warning' and not r['status']]
        passed = [r for r in results if r['status']]
        
        print(f"✅ Passed: {len(passed)}/{len(results)}", file=sys.stderr)
        print(f"⚠️  Warnings: {len(warnings)}", file=sys.stderr)
        print(f"❌ Critical: {len(critical_failures)}", file=sys.stderr)
        
        # Exit with appropriate code
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
