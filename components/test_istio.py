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

# Global variable for Istio namespace (will be set dynamically)
ISTIO_NAMESPACE = ""

# ------------------------------------------------------------
# Core Istio Tests (Original)
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

# ------------------------------------------------------------
# Advanced Data Plane Analysis
# ------------------------------------------------------------

def check_data_plane_status_advanced() -> List[Dict[str, Any]]:
    """Enhanced data plane status with per-proxy analysis."""
    description = "Advanced data plane proxy status analysis"
    tests: List[Dict[str, Any]] = []
    
    # Get detailed proxy status
    cmd = "istioctl proxy-status --all-namespaces 2>&1"
    r = run_command(cmd, timeout=30)
    
    proxy_details = {}
    if ok(r) and r['stdout']:
        lines = r['stdout'].split('\n')
        for line in lines[1:]:  # Skip header
            if line.strip() and not line.startswith('NAME'):
                parts = line.split()
                if len(parts) >= 3:
                    proxy_name = parts[0]
                    proxy_details[proxy_name] = {
                        'cds': 'SYNCED' in line,
                        'lds': 'SYNCED' in line,
                        'eds': 'SYNCED' in line,
                        'rds': 'SYNCED' in line,
                        'status': ' '.join(parts[2:])
                    }
    
    # Analyze proxy configuration sync
    total_proxies = len(proxy_details)
    fully_synced = sum(1 for p in proxy_details.values() if 'SYNCED' in p['status'])
    stale_proxies = sum(1 for p in proxy_details.values() if 'STALE' in p['status'])
    not_sent_proxies = sum(1 for p in proxy_details.values() if 'NOT SENT' in p['status'])
    
    output = f"Advanced proxy analysis:\n"
    output += f"  Total proxies: {total_proxies}\n"
    output += f"  Fully synced: {fully_synced}\n"
    output += f"  Stale configs: {stale_proxies}\n"
    output += f"  Not sent: {not_sent_proxies}"
    
    tests.append(create_test_result(
        "proxy_sync_analysis",
        description,
        stale_proxies == 0 and not_sent_proxies == 0,
        output,
        "WARNING" if stale_proxies > 0 or not_sent_proxies > 0 else "INFO"
    ))
    
    # Check problematic proxies in detail
    if stale_proxies > 0 or not_sent_proxies > 0:
        problematic = [name for name, details in proxy_details.items() 
                      if 'STALE' in details['status'] or 'NOT SENT' in details['status']][:5]
        
        for proxy in problematic:
            # Get proxy config for each problematic proxy
            cmd = f"istioctl proxy-config all {proxy} 2>&1 | head -50"
            r = run_command(cmd, timeout=10)
            
            tests.append(create_test_result(
                f"proxy_issue_{proxy[:20]}",
                f"Problematic proxy: {proxy[:30]}",
                False,
                f"Proxy {proxy[:30]} has configuration issues",
                "WARNING"
            ))
    
    return tests

def check_envoy_health_per_proxy() -> List[Dict[str, Any]]:
    """Check health of each Envoy proxy individually."""
    description = "Per-Envoy health and error analysis"
    tests: List[Dict[str, Any]] = []
    
    # Get all pods with sidecars
    cmd = "kubectl get pods --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.spec.containers[].name == \"istio-proxy\") | \"\\(.metadata.namespace)/\\(.metadata.name)\"'"
    r = run_command(cmd, timeout=20)
    
    if not ok(r) or not r['stdout']:
        return tests
    
    envoy_pods = r['stdout'].split('\n')[:10]  # Sample first 10 for performance
    
    unhealthy_envoys = []
    envoy_stats = {
        'healthy': 0,
        'unhealthy': 0,
        'connection_errors': 0,
        'config_errors': 0,
        'memory_issues': 0
    }
    
    for pod_ref in envoy_pods:
        if not pod_ref or '/' not in pod_ref:
            continue
            
        namespace, pod = pod_ref.split('/')
        
        # Check Envoy admin endpoint health
        cmd = f"kubectl exec -n {namespace} {pod} -c istio-proxy -- curl -s localhost:15000/server_info 2>/dev/null | jq -r '.state'"
        r = run_command(cmd, timeout=5)
        
        if ok(r) and r['stdout']:
            state = r['stdout']
            if state != 'LIVE':
                unhealthy_envoys.append(f"{namespace}/{pod}")
                envoy_stats['unhealthy'] += 1
            else:
                envoy_stats['healthy'] += 1
        
        # Check for Envoy errors in stats
        cmd = f"kubectl exec -n {namespace} {pod} -c istio-proxy -- curl -s localhost:15000/stats | grep -E '(failed|error|rejected)' | head -5 2>/dev/null"
        r = run_command(cmd, timeout=5)
        
        if ok(r) and r['stdout']:
            error_lines = r['stdout'].split('\n')
            for line in error_lines:
                if 'connection' in line.lower():
                    envoy_stats['connection_errors'] += 1
                elif 'config' in line.lower():
                    envoy_stats['config_errors'] += 1
    
    output = f"Envoy health analysis (sampled {len(envoy_pods)} pods):\n"
    output += f"  Healthy: {envoy_stats['healthy']}\n"
    output += f"  Unhealthy: {envoy_stats['unhealthy']}\n"
    output += f"  Connection errors detected: {envoy_stats['connection_errors']}\n"
    output += f"  Config errors detected: {envoy_stats['config_errors']}"
    
    if unhealthy_envoys:
        output += f"\n  Unhealthy Envoys: {', '.join(unhealthy_envoys[:3])}"
    
    tests.append(create_test_result(
        "envoy_health_check",
        description,
        envoy_stats['unhealthy'] == 0,
        output,
        "WARNING" if envoy_stats['unhealthy'] > 0 else "INFO"
    ))
    
    return tests

# ------------------------------------------------------------
# Traffic Flow and Relationship Analysis
# ------------------------------------------------------------

def analyze_traffic_relationships() -> List[Dict[str, Any]]:
    """Analyze service-to-service traffic relationships."""
    description = "Service mesh traffic flow analysis"
    tests: List[Dict[str, Any]] = []
    
    # Get service graph from proxy configs
    service_relationships = {}
    
    # Sample a few proxies to understand traffic patterns
    cmd = "istioctl proxy-status --all-namespaces 2>&1 | head -10 | tail -9"
    r = run_command(cmd, timeout=20)
    
    if ok(r) and r['stdout']:
        sample_proxies = []
        for line in r['stdout'].split('\n'):
            if line.strip() and not line.startswith('NAME'):
                parts = line.split()
                if parts:
                    sample_proxies.append(parts[0])
        
        # Analyze clusters (upstream services) for each proxy
        for proxy in sample_proxies[:5]:  # Sample first 5
            cmd = f"istioctl proxy-config cluster {proxy} 2>&1 | grep -E 'outbound|inbound' | head -20"
            r = run_command(cmd, timeout=10)
            
            if ok(r) and r['stdout']:
                for line in r['stdout'].split('\n'):
                    if 'outbound' in line:
                        # Extract service name from cluster
                        match = re.search(r'outbound\|.*?\|.*?\|([^|]+)', line)
                        if match:
                            service = match.group(1).split('.')[0]
                            proxy_service = proxy.split('-')[0] if '-' in proxy else proxy
                            
                            if proxy_service not in service_relationships:
                                service_relationships[proxy_service] = set()
                            service_relationships[proxy_service].add(service)
    
    # Analyze Virtual Services for traffic routing rules
    cmd = "kubectl get virtualservices --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    routing_rules = {}
    if ok(r) and r['stdout']:
        try:
            vs_data = json.loads(r['stdout'])
            for vs in vs_data.get('items', []):
                vs_name = vs.get('metadata', {}).get('name', 'unknown')
                hosts = vs.get('spec', {}).get('hosts', [])
                
                # Check for traffic splitting
                http_rules = vs.get('spec', {}).get('http', [])
                for rule in http_rules:
                    routes = rule.get('route', [])
                    if len(routes) > 1:
                        weights = [r.get('weight', 0) for r in routes]
                        routing_rules[vs_name] = {
                            'type': 'traffic-split',
                            'weights': weights,
                            'hosts': hosts
                        }
                    elif routes:
                        routing_rules[vs_name] = {
                            'type': 'standard',
                            'hosts': hosts
                        }
        except json.JSONDecodeError:
            pass
    
    output = f"Traffic relationship analysis:\n"
    output += f"  Services with detected dependencies: {len(service_relationships)}\n"
    
    if service_relationships:
        sample_deps = list(service_relationships.items())[:3]
        for svc, deps in sample_deps:
            output += f"    {svc} -> {', '.join(list(deps)[:3])}\n"
    
    output += f"  Virtual Services with routing rules: {len(routing_rules)}"
    
    if routing_rules:
        traffic_splits = [k for k, v in routing_rules.items() if v['type'] == 'traffic-split']
        if traffic_splits:
            output += f"\n  Traffic splitting detected: {', '.join(traffic_splits[:3])}"
    
    tests.append(create_test_result(
        "traffic_relationships",
        description,
        True,
        output,
        "INFO"
    ))
    
    return tests

def check_circuit_breakers_and_outliers() -> List[Dict[str, Any]]:
    """Check circuit breaker and outlier detection configurations."""
    description = "Circuit breaker and outlier detection analysis"
    tests: List[Dict[str, Any]] = []
    
    # Check DestinationRules for circuit breakers
    cmd = "kubectl get destinationrules --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    circuit_breakers = []
    outlier_configs = []
    
    if ok(r) and r['stdout']:
        try:
            dr_data = json.loads(r['stdout'])
            for dr in dr_data.get('items', []):
                dr_name = dr.get('metadata', {}).get('name', 'unknown')
                dr_namespace = dr.get('metadata', {}).get('namespace', 'unknown')
                
                # Check for circuit breaker config
                traffic_policy = dr.get('spec', {}).get('trafficPolicy', {})
                connection_pool = traffic_policy.get('connectionPool', {})
                
                if connection_pool:
                    tcp = connection_pool.get('tcp', {})
                    http = connection_pool.get('http', {})
                    
                    if tcp.get('maxConnections') or http.get('http1MaxPendingRequests'):
                        circuit_breakers.append(f"{dr_namespace}/{dr_name}")
                
                # Check for outlier detection
                outlier = traffic_policy.get('outlierDetection', {})
                if outlier:
                    outlier_configs.append({
                        'name': f"{dr_namespace}/{dr_name}",
                        'consecutive_errors': outlier.get('consecutiveErrors', 'default'),
                        'interval': outlier.get('interval', 'default'),
                        'ejection_time': outlier.get('baseEjectionTime', 'default')
                    })
        except json.JSONDecodeError:
            pass
    
    output = f"Resilience patterns:\n"
    output += f"  Circuit breakers configured: {len(circuit_breakers)}\n"
    if circuit_breakers:
        output += f"    Examples: {', '.join(circuit_breakers[:3])}\n"
    
    output += f"  Outlier detection configured: {len(outlier_configs)}"
    if outlier_configs:
        output += f"\n    Example: {outlier_configs[0]['name']} "
        output += f"(errors: {outlier_configs[0]['consecutive_errors']})"
    
    tests.append(create_test_result(
        "resilience_patterns",
        description,
        True,
        output,
        "INFO"
    ))
    
    return tests

def analyze_traffic_policies() -> List[Dict[str, Any]]:
    """Analyze traffic management policies."""
    description = "Traffic management policy analysis"
    tests: List[Dict[str, Any]] = []
    
    policies = {
        'retry': [],
        'timeout': [],
        'fault_injection': [],
        'load_balancing': []
    }
    
    # Analyze VirtualServices for traffic policies
    cmd = "kubectl get virtualservices --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    if ok(r) and r['stdout']:
        try:
            vs_data = json.loads(r['stdout'])
            for vs in vs_data.get('items', []):
                vs_name = vs.get('metadata', {}).get('name', 'unknown')
                vs_namespace = vs.get('metadata', {}).get('namespace', 'unknown')
                
                http_rules = vs.get('spec', {}).get('http', [])
                for rule in http_rules:
                    # Check for retry policies
                    if rule.get('retries'):
                        policies['retry'].append(f"{vs_namespace}/{vs_name}")
                    
                    # Check for timeout policies
                    if rule.get('timeout'):
                        policies['timeout'].append(f"{vs_namespace}/{vs_name}")
                    
                    # Check for fault injection
                    if rule.get('fault'):
                        policies['fault_injection'].append(f"{vs_namespace}/{vs_name}")
        except json.JSONDecodeError:
            pass
    
    # Check DestinationRules for load balancing
    cmd = "kubectl get destinationrules --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    if ok(r) and r['stdout']:
        try:
            dr_data = json.loads(r['stdout'])
            for dr in dr_data.get('items', []):
                dr_name = dr.get('metadata', {}).get('name', 'unknown')
                dr_namespace = dr.get('metadata', {}).get('namespace', 'unknown')
                
                lb_policy = dr.get('spec', {}).get('trafficPolicy', {}).get('loadBalancer', {})
                if lb_policy:
                    lb_type = lb_policy.get('simple', 'UNKNOWN')
                    policies['load_balancing'].append(f"{dr_namespace}/{dr_name} ({lb_type})")
        except json.JSONDecodeError:
            pass
    
    output = f"Traffic policies configured:\n"
    output += f"  Retry policies: {len(policies['retry'])}\n"
    output += f"  Timeout policies: {len(policies['timeout'])}\n"
    output += f"  Fault injection: {len(policies['fault_injection'])}\n"
    output += f"  Custom load balancing: {len(policies['load_balancing'])}"
    
    if any(policies.values()):
        output += "\n  Policy examples:"
        for policy_type, items in policies.items():
            if items:
                output += f"\n    {policy_type}: {items[0]}"
    
    tests.append(create_test_result(
        "traffic_policies",
        description,
        True,
        output,
        "INFO"
    ))
    
    return tests

# ------------------------------------------------------------
# Advanced Diagnostics
# ------------------------------------------------------------

def check_envoy_listeners_and_routes() -> List[Dict[str, Any]]:
    """Deep dive into Envoy listener and route configurations."""
    description = "Envoy listener and route configuration analysis"
    tests: List[Dict[str, Any]] = []
    
    # Sample a proxy for detailed analysis
    cmd = "istioctl proxy-status --all-namespaces 2>&1 | grep -v NAME | head -1 | awk '{print $1}'"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) or not r['stdout']:
        return tests
    
    sample_proxy = r['stdout'].strip()
    
    # Analyze listeners
    cmd = f"istioctl proxy-config listeners {sample_proxy} 2>&1 | wc -l"
    r = run_command(cmd, timeout=10)
    listener_count = 0
    if ok(r) and r['stdout'].isdigit():
        listener_count = int(r['stdout']) - 1  # Subtract header
    
    # Analyze routes
    cmd = f"istioctl proxy-config routes {sample_proxy} 2>&1 | wc -l"
    r = run_command(cmd, timeout=10)
    route_count = 0
    if ok(r) and r['stdout'].isdigit():
        route_count = int(r['stdout']) - 1  # Subtract header
    
    # Analyze clusters
    cmd = f"istioctl proxy-config clusters {sample_proxy} 2>&1 | wc -l"
    r = run_command(cmd, timeout=10)
    cluster_count = 0
    if ok(r) and r['stdout'].isdigit():
        cluster_count = int(r['stdout']) - 1  # Subtract header
    
    # Check for specific listener issues
    cmd = f"istioctl proxy-config listeners {sample_proxy} 2>&1 | grep -E 'INVALID|ERROR' | wc -l"
    r = run_command(cmd, timeout=10)
    invalid_listeners = 0
    if ok(r) and r['stdout'].isdigit():
        invalid_listeners = int(r['stdout'])
    
    output = f"Envoy configuration depth (sample: {sample_proxy[:30]}):\n"
    output += f"  Listeners: {listener_count}\n"
    output += f"  Routes: {route_count}\n"
    output += f"  Clusters: {cluster_count}\n"
    output += f"  Invalid listeners: {invalid_listeners}"
    
    tests.append(create_test_result(
        "envoy_config_depth",
        description,
        invalid_listeners == 0,
        output,
        "WARNING" if invalid_listeners > 0 else "INFO"
    ))
    
    # Check for blackhole clusters (misconfiguration indicator)
    cmd = f"istioctl proxy-config cluster {sample_proxy} 2>&1 | grep -i blackhole | wc -l"
    r = run_command(cmd, timeout=10)
    blackhole_count = 0
    if ok(r) and r['stdout'].isdigit():
        blackhole_count = int(r['stdout'])
    
    if blackhole_count > 0:
        tests.append(create_test_result(
            "blackhole_clusters",
            "Check for blackhole cluster configurations",
            False,
            f"Found {blackhole_count} blackhole cluster(s) - may indicate misconfiguration",
            "WARNING"
        ))
    
    return tests

def analyze_envoy_metrics() -> List[Dict[str, Any]]:
    """Analyze Envoy metrics for performance issues."""
    description = "Envoy performance metrics analysis"
    tests: List[Dict[str, Any]] = []
    
    # Sample a few proxies for metrics
    cmd = "istioctl proxy-status --all-namespaces 2>&1 | grep -v NAME | head -3 | awk '{print $1}'"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) or not r['stdout']:
        return tests
    
    sample_proxies = r['stdout'].split('\n')
    
    metrics_summary = {
        'high_memory': [],
        'high_connections': [],
        'circuit_breaker_trips': [],
        'retry_overflow': []
    }
    
    for proxy in sample_proxies:
        if not proxy:
            continue
        
        # Check memory usage
        cmd = f"istioctl proxy-config stats {proxy} 2>&1 | grep 'memory_allocated' | head -1"
        r = run_command(cmd, timeout=10)
        if ok(r) and r['stdout']:
            try:
                memory_line = r['stdout']
                if ':' in memory_line:
                    memory_value = int(memory_line.split(':')[-1].strip())
                    if memory_value > 100000000:  # 100MB threshold
                        metrics_summary['high_memory'].append(proxy[:30])
            except (ValueError, IndexError):
                pass
        
        # Check active connections
        cmd = f"istioctl proxy-config stats {proxy} 2>&1 | grep 'connections_active' | head -1"
        r = run_command(cmd, timeout=10)
        if ok(r) and r['stdout']:
            try:
                conn_line = r['stdout']
                if ':' in conn_line:
                    conn_value = int(conn_line.split(':')[-1].strip())
                    if conn_value > 1000:  # High connection threshold
                        metrics_summary['high_connections'].append(proxy[:30])
            except (ValueError, IndexError):
                pass
        
        # Check for circuit breaker trips
        cmd = f"istioctl proxy-config stats {proxy} 2>&1 | grep 'circuit_breakers.*tripped' | wc -l"
        r = run_command(cmd, timeout=10)
        if ok(r) and r['stdout'].isdigit():
            if int(r['stdout']) > 0:
                metrics_summary['circuit_breaker_trips'].append(proxy[:30])
    
    output = f"Envoy metrics analysis (sampled {len(sample_proxies)} proxies):\n"
    output += f"  High memory usage: {len(metrics_summary['high_memory'])}\n"
    output += f"  High connection count: {len(metrics_summary['high_connections'])}\n"
    output += f"  Circuit breaker trips: {len(metrics_summary['circuit_breaker_trips'])}"
    
    has_issues = any(metrics_summary.values())
    
    tests.append(create_test_result(
        "envoy_metrics",
        description,
        not has_issues,
        output,
        "WARNING" if has_issues else "INFO"
    ))
    
    return tests

def check_gateway_configuration() -> List[Dict[str, Any]]:
    """Deep analysis of gateway configurations."""
    description = "Gateway configuration and exposure analysis"
    tests: List[Dict[str, Any]] = []
    
    # Get all gateways
    cmd = "kubectl get gateways --all-namespaces -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    gateway_configs = []
    exposed_hosts = set()
    tls_configs = []
    
    if ok(r) and r['stdout']:
        try:
            gw_data = json.loads(r['stdout'])
            for gw in gw_data.get('items', []):
                gw_name = gw.get('metadata', {}).get('name', 'unknown')
                gw_namespace = gw.get('metadata', {}).get('namespace', 'unknown')
                
                servers = gw.get('spec', {}).get('servers', [])
                for server in servers:
                    hosts = server.get('hosts', [])
                    exposed_hosts.update(hosts)
                    
                    port = server.get('port', {})
                    protocol = port.get('protocol', 'HTTP')
                    
                    if protocol in ['HTTPS', 'TLS']:
                        tls = server.get('tls', {})
                        tls_configs.append({
                            'gateway': f"{gw_namespace}/{gw_name}",
                            'mode': tls.get('mode', 'SIMPLE'),
                            'hosts': hosts
                        })
                    
                    gateway_configs.append({
                        'name': f"{gw_namespace}/{gw_name}",
                        'protocol': protocol,
                        'port': port.get('number', 'unknown'),
                        'hosts': hosts
                    })
        except json.JSONDecodeError:
            pass
    
    # Check for wildcard hosts (security concern)
    wildcard_hosts = [h for h in exposed_hosts if '*' in h]
    
    output = f"Gateway analysis:\n"
    output += f"  Total gateways: {len(set(gc['name'] for gc in gateway_configs))}\n"
    output += f"  Exposed hosts: {len(exposed_hosts)}\n"
    output += f"  TLS configurations: {len(tls_configs)}\n"
    
    if wildcard_hosts:
        output += f"  ⚠️ Wildcard hosts detected: {', '.join(wildcard_hosts)}\n"
    
    # Check TLS modes
    if tls_configs:
        tls_modes = {}
        for tls in tls_configs:
            mode = tls['mode']
            if mode not in tls_modes:
                tls_modes[mode] = 0
            tls_modes[mode] += 1
        
        output += f"  TLS modes: {', '.join(f'{k}:{v}' for k, v in tls_modes.items())}"
    
    tests.append(create_test_result(
        "gateway_analysis",
        description,
        len(wildcard_hosts) == 0,
        output,
        "WARNING" if wildcard_hosts else "INFO"
    ))
    
    return tests

def analyze_service_mesh_topology() -> List[Dict[str, Any]]:
    """Analyze the overall service mesh topology."""
    description = "Service mesh topology and complexity analysis"
    tests: List[Dict[str, Any]] = []
    
    # Count services with sidecars
    cmd = "kubectl get pods --all-namespaces -o json 2>/dev/null | jq '[.items[] | select(.spec.containers[].name == \"istio-proxy\")] | length'"
    r = run_command(cmd, timeout=20)
    pods_with_sidecars = 0
    if ok(r) and r['stdout'].isdigit():
        pods_with_sidecars = int(r['stdout'])
    
    # Count unique services
    cmd = "kubectl get services --all-namespaces -o json 2>/dev/null | jq '[.items[] | select(.metadata.namespace != \"kube-system\")] | length'"
    r = run_command(cmd, timeout=15)
    total_services = 0
    if ok(r) and r['stdout'].isdigit():
        total_services = int(r['stdout'])
    
    # Analyze namespace distribution
    cmd = "kubectl get pods --all-namespaces -o json 2>/dev/null | jq -r '[.items[] | select(.spec.containers[].name == \"istio-proxy\")] | group_by(.metadata.namespace) | map({namespace: .[0].metadata.namespace, count: length}) | sort_by(.count) | reverse | .[0:5]'"
    r = run_command(cmd, timeout=20)
    
    namespace_distribution = []
    if ok(r) and r['stdout']:
        try:
            namespace_distribution = json.loads(r['stdout'])
        except json.JSONDecodeError:
            pass
    
    # Estimate mesh complexity
    complexity_score = "Low"
    if pods_with_sidecars > 100:
        complexity_score = "High"
    elif pods_with_sidecars > 50:
        complexity_score = "Medium"
    
    output = f"Service mesh topology:\n"
    output += f"  Pods with sidecars: {pods_with_sidecars}\n"
    output += f"  Total services: {total_services}\n"
    output += f"  Mesh complexity: {complexity_score}\n"
    
    if namespace_distribution:
        output += f"  Top namespaces by pod count:\n"
        for ns_info in namespace_distribution[:3]:
            output += f"    {ns_info.get('namespace', 'unknown')}: {ns_info.get('count', 0)} pods\n"
    
    tests.append(create_test_result(
        "mesh_topology",
        description,
        True,
        output.rstrip(),
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
    
    # Run all test suites (including new advanced ones)
    test_suites = [
        ("Version Check", check_istio_version),
        ("Control Plane Health", check_control_plane_health),
        ("Advanced Data Plane Status", check_data_plane_status_advanced),
        ("Per-Envoy Health Check", check_envoy_health_per_proxy),
        ("Traffic Relationships", analyze_traffic_relationships),
        ("Circuit Breakers & Outliers", check_circuit_breakers_and_outliers),
        ("Traffic Policies", analyze_traffic_policies),
        ("Envoy Listeners & Routes", check_envoy_listeners_and_routes),
        ("Envoy Metrics", analyze_envoy_metrics),
        ("Gateway Configuration", check_gateway_configuration),
        ("Service Mesh Topology", analyze_service_mesh_topology),
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
