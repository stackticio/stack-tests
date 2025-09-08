#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSearch Health Testing Script - Working Version
Uses actual ENV variables and confirmed working connection
"""

import os
import json
import subprocess
import re
import sys
from typing import Dict, List, Any

# Use YOUR ACTUAL ENV variables
NAMESPACE = os.getenv('OPENSEARCH_NS', 'opensearch')
OPENSEARCH_HOST = os.getenv('OPENSEARCH_HOST', 'opensearch.opensearch.svc.cluster.local')
OPENSEARCH_PORT = os.getenv('OPENSEARCH_PORT', '9200')
OPENSEARCH_ADMIN_PASSWORD = os.getenv('OPENSEARCH_ADMIN_PASSWORD', 'password_Default1A')
LOG_TIME_WINDOW = os.getenv('OPENSEARCH_LOG_TIME_WINDOW', '5m')

# Since OPENSEARCH_HOST is set to opensearch.opensearch.svc.cluster.local
# but the actual service is opensearch-cluster-master, we need to use the correct one
OPENSEARCH_SERVICE_HOST = f"opensearch-cluster-master.{NAMESPACE}.svc.cluster.local"
DASHBOARD_HOST = f"opensearch-dashboard-opensearch-dashboards.{NAMESPACE}.svc.cluster.local"

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

def test_opensearch_connectivity() -> List[Dict[str, Any]]:
    """Test OpenSearch API connectivity"""
    description = "Test OpenSearch API connectivity"
    
    # Use the confirmed working connection string
    url = f"https://{OPENSEARCH_SERVICE_HOST}:{OPENSEARCH_PORT}/"
    command = f"curl -s -k -u admin:{OPENSEARCH_ADMIN_PASSWORD} -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 300:
            output = f"OpenSearch API is accessible via HTTPS (HTTP {http_code})"
            return [create_test_result("opensearch_api_connectivity", description, True, output, "info")]
    
    output = f"OpenSearch API connectivity failed (HTTP {http_code if http_code else 'no response'})"
    return [create_test_result("opensearch_api_connectivity", description, False, output, "critical")]

def test_opensearch_cluster_health() -> List[Dict[str, Any]]:
    """Test OpenSearch cluster health"""
    description = "Test OpenSearch cluster health"
    
    # Use the confirmed working connection string
    url = f"https://{OPENSEARCH_SERVICE_HOST}:{OPENSEARCH_PORT}/_cluster/health"
    command = f"curl -s -k -u admin:{OPENSEARCH_ADMIN_PASSWORD} --connect-timeout 5 {url}"
    result = run_command(command)
    
    if result['stdout'] and '{' in result['stdout']:
        try:
            health_data = json.loads(result['stdout'])
            cluster_status = health_data.get('status', 'unknown')
            cluster_name = health_data.get('cluster_name', 'unknown')
            node_count = health_data.get('number_of_nodes', 0)
            active_shards = health_data.get('active_shards', 0)
            unassigned_shards = health_data.get('unassigned_shards', 0)
            
            if cluster_status == 'green':
                output = f"Cluster '{cluster_name}' is healthy (status: green, nodes: {node_count}, shards: {active_shards})"
                return [create_test_result("opensearch_cluster_health", description, True, output, "info")]
            elif cluster_status == 'yellow':
                output = f"Cluster '{cluster_name}' operational with warnings (status: yellow, nodes: {node_count}, unassigned: {unassigned_shards})"
                return [create_test_result("opensearch_cluster_health", description, True, output, "warning")]
            elif cluster_status == 'red':
                output = f"Cluster '{cluster_name}' has critical issues (status: red, nodes: {node_count})"
                return [create_test_result("opensearch_cluster_health", description, False, output, "critical")]
        except json.JSONDecodeError:
            pass
    
    output = "Could not retrieve cluster health status"
    return [create_test_result("opensearch_cluster_health", description, False, output, "critical")]

def test_opensearch_pods() -> List[Dict[str, Any]]:
    """Check OpenSearch pod status"""
    results = []
    
    # Check OpenSearch pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=opensearch' -o json"
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
                output = f"All {total_pods} OpenSearch pods are ready"
                severity = "info"
                passed = True
            elif ready_pods > 0:
                output = f"OpenSearch pods: {ready_pods}/{total_pods} ready"
                if not_ready:
                    output += f" (Not ready: {', '.join(not_ready)})"
                severity = "warning"
                passed = False
            else:
                output = f"No OpenSearch pods are ready ({total_pods} total)"
                severity = "critical"
                passed = False
            
            results.append(create_test_result("opensearch_pods_status", "Check OpenSearch pod status", 
                                             passed, output, severity))
        except json.JSONDecodeError:
            results.append(create_test_result("opensearch_pods_status", "Check OpenSearch pod status",
                                             False, "Failed to parse pod data", "warning"))
    
    # Check Dashboard pods
    command = f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=opensearch-dashboards' -o json"
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
                output = f"Dashboard pods: {ready_pods}/{total_pods} ready"
                passed = True
                severity = "info"
            else:
                output = f"Dashboard pods: {ready_pods}/{total_pods} ready"
                passed = False
                severity = "warning"
            
            results.append(create_test_result("opensearch_dashboard_pods", "Check Dashboard pod status",
                                             passed, output, severity))
        except json.JSONDecodeError:
            pass
    
    return results

def test_opensearch_indices() -> List[Dict[str, Any]]:
    """Check OpenSearch indices"""
    description = "Check OpenSearch indices status"
    
    url = f"https://{OPENSEARCH_SERVICE_HOST}:{OPENSEARCH_PORT}/_cat/indices?format=json"
    command = f"curl -s -k -u admin:{OPENSEARCH_ADMIN_PASSWORD} --connect-timeout 5 {url}"
    result = run_command(command)
    
    if result['stdout'] and '[' in result['stdout']:
        try:
            indices = json.loads(result['stdout'])
            total = len(indices)
            
            green = sum(1 for idx in indices if idx.get('health') == 'green')
            yellow = sum(1 for idx in indices if idx.get('health') == 'yellow')
            red = sum(1 for idx in indices if idx.get('health') == 'red')
            
            if red > 0:
                output = f"Indices: {total} total (Green: {green}, Yellow: {yellow}, Red: {red})"
                return [create_test_result("opensearch_indices", description, False, output, "critical")]
            elif yellow > 0:
                output = f"Indices: {total} total (Green: {green}, Yellow: {yellow})"
                return [create_test_result("opensearch_indices", description, True, output, "warning")]
            elif total > 0:
                output = f"All {total} indices are healthy (green)"
                return [create_test_result("opensearch_indices", description, True, output, "info")]
            else:
                output = "No indices found (empty cluster)"
                return [create_test_result("opensearch_indices", description, True, output, "info")]
        except json.JSONDecodeError:
            pass
    
    output = "Could not retrieve indices information"
    return [create_test_result("opensearch_indices", description, False, output, "warning")]

def test_opensearch_nodes() -> List[Dict[str, Any]]:
    """Test OpenSearch nodes status"""
    description = "Test OpenSearch nodes status"
    
    url = f"https://{OPENSEARCH_SERVICE_HOST}:{OPENSEARCH_PORT}/_nodes/stats"
    command = f"curl -s -k -u admin:{OPENSEARCH_ADMIN_PASSWORD} --connect-timeout 5 {url}"
    result = run_command(command)
    
    if result['stdout'] and '{' in result['stdout']:
        try:
            nodes_data = json.loads(result['stdout'])
            total_nodes = nodes_data.get('_nodes', {}).get('total', 0)
            successful_nodes = nodes_data.get('_nodes', {}).get('successful', 0)
            failed_nodes = nodes_data.get('_nodes', {}).get('failed', 0)
            
            passed = total_nodes > 0 and failed_nodes == 0
            severity = "info" if passed else ("warning" if failed_nodes < total_nodes else "critical")
            
            output = f"Total nodes: {total_nodes}, Successful: {successful_nodes}, Failed: {failed_nodes}"
            
            return [create_test_result("opensearch_nodes_status", description, passed, output, severity)]
        except json.JSONDecodeError:
            return [create_test_result("opensearch_nodes_status", description, False, 
                                     "Failed to parse nodes response", "warning")]
    else:
        return [create_test_result("opensearch_nodes_status", description, False,
                                 "Could not retrieve nodes information", "warning")]

def test_opensearch_logs() -> List[Dict[str, Any]]:
    """Check OpenSearch logs for errors"""
    results = []
    
    command = f"kubectl get pods -n {NAMESPACE} -l 'app.kubernetes.io/name=opensearch' -o jsonpath='{{.items[*].metadata.name}}'"
    pod_result = run_command(command)
    
    if pod_result['exit_code'] == 0 and pod_result['stdout']:
        pod_names = pod_result['stdout'].split()
        
        for pod_name in pod_names:
            if not pod_name:
                continue
            
            command = f"kubectl logs -n {NAMESPACE} {pod_name} --since={LOG_TIME_WINDOW} 2>&1 | grep -iE 'error|exception|fatal' | grep -v 'deprecation' | wc -l"
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
                
                results.append(create_test_result(f"opensearch_logs_{pod_name}", 
                                                f"Check logs for {pod_name}",
                                                passed, output, severity))
    
    if not results:
        results.append(create_test_result("opensearch_logs", "Check OpenSearch logs",
                                         False, "Could not check logs", "warning"))
    
    return results

def test_opensearch_dashboard() -> List[Dict[str, Any]]:
    """Test Dashboard connectivity"""
    description = "Test OpenSearch Dashboard connectivity"
    
    url = f"http://{DASHBOARD_HOST}:5601/api/status"
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 {url}"
    result = run_command(command)
    
    http_code = result['stdout'].strip()
    
    if http_code and http_code.isdigit():
        code = int(http_code)
        if 200 <= code < 500:
            output = f"Dashboard is accessible (HTTP {http_code})"
            passed = code < 400
            severity = "info" if passed else "warning"
            return [create_test_result("opensearch_dashboard", description, passed, output, severity)]
    
    output = "Dashboard is not accessible"
    return [create_test_result("opensearch_dashboard", description, False, output, "warning")]

def test_opensearch() -> List[Dict[str, Any]]:
    """Run all OpenSearch tests"""
    results = []
    
    # Basic connectivity
    results.extend(test_opensearch_connectivity())
    results.extend(test_opensearch_cluster_health())
    
    # Infrastructure
    results.extend(test_opensearch_nodes())
    results.extend(test_opensearch_pods())
    
    # Data
    results.extend(test_opensearch_indices())
    
    # Logs
    results.extend(test_opensearch_logs())
    
    # Dashboard
    results.extend(test_opensearch_dashboard())
    
    return results

def main():
    """Main entry point"""
    try:
        results = test_opensearch()
        print(json.dumps(results, indent=2))
        
        # Exit with error if any critical failures
        critical_failures = [r for r in results if not r['status'] and r.get('severity') == 'critical']
        return 1 if critical_failures else 0
    except Exception as e:
        error_result = [{
            "name": "opensearch_test_error",
            "description": "OpenSearch test script error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        return 1

if __name__ == "__main__":
    sys.exit(main())
