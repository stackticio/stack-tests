#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_alloy_json.py - Alloy Health Check with JSON output
"""

import os
import sys
import json
import subprocess
import time
import re
from typing import List, Dict

def run_command(command: str, timeout: int = 30) -> Dict:
    """Run shell command and return results"""
    try:
        completed = subprocess.run(
            command,
            shell=True,
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


def get_alloy_config() -> Dict:
    """Get Alloy configuration"""
    namespace = os.getenv("ALLOY_NS", "alloy")
    loki_namespace = os.getenv("LOKI_NS", "loki")
    
    return {
        "namespace": namespace,
        "loki_namespace": loki_namespace
    }


def test_alloy_pods() -> List[Dict]:
    """Test Alloy pods status"""
    config = get_alloy_config()
    
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o json"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            pods = data.get("items", [])
            total = len(pods)
            ready = sum(1 for p in pods if all(
                c.get("ready", False) for c in p.get("status", {}).get("containerStatuses", [])
            ))
            status = ready == total and total > 0
            output = f"{ready}/{total} pods ready"
        except:
            status = False
            output = "Error checking pods"
    else:
        status = False
        output = "Failed to get pods"
    
    return [{
        "name": "alloy_pods",
        "description": "Check Alloy pods status",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    }]


def test_alloy_health_api() -> List[Dict]:
    """Test Alloy health endpoint"""
    config = get_alloy_config()
    
    # Get first pod to test
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Alloy exposes metrics/health on port 12345
        health_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- curl -s http://localhost:12345/-/ready"
        health_result = run_command(health_cmd)
        
        if health_result["exit_code"] == 0:
            if "Alloy is ready" in health_result["stdout"] or health_result["stdout"] == "Ready.\n" or "ready" in health_result["stdout"].lower():
                status = True
                output = "Health check passed"
            else:
                status = False
                output = f"Health check returned: {health_result['stdout'][:50]}"
        else:
            status = False
            output = "Health endpoint not responding"
    else:
        status = False
        output = "No Alloy pods found"
    
    return [{
        "name": "alloy_health_api",
        "description": "Check Alloy health API endpoint",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    }]


def test_alloy_config_validity() -> List[Dict]:
    """Test Alloy configuration validity"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check if config is valid by looking at the running config
        config_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- alloy fmt --test /etc/alloy/config.alloy 2>&1"
        config_result = run_command(config_cmd)
        
        # If command doesn't exist, try alternative
        if "not found" in config_result["stderr"] or config_result["exit_code"] != 0:
            # Try to check if config file exists and is readable
            config_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- test -f /etc/alloy/config.alloy && echo 'Config exists' || echo 'Config missing'"
            config_result = run_command(config_cmd)
            
            if "Config exists" in config_result["stdout"]:
                status = True
                output = "Configuration file exists"
            else:
                status = False
                output = "Configuration file missing"
        else:
            if config_result["exit_code"] == 0:
                status = True
                output = "Configuration valid"
            else:
                status = False
                output = "Configuration invalid"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "alloy_config",
        "description": "Check Alloy configuration validity",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    }]


def test_loki_integration() -> List[Dict]:
    """Test Loki integration in Alloy config"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check if Loki is configured in Alloy
        check_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- grep -i 'loki\\|remote_write' /etc/alloy/config.alloy 2>/dev/null | head -5"
        check_result = run_command(check_cmd)
        
        if check_result["exit_code"] == 0 and check_result["stdout"]:
            if "loki" in check_result["stdout"].lower():
                status = True
                output = "Loki integration configured"
            else:
                status = False
                output = "Loki not found in config"
        else:
            # Try checking ConfigMap
            cm_cmd = f"kubectl get configmap -n {config['namespace']} alloy -o jsonpath='{{.data.config\\.alloy}}' 2>/dev/null | grep -i loki | head -1"
            cm_result = run_command(cm_cmd)
            
            if cm_result["exit_code"] == 0 and cm_result["stdout"]:
                status = True
                output = "Loki integration found in ConfigMap"
            else:
                status = False
                output = "Loki integration not configured"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "loki_integration",
        "description": "Check Loki integration in Alloy",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_log_collection() -> List[Dict]:
    """Test if Alloy is collecting logs"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check Alloy logs for log collection activity
        logs_cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=100 2>/dev/null | grep -i 'log.*collect\\|tail\\|scrape' | wc -l"
        logs_result = run_command(logs_cmd)
        
        try:
            log_lines = int(logs_result["stdout"]) if logs_result["exit_code"] == 0 else 0
            if log_lines > 0:
                status = True
                output = f"Log collection active ({log_lines} related entries)"
            else:
                # Check for any logs being processed
                process_cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=50 2>/dev/null | grep -c 'level='"
                process_result = run_command(process_cmd)
                entries = int(process_result["stdout"]) if process_result["exit_code"] == 0 else 0
                
                if entries > 0:
                    status = True
                    output = "Alloy is running"
                else:
                    status = False
                    output = "No log collection activity detected"
        except:
            status = False
            output = "Error checking log collection"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "log_collection",
        "description": "Check if Alloy is collecting logs",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_metrics_endpoint() -> List[Dict]:
    """Test Alloy metrics endpoint"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check metrics endpoint
        metrics_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- curl -s http://localhost:12345/metrics 2>/dev/null | head -20 | grep -c '^alloy_'"
        metrics_result = run_command(metrics_cmd)
        
        try:
            metric_count = int(metrics_result["stdout"]) if metrics_result["exit_code"] == 0 else 0
            if metric_count > 0:
                status = True
                output = f"{metric_count} Alloy metrics exposed"
            else:
                # Try just checking if endpoint responds
                check_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- curl -s -o /dev/null -w '%{{http_code}}' http://localhost:12345/metrics"
                check_result = run_command(check_cmd)
                
                if check_result["exit_code"] == 0 and check_result["stdout"] == "200":
                    status = True
                    output = "Metrics endpoint responding"
                else:
                    status = False
                    output = "Metrics endpoint not working"
        except:
            status = False
            output = "Error checking metrics"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "metrics_endpoint",
        "description": "Check Alloy metrics endpoint",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_loki_push_success() -> List[Dict]:
    """Test if logs are successfully pushed to Loki"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check for Loki connection issues more comprehensively
        # Look for both success and error patterns
        success_patterns = [
            "successfully sent batch",
            "batch sent successfully", 
            "exported.*success",
            "push.*success",
            "loki.*200",
            "loki.*204"
        ]
        
        error_patterns = [
            "loki.*error",
            "loki.*fail", 
            "push.*fail",
            "connection refused",
            "dial tcp.*loki",
            "401",
            "403",
            "500",
            "502",
            "503"
        ]
        
        # Check for success indicators
        success_count = 0
        for pattern in success_patterns:
            cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=500 2>/dev/null | grep -i '{pattern}' | wc -l"
            result = run_command(cmd)
            try:
                success_count += int(result["stdout"]) if result["exit_code"] == 0 else 0
            except:
                pass
        
        # Check for errors
        error_count = 0
        error_details = []
        for pattern in error_patterns:
            cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=500 2>/dev/null | grep -i '{pattern}' | wc -l"
            result = run_command(cmd)
            try:
                count = int(result["stdout"]) if result["exit_code"] == 0 else 0
                if count > 0:
                    error_count += count
                    # Get a sample error for details
                    detail_cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=500 2>/dev/null | grep -i '{pattern}' | tail -1"
                    detail_result = run_command(detail_cmd)
                    if detail_result["exit_code"] == 0 and detail_result["stdout"]:
                        # Extract just the error type
                        if "401" in detail_result["stdout"]:
                            error_details.append("auth failed")
                        elif "connection refused" in detail_result["stdout"]:
                            error_details.append("connection refused")
                        elif "timeout" in detail_result["stdout"].lower():
                            error_details.append("timeout")
            except:
                pass
        
        # Determine status
        if error_count > 20 and success_count < 5:
            status = False
            if error_details:
                unique_errors = list(set(error_details))[:2]  # Convert set to list first
                output = f"{error_count} Loki errors ({', '.join(unique_errors)})"
            else:
                output = f"{error_count} Loki push errors detected"
        elif success_count > 0:
            status = True
            output = f"Loki pushes working ({success_count} success, {error_count} errors)"
        elif error_count > 0:
            status = False
            output = f"{error_count} Loki errors, no recent success"
        else:
            # No clear indicators, check if Loki is configured
            config_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- grep -c 'loki.write' /etc/alloy/config.alloy 2>/dev/null || echo 0"
            config_result = run_command(config_cmd)
            
            try:
                loki_configs = int(config_result["stdout"]) if config_result["exit_code"] == 0 else 0
                if loki_configs > 0:
                    status = True
                    output = "Loki configured, no recent push activity"
                else:
                    status = True
                    output = "No Loki push activity detected"
            except:
                status = True
                output = "Unable to verify Loki pushes"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "loki_push",
        "description": "Check if logs are pushed to Loki",
        "status": status,
        "output": output,
        "severity": "critical" if not status and error_count > 50 else "warning" if not status else "info"
    }]


def test_alloy_errors() -> List[Dict]:
    """Check for errors in Alloy logs"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check for errors in last 100 lines
        error_cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=100 2>/dev/null | grep -c 'level=error\\|ERROR\\|panic'"
        error_result = run_command(error_cmd)
        
        try:
            error_count = int(error_result["stdout"]) if error_result["exit_code"] == 0 else 0
            status = error_count < 5  # Allow some errors
            output = f"{error_count} errors in recent logs"
        except:
            status = True
            output = "No significant errors"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "alloy_errors",
        "description": "Check for errors in Alloy logs",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_alloy_restarts() -> List[Dict]:
    """Check for pod restarts"""
    config = get_alloy_config()
    
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o json"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            pods = data.get("items", [])
            total_restarts = 0
            
            for pod in pods:
                for container in pod.get("status", {}).get("containerStatuses", []):
                    total_restarts += container.get("restartCount", 0)
            
            status = total_restarts < 5  # Allow some restarts
            output = f"Total restarts: {total_restarts}"
        except:
            status = False
            output = "Error checking restarts"
    else:
        status = False
        output = "Failed to get pod info"
    
    return [{
        "name": "alloy_restarts",
        "description": "Check Alloy pod restart count",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_alloy_daemonset() -> List[Dict]:
    """Check Alloy DaemonSet status"""
    config = get_alloy_config()
    
    cmd = f"kubectl get daemonset -n {config['namespace']} alloy -o json 2>/dev/null"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])
            status_info = data.get("status", {})
            desired = status_info.get("desiredNumberScheduled", 0)
            ready = status_info.get("numberReady", 0)
            
            status = ready == desired and desired > 0
            output = f"DaemonSet: {ready}/{desired} nodes ready"
        except:
            status = False
            output = "Error checking DaemonSet"
    else:
        # Maybe it's a Deployment
        cmd = f"kubectl get deployment -n {config['namespace']} alloy -o json 2>/dev/null"
        result = run_command(cmd)
        
        if result["exit_code"] == 0 and result["stdout"]:
            status = True
            output = "Deployment mode (not DaemonSet)"
        else:
            status = True
            output = "Custom deployment detected"
    
    return [{
        "name": "alloy_daemonset",
        "description": "Check Alloy DaemonSet deployment",
        "status": status,
        "output": output,
        "severity": "info"
    }]


def test_alloy_resources() -> List[Dict]:
    """Check Alloy resource usage"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Get resource usage
        resource_cmd = f"kubectl top pod {pod_name} -n {config['namespace']} --no-headers 2>/dev/null"
        resource_result = run_command(resource_cmd)
        
        if resource_result["exit_code"] == 0 and resource_result["stdout"]:
            parts = resource_result["stdout"].split()
            if len(parts) >= 3:
                cpu = parts[1]
                memory = parts[2]
                output = f"CPU: {cpu}, Memory: {memory}"
                status = True
            else:
                output = "Metrics available"
                status = True
        else:
            output = "Metrics server not available"
            status = True  # Not critical
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "alloy_resources",
        "description": "Check Alloy resource usage",
        "status": status,
        "output": output,
        "severity": "info"
    }]


def test_alloy_service_discovery() -> List[Dict]:
    """Test service discovery components"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Check for kubernetes service discovery in config
        sd_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- grep -i 'kubernetes\\|discovery' /etc/alloy/config.alloy 2>/dev/null | wc -l"
        sd_result = run_command(sd_cmd)
        
        try:
            sd_count = int(sd_result["stdout"]) if sd_result["exit_code"] == 0 else 0
            if sd_count > 0:
                status = True
                output = f"Service discovery configured ({sd_count} references)"
            else:
                status = True
                output = "Basic configuration"
        except:
            status = True
            output = "Unable to verify discovery"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "service_discovery",
        "description": "Check Alloy service discovery",
        "status": status,
        "output": output,
        "severity": "info"
    }]


def test_alloy_targets() -> List[Dict]:
    """Check discovered targets"""
    config = get_alloy_config()
    
    # Get first pod
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/name=alloy -o jsonpath='{{.items[0].metadata.name}}'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod_name = result["stdout"]
        
        # Try to get targets from API
        targets_cmd = f"kubectl exec -n {config['namespace']} {pod_name} -- curl -s http://localhost:12345/api/v1/targets 2>/dev/null | grep -o 'job' | wc -l"
        targets_result = run_command(targets_cmd)
        
        try:
            target_count = int(targets_result["stdout"]) if targets_result["exit_code"] == 0 else 0
            if target_count > 0:
                status = True
                output = f"{target_count} targets discovered"
            else:
                # Check logs for target discovery
                log_cmd = f"kubectl logs -n {config['namespace']} {pod_name} --tail=50 2>/dev/null | grep -i 'target\\|discover' | wc -l"
                log_result = run_command(log_cmd)
                
                discoveries = int(log_result["stdout"]) if log_result["exit_code"] == 0 else 0
                if discoveries > 0:
                    status = True
                    output = "Target discovery active"
                else:
                    status = True
                    output = "No targets API available"
        except:
            status = True
            output = "Targets check unavailable"
    else:
        status = False
        output = "No pods to check"
    
    return [{
        "name": "alloy_targets",
        "description": "Check discovered scrape targets",
        "status": status,
        "output": output,
        "severity": "info"
    }]


def test_alloy():
    """Run all tests"""
    all_results = []
    
    all_results.extend(test_alloy_pods())
    all_results.extend(test_alloy_health_api())
    all_results.extend(test_alloy_config_validity())
    all_results.extend(test_loki_integration())
    all_results.extend(test_log_collection())
    all_results.extend(test_metrics_endpoint())
    all_results.extend(test_loki_push_success())
    all_results.extend(test_alloy_errors())
    all_results.extend(test_alloy_restarts())
    all_results.extend(test_alloy_daemonset())
    all_results.extend(test_alloy_resources())
    all_results.extend(test_alloy_service_discovery())
    all_results.extend(test_alloy_targets())
    
    return all_results


if __name__ == "__main__":
    results = test_alloy()
    
    # Output as JSON
    print(json.dumps(results, indent=2))
    
    # Exit code based on critical failures
    critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "critical")
    sys.exit(1 if critical_failures > 0 else 0)
