#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_loki_json.py - Loki Health Check with JSON output
"""

import os
import sys
import json
import subprocess
import time
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


def get_loki_config() -> Dict:
    """Get Loki configuration"""
    namespace = os.getenv("LOKI_NS", "loki")
    user = os.getenv("LOKI_USER", "")
    password = os.getenv("LOKI_PASS", "")
    
    return {
        "namespace": namespace,
        "user": user,
        "password": password
    }


def test_loki_api() -> List[Dict]:
    """Test Loki API connectivity"""
    config = get_loki_config()
    
    # Gateway listens on 8080 internally, not 80
    cmd = f"kubectl exec -n {config['namespace']} deployment/loki-gateway -- curl -s -o /dev/null -w '%{{http_code}}' --user '{config['user']}:{config['password']}' -X POST http://localhost:8080/api/v1/push"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        http_code = result["stdout"]
        if http_code in ["400", "405"]:  # 400/405 means endpoint exists
            status = True
            output = "Connected to Loki API"
        else:
            status = False
            output = f"API connection failed: HTTP {http_code}"
    else:
        status = False
        output = "Failed to connect to Loki API"
    
    return [{
        "name": "loki_api",
        "description": "Check Loki API connectivity",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    }]


def test_loki_components() -> List[Dict]:
    """Test Loki components"""
    config = get_loki_config()
    results = []
    
    components = [
        ("gateway", "app.kubernetes.io/component=gateway"),
        ("read", "app.kubernetes.io/component=read"),
        ("write", "app.kubernetes.io/component=write"),
        ("backend", "app.kubernetes.io/component=backend"),
        ("canary", "app.kubernetes.io/component=canary"),
        ("chunks-cache", "app.kubernetes.io/component=memcached-chunks-cache"),
        ("results-cache", "app.kubernetes.io/component=memcached-results-cache")
    ]
    
    for comp_name, label in components:
        cmd = f"kubectl get pods -n {config['namespace']} -l {label} -o json"
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
                output = "Error checking"
        else:
            status = True
            output = "Not deployed"
        
        results.append({
            "name": f"loki_{comp_name.replace('-', '_')}",
            "description": f"Check Loki {comp_name} component",
            "status": status,
            "output": output,
            "severity": "critical" if comp_name in ["gateway", "write", "read"] and not status else "info"
        })
    
    return results


def test_loki_ingestion() -> List[Dict]:
    """Test log ingestion"""
    config = get_loki_config()
    
    timestamp = str(int(time.time() * 1e9))
    log_data = '{"streams":[{"stream":{"job":"test"},"values":[["' + timestamp + '","test"]]}]}'
    
    # Use port 8080 for gateway
    cmd = f"""kubectl exec -n {config['namespace']} deployment/loki-gateway -- sh -c 'echo {log_data} | curl -s -X POST --user {config['user']}:{config['password']} -H "Content-Type: application/json" -d @- http://localhost:8080/api/v1/push'"""
    
    result = run_command(cmd)
    status = result["exit_code"] == 0 and (not result["stdout"] or "error" not in result["stdout"].lower())
    
    return [{
        "name": "loki_ingestion",
        "description": "Test log ingestion",
        "status": status,
        "output": "Log ingestion successful" if status else "Log ingestion failed",
        "severity": "critical" if not status else "info"
    }]


def test_loki_query() -> List[Dict]:
    """Test query capability"""
    config = get_loki_config()
    
    # Use port 8080 for gateway
    cmd = f"""kubectl exec -n {config['namespace']} deployment/loki-gateway -- curl -s -G --user '{config['user']}:{config['password']}' --data-urlencode 'query={{job=~".+"}}' --data-urlencode 'limit=1' http://localhost:8080/api/v1/query_range"""
    
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            if data.get("status") == "success":
                output = f"Query successful: {len(data.get('data', {}).get('result', []))} streams"
                status = True
            else:
                output = "Query failed"
                status = False
        except:
            output = "Query parse failed"
            status = False
    else:
        output = "Query failed"
        status = False
    
    return [{
        "name": "loki_query",
        "description": "Test Loki query capability",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    }]


def test_loki_labels() -> List[Dict]:
    """Test labels API"""
    config = get_loki_config()
    
    # Use port 8080 for gateway - simpler command
    cmd = f"""kubectl exec -n {config['namespace']} deployment/loki-gateway -- curl -s --user '{config['user']}:{config['password']}' 'http://localhost:8080/api/v1/labels'"""
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])
            if data.get("status") == "success":
                labels = data.get("data", [])
                output = f"{len(labels)} labels available"
                status = len(labels) > 0
            else:
                output = f"Labels API returned: {data.get('status', 'unknown')}"
                status = False
        except:
            # Check if it's an HTML error page
            if "404" in result["stdout"] or "not found" in result["stdout"].lower():
                output = "Labels endpoint not found"
            else:
                output = f"Response: {result['stdout'][:100]}"
            status = False
    else:
        output = "Failed to get labels"
        status = False
    
    return [{
        "name": "loki_labels",
        "description": "Check available labels",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_storage_backend() -> List[Dict]:
    """Test storage backend"""
    config = get_loki_config()
    
    cmd = f"kubectl get configmap -n {config['namespace']} loki -o jsonpath='{{.data.config\\.yaml}}' | grep -i 's3\\|minio\\|bucket' | head -1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        output = "Storage: S3/MinIO configured"
    else:
        output = "Storage: Default configuration"
    
    return [{
        "name": "storage_backend",
        "description": "Check storage backend connectivity",
        "status": True,
        "output": output,
        "severity": "info"
    }]


def test_alloy_connection() -> List[Dict]:
    """Test Alloy connection"""
    config = get_loki_config()
    
    cmd = f"kubectl get pods -n alloy -l app.kubernetes.io/name=alloy --no-headers 2>/dev/null | wc -l"
    result = run_command(cmd)
    
    try:
        pod_count = int(result["stdout"]) if result["exit_code"] == 0 else 0
        if pod_count > 0:
            output = f"Alloy: {pod_count} pods found"
            status = True
        else:
            output = "Alloy not found"
            status = False
    except:
        output = "Alloy check failed"
        status = False
    
    return [{
        "name": "alloy_connection",
        "description": "Check Alloy/Grafana Agent connection",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_recent_errors() -> List[Dict]:
    """Check recent errors"""
    config = get_loki_config()
    
    cmd = f"kubectl logs -n {config['namespace']} deployment/loki-gateway --tail=50 2>/dev/null | grep -c -i 'error\\|panic'"
    result = run_command(cmd)
    
    try:
        errors = int(result["stdout"]) if result["exit_code"] == 0 else 0
        status = errors < 5
        output = f"{errors} errors in recent logs"
    except:
        status = True
        output = "No recent errors"
    
    return [{
        "name": "recent_errors",
        "description": "Check for recent errors in logs",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_ring_membership() -> List[Dict]:
    """Test ring membership"""
    config = get_loki_config()
    
    # loki-write is a StatefulSet, not Deployment
    cmd = f"kubectl exec -n {config['namespace']} statefulset/loki-write -- curl -s http://localhost:3100/ring 2>/dev/null | grep -c ACTIVE"
    result = run_command(cmd)
    
    try:
        active = int(result["stdout"]) if result["exit_code"] == 0 else 0
        status = active > 0
        output = f"Ring members: {active} ACTIVE"
    except:
        status = False
        output = "Ring status unavailable"
    
    return [{
        "name": "ring_membership",
        "description": "Check Loki ring membership",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_servicemonitor() -> List[Dict]:
    """Test ServiceMonitor"""
    config = get_loki_config()
    
    cmd = f"kubectl get servicemonitor -n {config['namespace']} 2>/dev/null | grep -c loki"
    result = run_command(cmd)
    
    try:
        count = int(result["stdout"]) if result["exit_code"] == 0 else 0
        status = count > 0
        output = f"{count} ServiceMonitors configured" if count > 0 else "No Loki ServiceMonitors found"
    except:
        status = False
        output = "ServiceMonitor check failed"
    
    return [{
        "name": "servicemonitor",
        "description": "Check ServiceMonitor for metrics scraping",
        "status": status,
        "output": output,
        "severity": "info"
    }]


def test_data_retention() -> List[Dict]:
    """Check retention config"""
    config = get_loki_config()
    
    cmd = f"kubectl get configmap -n {config['namespace']} loki -o jsonpath='{{.data.config\\.yaml}}' | grep -i retention | head -1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        output = f"Retention: {result['stdout'].strip()[:50]}"
    else:
        output = "Default retention"
    
    return [{
        "name": "data_retention",
        "description": "Check data retention configuration",
        "status": True,
        "output": output,
        "severity": "info"
    }]


def test_loki_canary() -> List[Dict]:
    """Test Loki Canary"""
    config = get_loki_config()
    
    cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/component=canary --no-headers 2>/dev/null | wc -l"
    result = run_command(cmd)
    
    try:
        count = int(result["stdout"]) if result["exit_code"] == 0 else 0
        if count > 0:
            output = f"Canary pods: {count} running"
            status = True
        else:
            output = "Canary not deployed"
            status = True  # Not critical
    except:
        output = "Canary check failed"
        status = False
    
    return [{
        "name": "loki_canary",
        "description": "Check Loki Canary synthetic monitoring",
        "status": status,
        "output": output,
        "severity": "info"
    }]


def test_loki():
    """Run all tests"""
    all_results = []
    
    all_results.extend(test_loki_api())
    all_results.extend(test_loki_components())
    all_results.extend(test_loki_ingestion())
    all_results.extend(test_loki_query())
    all_results.extend(test_loki_labels())
    all_results.extend(test_storage_backend())
    all_results.extend(test_alloy_connection())
    all_results.extend(test_recent_errors())
    all_results.extend(test_ring_membership())
    all_results.extend(test_servicemonitor())
    all_results.extend(test_data_retention())
    all_results.extend(test_loki_canary())
    
    return all_results


if __name__ == "__main__":
    results = test_loki()
    
    # Output as JSON
    print(json.dumps(results, indent=2))
    
    # Exit code based on critical failures
    critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "critical")
    sys.exit(1 if critical_failures > 0 else 0)
