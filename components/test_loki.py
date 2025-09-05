#!/usr/bin/env python3
"""
test_loki.py - Comprehensive Loki Stack Testing Script
Tests Loki connectivity, ingestion, querying, components, and overall health
"""

import os
import json
import subprocess
import time
import base64
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import uuid

def run_command(command: str, env: Dict = None, timeout: int = 30) -> Dict:
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


def get_loki_config() -> Dict:
    """Get Loki configuration from environment variables"""
    return {
        "namespace": os.getenv("LOKI_NS", os.getenv("LOKI_NAMESPACE", "loki")),
        "host": os.getenv("LOKI_HOST", "loki-gateway.loki.svc.cluster.local"),
        "port": os.getenv("LOKI_PORT", "3100"),
        "user": os.getenv("LOKI_USER", ""),
        "password": os.getenv("LOKI_PASS", "")
    }


def get_loki_gateway_pod() -> Optional[str]:
    """Get Loki gateway pod for API access"""
    config = get_loki_config()
    namespace = config["namespace"]
    
    # Try to find gateway pod
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/component=gateway --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    # Fallback: look for any loki-gateway pod
    cmd = f"kubectl get pods -n {namespace} --no-headers 2>/dev/null | grep 'loki-gateway' | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    return None


def get_auth_header() -> str:
    """Generate basic auth header if credentials are provided"""
    config = get_loki_config()
    if config["user"] and config["password"]:
        credentials = f"{config['user']}:{config['password']}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"-H 'Authorization: Basic {encoded}'"
    return ""


def test_loki_connectivity() -> List[Dict]:
    """Test basic Loki connectivity through gateway"""
    config = get_loki_config()
    namespace = config["namespace"]
    pod = get_loki_gateway_pod()
    
    if not pod:
        return [{
            "name": "loki_connectivity",
            "status": False,
            "output": f"No Loki gateway pod found in namespace {namespace}",
            "severity": "CRITICAL"
        }]
    
    auth = get_auth_header()
    
    # Test Loki ready endpoint
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' {auth} http://localhost:{config['port']}/ready 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    http_code = result["stdout"] if result["exit_code"] == 0 else "000"
    status = http_code == "200"
    
    output = f"Using pod: {pod}\n"
    output += f"Ready endpoint: HTTP {http_code}"
    
    # Also test metrics endpoint
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{config['port']}/metrics 2>/dev/null | head -1"
    metrics_result = run_command(cmd, timeout=5)
    
    if metrics_result["exit_code"] == 0:
        metrics_code = metrics_result["stdout"][:3] if metrics_result["stdout"] else "000"
        output += f"\nMetrics endpoint: HTTP {metrics_code}"
    
    return [{
        "name": "loki_connectivity",
        "status": status,
        "output": output.strip(),
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_loki_components() -> List[Dict]:
    """Test all Loki distributed components"""
    config = get_loki_config()
    namespace = config["namespace"]
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
        cmd = f"kubectl get pods -n {namespace} -l {label} --no-headers 2>/dev/null"
        result = run_command(cmd, timeout=5)
        
        if result["exit_code"] == 0 and result["stdout"]:
            lines = [l for l in result["stdout"].split("\n") if l.strip()]
            total = len(lines)
            running = sum(1 for l in lines if "Running" in l)
            ready = sum(1 for l in lines if all(x in l for x in ["Running", "/"]) and l.split()[1].split("/")[0] == l.split()[1].split("/")[1])
            
            status = ready == total and total > 0
            output = f"loki-{comp_name}: {ready}/{total} ready"
            
            # Add pod names for critical components
            if comp_name in ["read", "write", "backend"] and not status:
                not_ready = [l.split()[0] for l in lines if "Running" not in l or l.split()[1].split("/")[0] != l.split()[1].split("/")[1]]
                if not_ready:
                    output += f" (Not ready: {', '.join(not_ready[:2])})"
            
            severity = "CRITICAL" if comp_name in ["gateway", "write", "read"] and not status else "WARNING"
        else:
            # Component might not be deployed (like in simpler setups)
            status = True
            output = f"loki-{comp_name}: Not deployed"
            severity = "INFO"
        
        results.append({
            "name": f"loki_component_{comp_name.replace('-', '_')}",
            "status": status,
            "output": output,
            "severity": severity if not status else "INFO"
        })
    
    return results


def test_loki_ingestion() -> List[Dict]:
    """Test log ingestion capability"""
    config = get_loki_config()
    namespace = config["namespace"]
    pod = get_loki_gateway_pod()
    
    if not pod:
        return [{
            "name": "loki_ingestion",
            "status": False,
            "output": "No Loki gateway pod available",
            "severity": "CRITICAL"
        }]
    
    auth = get_auth_header()
    
    # Create a test log entry
    timestamp = str(int(time.time() * 1e9))  # nanoseconds
    test_id = str(uuid.uuid4())
    log_data = json.dumps({
        "streams": [{
            "stream": {
                "job": "test",
                "test_id": test_id
            },
            "values": [
                [timestamp, f"Test log message {test_id}"]
            ]
        }]
    })
    
    # Push log to Loki
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -X POST {auth} " \
          f"-H 'Content-Type: application/json' " \
          f"-d '{log_data}' " \
          f"http://localhost:{config['port']}/loki/api/v1/push 2>/dev/null"
    
    result = run_command(cmd, timeout=10)
    
    # Check if push was successful (204 No Content is success)
    status = result["exit_code"] == 0 and (result["stdout"] == "" or "error" not in result["stdout"].lower())
    
    output = f"Log ingestion test: {'✓ Success' if status else '✗ Failed'}"
    
    if not status and result["stdout"]:
        # Parse error if available
        try:
            error_data = json.loads(result["stdout"])
            error_msg = error_data.get("error", "Unknown error")
            output += f"\n  Error: {error_msg[:100]}"
        except:
            output += f"\n  Response: {result['stdout'][:100]}"
    
    return [{
        "name": "loki_ingestion",
        "status": status,
        "output": output,
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_loki_query() -> List[Dict]:
    """Test Loki query capability"""
    config = get_loki_config()
    namespace = config["namespace"]
    pod = get_loki_gateway_pod()
    
    if not pod:
        return [{
            "name": "loki_query",
            "status": False,
            "output": "No Loki gateway pod available",
            "severity": "CRITICAL"
        }]
    
    auth = get_auth_header()
    
    # Query for recent logs (last hour)
    query = '{job=~".+"}'
    encoded_query = urllib.parse.quote(query)
    
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -G {auth} " \
          f"--data-urlencode 'query={query}' " \
          f"--data-urlencode 'limit=10' " \
          f"http://localhost:{config['port']}/loki/api/v1/query_range 2>/dev/null"
    
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "loki_query",
            "status": False,
            "output": "Failed to execute query",
            "severity": "CRITICAL"
        }]
    
    try:
        data = json.loads(result["stdout"])
        status_str = data.get("status", "")
        
        if status_str == "success":
            streams = data.get("data", {}).get("result", [])
            total_entries = sum(len(s.get("values", [])) for s in streams)
            unique_labels = set()
            
            for stream in streams:
                labels = stream.get("stream", {})
                for key in labels:
                    unique_labels.add(key)
            
            output = f"Query test: ✓ Success\n"
            output += f"  Streams found: {len(streams)}\n"
            output += f"  Log entries: {total_entries}\n"
            output += f"  Unique labels: {', '.join(sorted(list(unique_labels)[:5]))}"
            
            status = True
        else:
            error = data.get("error", "Unknown error")
            output = f"Query test: ✗ Failed\n  Error: {error}"
            status = False
            
    except Exception as e:
        output = f"Query test: ✗ Failed to parse response"
        status = False
    
    return [{
        "name": "loki_query",
        "status": status,
        "output": output,
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_loki_labels() -> List[Dict]:
    """Test Loki labels API"""
    config = get_loki_config()
    namespace = config["namespace"]
    pod = get_loki_gateway_pod()
    
    if not pod:
        return [{
            "name": "loki_labels",
            "status": False,
            "output": "No Loki gateway pod available",
            "severity": "WARNING"
        }]
    
    auth = get_auth_header()
    
    # Get all labels
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s {auth} " \
          f"http://localhost:{config['port']}/loki/api/v1/labels 2>/dev/null"
    
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "loki_labels",
            "status": False,
            "output": "Failed to query labels",
            "severity": "WARNING"
        }]
    
    try:
        data = json.loads(result["stdout"])
        
        if data.get("status") == "success":
            labels = data.get("data", [])
            
            output = f"Available labels: {len(labels)}\n"
            if labels:
                output += f"  Labels: {', '.join(labels[:10])}"
                if len(labels) > 10:
                    output += f" (+{len(labels)-10} more)"
            
            status = len(labels) > 0
        else:
            output = "Failed to retrieve labels"
            status = False
            
    except Exception as e:
        output = f"Failed to parse labels response"
        status = False
    
    return [{
        "name": "loki_labels",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_loki_ring_health() -> List[Dict]:
    """Test Loki ring/memberlist health"""
    config = get_loki_config()
    namespace = config["namespace"]
    
    # Get a write pod to check ring membership
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/component=write --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0 or not result["stdout"]:
        return [{
            "name": "loki_ring_health",
            "status": True,
            "output": "Ring health check not applicable (no write pods)",
            "severity": "INFO"
        }]
    
    write_pod = result["stdout"].strip()
    
    # Check ring members via HTTP endpoint
    cmd = f"kubectl exec -n {namespace} {write_pod} -- curl -s http://localhost:3100/ring 2>/dev/null | grep -c 'ACTIVE' || echo 0"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        try:
            active_count = int(result["stdout"].strip())
            output = f"Ring members: {active_count} ACTIVE"
            status = active_count > 0
        except:
            output = "Ring status: Unable to determine"
            status = False
    else:
        output = "Ring status: Check failed"
        status = False
    
    return [{
        "name": "loki_ring_health",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_loki_canary() -> List[Dict]:
    """Test Loki Canary (synthetic monitoring)"""
    config = get_loki_config()
    namespace = config["namespace"]
    
    # Check canary pods
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/component=canary --no-headers 2>/dev/null"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0 or not result["stdout"]:
        return [{
            "name": "loki_canary",
            "status": True,
            "output": "Loki Canary not deployed",
            "severity": "INFO"
        }]
    
    lines = [l for l in result["stdout"].split("\n") if l.strip()]
    total = len(lines)
    running = sum(1 for l in lines if "Running" in l and "1/1" in l)
    
    status = running == total and total > 0
    output = f"Canary pods: {running}/{total} running"
    
    # Check canary metrics if available
    if running > 0:
        canary_pod = lines[0].split()[0]
        cmd = f"kubectl exec -n {namespace} {canary_pod} -- curl -s http://localhost:3500/metrics 2>/dev/null | grep -E 'loki_canary_.*_total' | head -3"
        metrics_result = run_command(cmd, timeout=5)
        
        if metrics_result["exit_code"] == 0 and metrics_result["stdout"]:
            output += "\n  Canary metrics available ✓"
    
    return [{
        "name": "loki_canary",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_loki_storage_backend() -> List[Dict]:
    """Test Loki storage backend (MinIO/S3)"""
    config = get_loki_config()
    namespace = config["namespace"]
    
    # Check if MinIO is mentioned in environment
    minio_buckets = os.getenv("MINIO_BUCKETS", "")
    
    if "loki" not in minio_buckets.lower():
        return [{
            "name": "loki_storage_backend",
            "status": True,
            "output": "Storage backend check skipped (no MinIO config)",
            "severity": "INFO"
        }]
    
    # Get a backend pod to check storage config
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/component=backend --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        backend_pod = result["stdout"].strip()
        
        # Check if pod can access storage (look for config)
        cmd = f"kubectl exec -n {namespace} {backend_pod} -- cat /etc/loki/config/config.yaml 2>/dev/null | grep -A5 'object_store:' | head -6"
        config_result = run_command(cmd, timeout=5)
        
        if config_result["exit_code"] == 0 and "s3" in config_result["stdout"].lower():
            output = "Storage backend: S3/MinIO configured ✓"
            status = True
        else:
            output = "Storage backend: Configuration unclear"
            status = False
    else:
        output = "Storage backend: Unable to verify"
        status = False
    
    return [{
        "name": "loki_storage_backend",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_loki_recent_logs() -> List[Dict]:
    """Check recent Loki logs for errors"""
    config = get_loki_config()
    namespace = config["namespace"]
    results = []
    
    # Check logs from different components
    components_to_check = [
        ("gateway", "app.kubernetes.io/component=gateway"),
        ("write", "app.kubernetes.io/component=write"),
        ("read", "app.kubernetes.io/component=read")
    ]
    
    for comp_name, label in components_to_check:
        cmd = f"kubectl get pods -n {namespace} -l {label} --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
        result = run_command(cmd, timeout=5)
        
        if result["exit_code"] == 0 and result["stdout"]:
            pod = result["stdout"].strip()
            
            # Get last 30 log lines
            cmd = f"kubectl logs -n {namespace} {pod} --tail=30 2>/dev/null"
            log_result = run_command(cmd, timeout=10)
            
            if log_result["exit_code"] == 0:
                logs = log_result["stdout"]
                error_count = logs.lower().count("error")
                warning_count = logs.lower().count("warning")
                panic_count = logs.lower().count("panic")
                
                status = panic_count == 0 and error_count < 3
                
                output = f"loki-{comp_name} logs:\n"
                output += f"  Errors: {error_count}, Warnings: {warning_count}, Panics: {panic_count}"
                
                results.append({
                    "name": f"loki_{comp_name}_logs",
                    "status": status,
                    "output": output,
                    "severity": "WARNING" if not status else "INFO"
                })
    
    return results if results else [{
        "name": "loki_logs",
        "status": False,
        "output": "Unable to check component logs",
        "severity": "WARNING"
    }]


def test_loki_metrics_scraping() -> List[Dict]:
    """Test if Loki metrics are being scraped by Prometheus"""
    config = get_loki_config()
    namespace = config["namespace"]
    
    # Check for ServiceMonitor
    cmd = f"kubectl get servicemonitor -n {namespace} loki 2>/dev/null"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0:
        output = "ServiceMonitor: ✓ Configured"
        
        # Get ServiceMonitor details
        cmd = f"kubectl get servicemonitor -n {namespace} loki -o json 2>/dev/null"
        detail_result = run_command(cmd, timeout=5)
        
        if detail_result["exit_code"] == 0:
            try:
                data = json.loads(detail_result["stdout"])
                endpoints = data.get("spec", {}).get("endpoints", [])
                output += f"\n  Endpoints: {len(endpoints)}"
                
                # Check selector
                selector = data.get("spec", {}).get("selector", {})
                match_labels = selector.get("matchLabels", {})
                if match_labels:
                    output += f"\n  Selector: {', '.join([f'{k}={v}' for k, v in match_labels.items()])}"
            except:
                pass
        
        status = True
    else:
        output = "ServiceMonitor: Not configured"
        status = False
    
    return [{
        "name": "loki_metrics_scraping",
        "status": status,
        "output": output,
        "severity": "INFO"
    }]


def test_loki_cluster_stats() -> List[Dict]:
    """Get Loki cluster statistics"""
    config = get_loki_config()
    namespace = config["namespace"]
    pod = get_loki_gateway_pod()
    
    if not pod:
        return [{
            "name": "loki_cluster_stats",
            "status": False,
            "output": "No Loki gateway pod available",
            "severity": "WARNING"
        }]
    
    auth = get_auth_header()
    
    # Get series statistics
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s {auth} " \
          f"http://localhost:{config['port']}/loki/api/v1/series 2>/dev/null"
    
    result = run_command(cmd, timeout=10)
    
    output = "Cluster Statistics:\n"
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            if data.get("status") == "success":
                series = data.get("data", [])
                output += f"  Active series: {len(series)}\n"
        except:
            pass
    
    # Count total pods
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=loki --no-headers 2>/dev/null | wc -l"
    pod_result = run_command(cmd, timeout=5)
    
    if pod_result["exit_code"] == 0:
        pod_count = pod_result["stdout"].strip()
        output += f"  Total pods: {pod_count}\n"
    
    # Get namespace size
    cmd = f"kubectl top pods -n {namespace} --no-headers 2>/dev/null | grep loki | awk '{{sum+=$3}} END {{print sum}}'"
    mem_result = run_command(cmd, timeout=10)
    
    if mem_result["exit_code"] == 0 and mem_result["stdout"]:
        try:
            memory_mi = int(mem_result["stdout"].strip())
            output += f"  Total memory: {memory_mi}Mi"
        except:
            pass
    
    return [{
        "name": "loki_cluster_stats",
        "status": True,
        "output": output.strip(),
        "severity": "INFO"
    }]


def test_loki_data_retention() -> List[Dict]:
    """Check Loki data retention configuration"""
    config = get_loki_config()
    namespace = config["namespace"]
    
    # Get a backend or write pod to check config
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/component=backend --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0 or not result["stdout"]:
        cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/component=write --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
        result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        pod = result["stdout"].strip()
        
        # Check retention config
        cmd = f"kubectl exec -n {namespace} {pod} -- cat /etc/loki/config/config.yaml 2>/dev/null | grep -A10 'limits_config:' | grep -E 'retention|delete'"
        config_result = run_command(cmd, timeout=5)
        
        if config_result["exit_code"] == 0 and config_result["stdout"]:
            output = "Retention configuration:\n"
            for line in config_result["stdout"].split("\n")[:3]:
                if line.strip():
                    output += f"  {line.strip()}\n"
            status = True
        else:
            output = "Retention: Default configuration"
            status = True
    else:
        output = "Retention: Unable to check configuration"
        status = False
    
    return [{
        "name": "loki_data_retention",
        "status": status,
        "output": output.strip(),
        "severity": "INFO"
    }]


# Main execution
if __name__ == "__main__":
    all_results = []
    
    config = get_loki_config()
    print(f"Using Loki configuration:")
    print(f"  Namespace: {config['namespace']}")
    print(f"  Host: {config['host']}")
    print(f"  Port: {config['port']}")
    if config['user']:
        print(f"  Auth: Basic (user: {config['user']})")
    print()
    
    # Run all tests
    print("Running Loki stack tests...\n")
    
    all_results.extend(test_loki_connectivity())
    all_results.extend(test_loki_components())
    all_results.extend(test_loki_ingestion())
    all_results.extend(test_loki_query())
    all_results.extend(test_loki_labels())
    all_results.extend(test_loki_ring_health())
    all_results.extend(test_loki_canary())
    all_results.extend(test_loki_storage_backend())
    all_results.extend(test_loki_metrics_scraping())
    all_results.extend(test_loki_cluster_stats())
    all_results.extend(test_loki_data_retention())
    all_results.extend(test_loki_recent_logs())
    
    # Print results
    print("\n" + "="*60)
    print("LOKI TEST RESULTS")
    print("="*60 + "\n")
    
    for result in all_results:
        status_icon = "✓" if result["status"] else "✗"
        status_text = "Passed" if result["status"] else "Failed"
        severity = result.get("severity", "INFO")
        
        print(f"{result['name']} [{severity}]")
        print(f"  Status: {status_text}")
        if result["output"]:
            # Indent multiline output
            output_lines = result["output"].split("\n")
            for line in output_lines:
                print(f"  {line}")
        print()
    
    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"])
    failed = total - passed
    
    # Count by severity
    critical = sum(1 for r in all_results if not r["status"] and r.get("severity") == "CRITICAL")
    warnings = sum(1 for r in all_results if not r["status"] and r.get("severity") == "WARNING")
    
    print("="*60)
    print(f"SUMMARY: {passed}/{total} tests passed, {failed} failed")
    if failed > 0:
        print(f"  Critical failures: {critical}")
        print(f"  Warnings: {warnings}")
    print("="*60)
    
    # Exit with error code if critical failures
    if critical > 0:
        exit(1)
