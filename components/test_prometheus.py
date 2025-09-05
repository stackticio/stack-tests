#!/usr/bin/env python3
"""
test_prometheus_improved.py - Improved Prometheus Stack Testing Script
Tests Prometheus connectivity, metrics, ServiceMonitors, and overall health
Uses port-forwarding and direct service access instead of exec
"""

import os
import json
import subprocess
import time
import urllib.request
import urllib.error
import socket
import threading
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager

class PortForwarder:
    """Context manager for kubectl port-forward"""
    def __init__(self, namespace: str, service: str, local_port: int, remote_port: int):
        self.namespace = namespace
        self.service = service
        self.local_port = local_port
        self.remote_port = remote_port
        self.process = None
        
    def __enter__(self):
        cmd = f"kubectl port-forward -n {self.namespace} svc/{self.service} {self.local_port}:{self.remote_port}"
        self.process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)  # Give port-forward time to establish
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


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


def query_prometheus_api(endpoint: str, port: int = 9090) -> Optional[Dict]:
    """Query Prometheus API endpoint via localhost port-forward"""
    try:
        url = f"http://localhost:{port}{endpoint}"
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"  Debug: Failed to query {endpoint}: {str(e)}")
        return None


def get_prometheus_config() -> Dict:
    """Get Prometheus configuration from environment variables"""
    return {
        "namespace": os.getenv("PROMETHEUS_NS", os.getenv("PROMETHEUS_NAMESPACE", "prometheus")),
        "service": os.getenv("PROMETHEUS_SERVICE", "prometheus-kube-prometheus-prometheus"),
        "port": int(os.getenv("PROMETHEUS_PORT", "9090"))
    }


def find_free_port() -> int:
    """Find a free local port"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def test_prometheus_connectivity() -> List[Dict]:
    """Test basic Prometheus connectivity using port-forward"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    service = config["service"]
    local_port = find_free_port()
    
    try:
        with PortForwarder(namespace, service, local_port, config["port"]):
            # Test API endpoint
            data = query_prometheus_api("/api/v1/query?query=up", local_port)
            
            if data and data.get("status") == "success":
                status = True
                output = f"Prometheus API: ✓ Accessible\n"
                output += f"  Service: {service}\n"
                output += f"  Port: {config['port']}"
            else:
                status = False
                output = "Prometheus API: ✗ Failed to query"
                
    except Exception as e:
        status = False
        output = f"Failed to establish port-forward: {str(e)}"
    
    return [{
        "name": "prometheus_connectivity",
        "status": status,
        "output": output,
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_prometheus_targets() -> List[Dict]:
    """Check Prometheus scrape targets health"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    service = config["service"]
    local_port = find_free_port()
    
    try:
        with PortForwarder(namespace, service, local_port, config["port"]):
            data = query_prometheus_api("/api/v1/targets", local_port)
            
            if not data:
                return [{
                    "name": "prometheus_targets",
                    "status": False,
                    "output": "Failed to query targets API",
                    "severity": "CRITICAL"
                }]
            
            active_targets = data.get("data", {}).get("activeTargets", [])
            
            total = len(active_targets)
            up_count = sum(1 for t in active_targets if t.get("health") == "up")
            down_targets = [t for t in active_targets if t.get("health") != "up"]
            
            # Group targets by job
            targets_by_job = {}
            for target in active_targets:
                job = target.get("labels", {}).get("job", "unknown")
                if job not in targets_by_job:
                    targets_by_job[job] = {"up": 0, "down": 0}
                if target.get("health") == "up":
                    targets_by_job[job]["up"] += 1
                else:
                    targets_by_job[job]["down"] += 1
            
            output = f"Scrape Targets: {up_count}/{total} healthy\n"
            output += "By job:\n"
            for job, counts in sorted(targets_by_job.items())[:10]:
                status_str = f"{counts['up']}/{counts['up'] + counts['down']}"
                output += f"  {job}: {status_str}\n"
            
            # Show first 3 down targets if any
            if down_targets:
                output += "\nDown targets:\n"
                for target in down_targets[:3]:
                    job = target.get("labels", {}).get("job", "unknown")
                    instance = target.get("labels", {}).get("instance", "unknown")
                    error = target.get("lastError", "")[:50]
                    output += f"  - {job}/{instance}: {error}\n"
            
            status = up_count == total or (total > 0 and up_count/total > 0.8)
            
            return [{
                "name": "prometheus_targets",
                "status": status,
                "output": output.strip(),
                "severity": "WARNING" if not status else "INFO"
            }]
            
    except Exception as e:
        return [{
            "name": "prometheus_targets",
            "status": False,
            "output": f"Error testing targets: {str(e)}",
            "severity": "CRITICAL"
        }]


def test_service_monitors() -> List[Dict]:
    """Test ServiceMonitor resources and their targets"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    results = []
    
    # Get all ServiceMonitors
    cmd = "kubectl get servicemonitors.monitoring.coreos.com -A -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "service_monitors",
            "status": False,
            "output": "Failed to get ServiceMonitors",
            "severity": "WARNING"
        }]
    
    try:
        data = json.loads(result["stdout"])
        items = data.get("items", [])
        
        total = len(items)
        by_namespace = {}
        
        # Analyze each ServiceMonitor
        monitors_with_issues = []
        
        for item in items:
            ns = item.get("metadata", {}).get("namespace", "unknown")
            name = item.get("metadata", {}).get("name", "unknown")
            by_namespace[ns] = by_namespace.get(ns, 0) + 1
            
            # Check if ServiceMonitor has proper configuration
            spec = item.get("spec", {})
            endpoints = spec.get("endpoints", [])
            selector = spec.get("selector", {})
            
            if not endpoints:
                monitors_with_issues.append(f"{ns}/{name}: No endpoints defined")
            elif not selector:
                monitors_with_issues.append(f"{ns}/{name}: No selector defined")
        
        output = f"ServiceMonitors: {total} total\n"
        output += "By namespace:\n"
        for ns in sorted(by_namespace.keys())[:5]:
            output += f"  {ns}: {by_namespace[ns]}\n"
        
        if monitors_with_issues:
            output += "\nServiceMonitors with issues:\n"
            for issue in monitors_with_issues[:5]:
                output += f"  - {issue}\n"
        
        # Now check if ServiceMonitors are being scraped
        local_port = find_free_port()
        service = config["service"]
        
        try:
            with PortForwarder(namespace, service, local_port, config["port"]):
                targets_data = query_prometheus_api("/api/v1/targets", local_port)
                
                if targets_data:
                    active_targets = targets_data.get("data", {}).get("activeTargets", [])
                    
                    # Map ServiceMonitors to their scrape jobs
                    monitored_jobs = set()
                    for target in active_targets:
                        job = target.get("labels", {}).get("job", "")
                        if job:
                            monitored_jobs.add(job)
                    
                    output += f"\nActive scrape jobs: {len(monitored_jobs)}"
                    
                    # Check specific important monitors
                    important_monitors = {
                        "prometheus-kube-prometheus-prometheus": "prometheus",
                        "prometheus-kube-state-metrics": "kube-state-metrics",
                        "prometheus-prometheus-node-exporter": "node-exporter"
                    }
                    
                    output += "\n\nImportant monitors status:"
                    for monitor_name, job_pattern in important_monitors.items():
                        matched = any(job_pattern in job for job in monitored_jobs)
                        status_icon = "✓" if matched else "✗"
                        output += f"\n  {monitor_name}: {status_icon}"
                        
        except Exception as e:
            output += f"\n\nCouldn't verify active scraping: {str(e)}"
        
        results.append({
            "name": "service_monitors",
            "status": total > 0 and len(monitors_with_issues) < total/2,
            "output": output.strip(),
            "severity": "WARNING" if total == 0 else "INFO"
        })
        
    except Exception as e:
        results.append({
            "name": "service_monitors",
            "status": False,
            "output": f"Failed to parse ServiceMonitors: {str(e)}",
            "severity": "WARNING"
        })
    
    return results


def test_prometheus_operator() -> List[Dict]:
    """Test Prometheus Operator health"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    # Check operator pod - fixed selector
    cmd = f"kubectl get pods -n {namespace} -l app=kube-prometheus-stack-operator --no-headers 2>/dev/null"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0 or not result["stdout"]:
        # Try alternative selector
        cmd = f"kubectl get pods -n {namespace} | grep prometheus-operator | grep -v node-exporter"
        result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = [l for l in result["stdout"].split("\n") if l.strip()]
        running = [l for l in lines if "Running" in l and "1/1" in l]
        
        status = len(running) == len(lines) and len(lines) > 0
        output = f"Prometheus Operator: {len(running)}/{len(lines)} running"
        
        # Get pod name for logs check
        if lines:
            pod_name = lines[0].split()[0]
            # Check recent logs for errors
            cmd = f"kubectl logs -n {namespace} {pod_name} --tail=20 2>/dev/null | grep -i error | wc -l"
            log_result = run_command(cmd, timeout=5)
            if log_result["exit_code"] == 0:
                error_count = int(log_result["stdout"]) if log_result["stdout"].isdigit() else 0
                output += f"\n  Recent errors in logs: {error_count}"
    else:
        status = False
        output = "Prometheus Operator: Not found or not running"
    
    # Check CRDs
    crds = ["prometheuses", "servicemonitors", "prometheusrules", "alertmanagerconfigs"]
    crd_count = 0
    
    for crd in crds:
        cmd = f"kubectl get crd {crd}.monitoring.coreos.com 2>/dev/null"
        if run_command(cmd, timeout=5)["exit_code"] == 0:
            crd_count += 1
    
    output += f"\n  CRDs: {crd_count}/{len(crds)} installed"
    
    # Check if operator is creating resources
    cmd = f"kubectl get prometheuses.monitoring.coreos.com -n {namespace} --no-headers 2>/dev/null | wc -l"
    prom_result = run_command(cmd, timeout=5)
    if prom_result["exit_code"] == 0:
        prom_count = int(prom_result["stdout"]) if prom_result["stdout"].isdigit() else 0
        output += f"\n  Prometheus instances managed: {prom_count}"
    
    return [{
        "name": "prometheus_operator",
        "status": status and crd_count == len(crds),
        "output": output,
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_alertmanager() -> List[Dict]:
    """Test Alertmanager connectivity and status"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    # Find Alertmanager pod
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=alertmanager --no-headers 2>/dev/null | head -1"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0 or not result["stdout"]:
        return [{
            "name": "alertmanager",
            "status": True,
            "output": "No Alertmanager deployed",
            "severity": "INFO"
        }]
    
    pod_info = result["stdout"].strip().split()
    alertmanager_pod = pod_info[0]
    pod_status = pod_info[2] if len(pod_info) > 2 else "Unknown"
    
    output = f"Alertmanager Status:\n"
    output += f"  Pod: {alertmanager_pod}\n"
    output += f"  Status: {pod_status}\n"
    
    # Try to access via port-forward
    local_port = find_free_port()
    
    try:
        with PortForwarder(namespace, "prometheus-kube-prometheus-alertmanager", local_port, 9093):
            # Check API
            try:
                url = f"http://localhost:{local_port}/api/v1/status"
                with urllib.request.urlopen(url, timeout=5) as response:
                    status_data = json.loads(response.read().decode())
                    output += f"  API: ✓ Accessible\n"
                    
                    # Get cluster status
                    cluster = status_data.get("data", {}).get("cluster", {})
                    if cluster:
                        output += f"  Cluster status: {cluster.get('status', 'unknown')}\n"
                    
                    # Get alerts
                    url = f"http://localhost:{local_port}/api/v1/alerts"
                    with urllib.request.urlopen(url, timeout=5) as response:
                        alerts_data = json.loads(response.read().decode())
                        alerts = alerts_data.get("data", [])
                        output += f"  Active Alerts: {len(alerts)}"
                        
                        if alerts:
                            # Group by severity
                            by_severity = {}
                            for alert in alerts:
                                severity = alert.get("labels", {}).get("severity", "unknown")
                                by_severity[severity] = by_severity.get(severity, 0) + 1
                            output += " ("
                            output += ", ".join([f"{k}: {v}" for k, v in by_severity.items()])
                            output += ")"
                    
                    status = True
                    
            except Exception as e:
                output += f"  API: ✗ Error: {str(e)}"
                status = False
                
    except Exception as e:
        output += f"  Port-forward failed: {str(e)}"
        status = pod_status == "Running"
    
    return [{
        "name": "alertmanager",
        "status": status,
        "output": output.strip(),
        "severity": "WARNING" if not status else "INFO"
    }]


def test_prometheus_metrics() -> List[Dict]:
    """Test key Prometheus metrics"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    service = config["service"]
    local_port = find_free_port()
    
    results = []
    
    try:
        with PortForwarder(namespace, service, local_port, config["port"]):
            # Test queries for important metrics
            test_queries = [
                ("up", "Target health status"),
                ("prometheus_tsdb_head_samples", "TSDB samples"),
                ("prometheus_rule_evaluations_total", "Rule evaluations"),
                ("prometheus_tsdb_symbol_table_size_bytes", "Symbol table size"),
                ("process_resident_memory_bytes", "Memory usage")
            ]
            
            for query, description in test_queries:
                data = query_prometheus_api(f"/api/v1/query?query={query}", local_port)
                
                if data and data.get("status") == "success":
                    result_data = data.get("data", {}).get("result", [])
                    
                    if result_data:
                        if query == "up":
                            up_count = sum(1 for r in result_data if r.get("value", [None, "0"])[1] == "1")
                            total_count = len(result_data)
                            output = f"{description}: {up_count}/{total_count} up"
                            status = up_count > 0
                        else:
                            output = f"{description}: ✓ Available ({len(result_data)} series)"
                            status = True
                    else:
                        output = f"{description}: No data"
                        status = False
                else:
                    output = f"{description}: Query failed"
                    status = False
                
                results.append({
                    "name": f"metric_{query.replace('_', '-')[:30]}",
                    "status": status,
                    "output": output,
                    "severity": "WARNING" if not status else "INFO"
                })
                
    except Exception as e:
        results.append({
            "name": "prometheus_metrics",
            "status": False,
            "output": f"Failed to test metrics: {str(e)}",
            "severity": "WARNING"
        })
    
    return results


def test_exporters() -> List[Dict]:
    """Test various exporters (node-exporter, kube-state-metrics, etc.)"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    results = []
    
    exporters = [
        ("node-exporter", "app.kubernetes.io/name=prometheus-node-exporter", True),
        ("kube-state-metrics", "app.kubernetes.io/name=kube-state-metrics", True),
        ("pushgateway", "app=pushgateway", False)
    ]
    
    for exporter_name, label, is_critical in exporters:
        cmd = f"kubectl get pods -n {namespace} -l {label} --no-headers 2>/dev/null"
        result = run_command(cmd, timeout=5)
        
        if result["exit_code"] == 0 and result["stdout"]:
            lines = [l for l in result["stdout"].split("\n") if l.strip()]
            running = [l for l in lines if "Running" in l]
            
            status = len(running) == len(lines)
            output = f"{exporter_name}: {len(running)}/{len(lines)} running"
            
            # For node-exporter (DaemonSet), show node coverage
            if exporter_name == "node-exporter":
                cmd = "kubectl get nodes --no-headers 2>/dev/null | wc -l"
                node_result = run_command(cmd, timeout=5)
                if node_result["exit_code"] == 0:
                    node_count = int(node_result["stdout"].strip())
                    output += f" (nodes: {len(lines)}/{node_count})"
                    status = status and len(lines) == node_count
                
                # Check if metrics are being scraped
                if status:
                    local_port = find_free_port()
                    try:
                        with PortForwarder(namespace, config["service"], local_port, config["port"]):
                            data = query_prometheus_api("/api/v1/query?query=up{job=~'.*node.*'}", local_port)
                            if data:
                                result_data = data.get("data", {}).get("result", [])
                                up_count = sum(1 for r in result_data if r.get("value", [None, "0"])[1] == "1")
                                output += f"\n  Metrics scraping: {up_count} targets up"
                    except:
                        pass
        else:
            status = not is_critical  # Not critical if optional exporter is missing
            output = f"{exporter_name}: Not deployed"
        
        results.append({
            "name": f"exporter_{exporter_name.replace('-', '_')}",
            "status": status,
            "output": output,
            "severity": "CRITICAL" if not status and is_critical else "WARNING" if not status else "INFO"
        })
    
    return results


# Main execution
if __name__ == "__main__":
    all_results = []
    
    config = get_prometheus_config()
    print(f"Prometheus Health Check - Improved Version")
    print(f"=" * 60)
    print(f"Configuration:")
    print(f"  Namespace: {config['namespace']}")
    print(f"  Service: {config['service']}")
    print(f"  Port: {config['port']}")
    print(f"=" * 60)
    print(f"\nRunning tests...\n")
    
    # Run all tests
    test_functions = [
        ("Connectivity", test_prometheus_connectivity),
        ("Targets", test_prometheus_targets),
        ("ServiceMonitors", test_service_monitors),
        ("Operator", test_prometheus_operator),
        ("Alertmanager", test_alertmanager),
        ("Metrics", test_prometheus_metrics),
        ("Exporters", test_exporters)
    ]
    
    for test_name, test_func in test_functions:
        print(f"Testing {test_name}...")
        try:
            results = test_func()
            all_results.extend(results)
        except Exception as e:
            all_results.append({
                "name": test_name.lower(),
                "status": False,
                "output": f"Test failed with error: {str(e)}",
                "severity": "WARNING"
            })
    
    # Print results
    print("\n" + "="*60)
    print("TEST RESULTS")
    print("="*60 + "\n")
    
    # Group results by severity
    by_severity = {"CRITICAL": [], "WARNING": [], "INFO": []}
    
    for result in all_results:
        severity = result.get("severity", "INFO")
        by_severity[severity].append(result)
    
    # Print critical failures first
    for severity in ["CRITICAL", "WARNING", "INFO"]:
        if by_severity[severity]:
            print(f"\n{severity} ({len(by_severity[severity])} items):")
            print("-" * 40)
            for result in by_severity[severity]:
                status_icon = "✓" if result["status"] else "✗"
                print(f"\n{status_icon} {result['name']}")
                if result["output"]:
                    for line in result["output"].split("\n"):
                        print(f"    {line}")
    
    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"])
    failed = total - passed
    
    critical = len(by_severity["CRITICAL"])
    warnings = len(by_severity["WARNING"])
    critical_failed = sum(1 for r in by_severity["CRITICAL"] if not r["status"])
    warnings_failed = sum(1 for r in by_severity["WARNING"] if not r["status"])
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed} ({passed*100//total}%)")
    print(f"Failed: {failed} ({failed*100//total}%)")
    
    if failed > 0:
        print(f"\nFailed by severity:")
        print(f"  Critical: {critical_failed}/{critical}")
        print(f"  Warnings: {warnings_failed}/{warnings}")
    
    print("\n" + "="*60)
    
    # Exit with error code if critical failures
    exit_code = 1 if critical_failed > 0 else 0
    exit(exit_code)
