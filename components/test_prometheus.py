#!/usr/bin/env python3
"""
test_prometheus.py - Comprehensive Prometheus Stack Testing Script
Tests Prometheus connectivity, metrics, ServiceMonitors, and overall health
"""

import os
import json
import subprocess
import time
import urllib.request
import urllib.error
from typing import List, Dict, Optional
from datetime import datetime, timedelta

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


def get_prometheus_config() -> Dict:
    """Get Prometheus configuration from environment variables"""
    return {
        "namespace": os.getenv("PROMETHEUS_NS", os.getenv("PROMETHEUS_NAMESPACE", "prometheus")),
        "host": os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local"),
        "port": os.getenv("PROMETHEUS_PORT", "9090")
    }


def get_prometheus_pod() -> Optional[str]:
    """Get the main Prometheus pod name"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    # Try to find the main Prometheus server pod
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=prometheus --no-headers 2>/dev/null | grep prometheus-prometheus | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    # Fallback: look for any pod with prometheus in name that's not node-exporter
    cmd = f"kubectl get pods -n {namespace} --no-headers 2>/dev/null | grep 'prometheus-prometheus-' | grep -v node-exporter | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    return None


def test_prometheus_connectivity() -> List[Dict]:
    """Test basic Prometheus connectivity"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_connectivity",
            "status": False,
            "output": f"No Prometheus pod found in namespace {namespace}",
            "severity": "CRITICAL"
        }]
    
    # Test Prometheus API endpoint
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{config['port']}/api/v1/query 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    http_code = result["stdout"] if result["exit_code"] == 0 else "000"
    status = http_code == "200"
    
    output = f"Using pod: {pod}\n"
    output += f"API Response: HTTP {http_code}"
    
    return [{
        "name": "prometheus_connectivity",
        "status": status,
        "output": output.strip(),
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_prometheus_targets() -> List[Dict]:
    """Check Prometheus scrape targets health"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_targets",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "CRITICAL"
        }]
    
    # Query targets API
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s http://localhost:{config['port']}/api/v1/targets 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "prometheus_targets",
            "status": False,
            "output": "Failed to query targets API",
            "severity": "CRITICAL"
        }]
    
    try:
        data = json.loads(result["stdout"])
        active_targets = data.get("data", {}).get("activeTargets", [])
        
        total = len(active_targets)
        up_count = sum(1 for t in active_targets if t.get("health") == "up")
        down_targets = [t for t in active_targets if t.get("health") != "up"]
        
        output = f"Scrape Targets: {up_count}/{total} healthy\n"
        
        # Show first 3 down targets if any
        if down_targets:
            output += "Down targets:\n"
            for target in down_targets[:3]:
                job = target.get("labels", {}).get("job", "unknown")
                instance = target.get("labels", {}).get("instance", "unknown")
                error = target.get("lastError", "")[:50]  # First 50 chars of error
                output += f"  - {job}/{instance}: {error}\n"
        
        status = up_count == total or up_count/total > 0.8  # Allow 80% threshold
        
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
            "output": f"Failed to parse targets data: {str(e)}",
            "severity": "WARNING"
        }]


def test_prometheus_rules() -> List[Dict]:
    """Check Prometheus recording and alerting rules"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_rules",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "WARNING"
        }]
    
    # Query rules API
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s http://localhost:{config['port']}/api/v1/rules 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "prometheus_rules",
            "status": False,
            "output": "Failed to query rules API",
            "severity": "WARNING"
        }]
    
    try:
        data = json.loads(result["stdout"])
        groups = data.get("data", {}).get("groups", [])
        
        total_rules = sum(len(g.get("rules", [])) for g in groups)
        
        # Count rule types
        recording_rules = 0
        alerting_rules = 0
        firing_alerts = []
        
        for group in groups:
            for rule in group.get("rules", []):
                if rule.get("type") == "recording":
                    recording_rules += 1
                elif rule.get("type") == "alerting":
                    alerting_rules += 1
                    if rule.get("state") == "firing":
                        firing_alerts.append(rule.get("name", "unknown"))
        
        output = f"Rules Summary:\n"
        output += f"  Total: {total_rules}\n"
        output += f"  Recording: {recording_rules}\n"
        output += f"  Alerting: {alerting_rules}\n"
        
        if firing_alerts:
            output += f"  Firing Alerts: {', '.join(firing_alerts[:5])}"
        
        return [{
            "name": "prometheus_rules",
            "status": True,
            "output": output.strip(),
            "severity": "INFO"
        }]
    except Exception as e:
        return [{
            "name": "prometheus_rules",
            "status": False,
            "output": f"Failed to parse rules data: {str(e)}",
            "severity": "WARNING"
        }]


def test_service_monitors() -> List[Dict]:
    """Test ServiceMonitor resources"""
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
        
        for item in items:
            ns = item.get("metadata", {}).get("namespace", "unknown")
            by_namespace[ns] = by_namespace.get(ns, 0) + 1
        
        output = f"ServiceMonitors: {total} total\n"
        output += "By namespace:\n"
        for ns in sorted(by_namespace.keys())[:5]:  # Show first 5 namespaces
            output += f"  {ns}: {by_namespace[ns]}\n"
        
        # Check a few specific important ServiceMonitors
        important_monitors = [
            "prometheus-kube-prometheus-prometheus",
            "prometheus-kube-state-metrics",
            "prometheus-prometheus-node-exporter"
        ]
        
        for monitor_name in important_monitors:
            monitor = next((i for i in items if i.get("metadata", {}).get("name") == monitor_name), None)
            if monitor:
                # Check if it has endpoints defined
                endpoints = monitor.get("spec", {}).get("endpoints", [])
                status_text = f"✓ {len(endpoints)} endpoints" if endpoints else "✗ No endpoints"
                output += f"\n{monitor_name}: {status_text}"
        
        results.append({
            "name": "service_monitors",
            "status": total > 0,
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


def test_prometheus_metrics() -> List[Dict]:
    """Test key Prometheus metrics"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_metrics",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "WARNING"
        }]
    
    results = []
    
    # Test queries for important metrics
    test_queries = [
        ("up", "Target health status"),
        ("prometheus_tsdb_head_samples", "TSDB samples"),
        ("prometheus_rule_evaluations_total", "Rule evaluations"),
        ("process_resident_memory_bytes", "Memory usage")
    ]
    
    for query, description in test_queries:
        cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -G --data-urlencode 'query={query}' http://localhost:{config['port']}/api/v1/query 2>/dev/null"
        result = run_command(cmd, timeout=5)
        
        if result["exit_code"] == 0:
            try:
                data = json.loads(result["stdout"])
                result_data = data.get("data", {}).get("result", [])
                
                if result_data:
                    # For 'up' metric, count how many are up
                    if query == "up":
                        up_count = sum(1 for r in result_data if r.get("value", [None, "0"])[1] == "1")
                        total_count = len(result_data)
                        output = f"{description}: {up_count}/{total_count} up"
                    else:
                        # For other metrics, just confirm they exist
                        output = f"{description}: ✓ Available ({len(result_data)} series)"
                    
                    status = True
                else:
                    output = f"{description}: No data"
                    status = False
                
                results.append({
                    "name": f"metric_{query.replace('_', '-')}",
                    "status": status,
                    "output": output,
                    "severity": "WARNING" if not status else "INFO"
                })
            except:
                pass
    
    return results if results else [{
        "name": "prometheus_metrics",
        "status": False,
        "output": "Failed to query metrics",
        "severity": "WARNING"
    }]


def test_prometheus_storage() -> List[Dict]:
    """Check Prometheus storage statistics"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_storage",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "WARNING"
        }]
    
    # Query TSDB status
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s http://localhost:{config['port']}/api/v1/status/tsdb 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "prometheus_storage",
            "status": False,
            "output": "Failed to query TSDB status",
            "severity": "WARNING"
        }]
    
    try:
        data = json.loads(result["stdout"])
        tsdb = data.get("data", {})
        
        # Extract key metrics
        head_stats = tsdb.get("headStats", {})
        series_count = head_stats.get("numSeries", 0)
        samples_count = head_stats.get("numSamples", 0)
        chunks_count = head_stats.get("chunks", 0)
        
        # Convert to readable format
        def format_number(n):
            if n > 1_000_000:
                return f"{n/1_000_000:.1f}M"
            elif n > 1000:
                return f"{n/1000:.1f}K"
            return str(n)
        
        output = f"TSDB Statistics:\n"
        output += f"  Series: {format_number(series_count)}\n"
        output += f"  Samples: {format_number(samples_count)}\n"
        output += f"  Chunks: {format_number(chunks_count)}"
        
        # Check if values are reasonable (not zero)
        status = series_count > 0 and samples_count > 0
        
        return [{
            "name": "prometheus_storage",
            "status": status,
            "output": output,
            "severity": "WARNING" if not status else "INFO"
        }]
    except Exception as e:
        return [{
            "name": "prometheus_storage",
            "status": False,
            "output": f"Failed to parse TSDB data: {str(e)}",
            "severity": "WARNING"
        }]


def test_alertmanager() -> List[Dict]:
    """Test Alertmanager connectivity and status"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    # Find Alertmanager pod
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=alertmanager --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0 or not result["stdout"]:
        return [{
            "name": "alertmanager",
            "status": True,
            "output": "No Alertmanager deployed",
            "severity": "INFO"
        }]
    
    alertmanager_pod = result["stdout"].strip()
    
    # Check Alertmanager API
    cmd = f"kubectl exec -n {namespace} {alertmanager_pod} -- curl -s -o /dev/null -w '%{{http_code}}' http://localhost:9093/api/v1/status 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    http_code = result["stdout"] if result["exit_code"] == 0 else "000"
    status = http_code == "200"
    
    # Get active alerts count
    cmd = f"kubectl exec -n {namespace} {alertmanager_pod} -- curl -s http://localhost:9093/api/v1/alerts 2>/dev/null"
    alert_result = run_command(cmd, timeout=10)
    
    alerts_count = 0
    if alert_result["exit_code"] == 0:
        try:
            data = json.loads(alert_result["stdout"])
            alerts_count = len(data.get("data", []))
        except:
            pass
    
    output = f"Alertmanager Status:\n"
    output += f"  Pod: {alertmanager_pod}\n"
    output += f"  API: HTTP {http_code}\n"
    output += f"  Active Alerts: {alerts_count}"
    
    return [{
        "name": "alertmanager",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_prometheus_operator() -> List[Dict]:
    """Test Prometheus Operator health"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    # Check operator pod
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=prometheus-operator --no-headers 2>/dev/null"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] != 0:
        return [{
            "name": "prometheus_operator",
            "status": True,
            "output": "No Prometheus Operator deployed",
            "severity": "INFO"
        }]
    
    lines = [l for l in result["stdout"].split("\n") if l.strip()]
    running = [l for l in lines if "Running" in l and "1/1" in l]
    
    status = len(running) == len(lines) and len(lines) > 0
    
    output = f"Prometheus Operator: {len(running)}/{len(lines)} running"
    
    # Check CRDs
    crds = ["prometheuses", "servicemonitors", "prometheusrules", "alertmanagerconfigs"]
    crd_count = 0
    
    for crd in crds:
        cmd = f"kubectl get crd {crd}.monitoring.coreos.com 2>/dev/null"
        if run_command(cmd, timeout=5)["exit_code"] == 0:
            crd_count += 1
    
    output += f"\n  CRDs: {crd_count}/{len(crds)} installed"
    
    return [{
        "name": "prometheus_operator",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_exporters() -> List[Dict]:
    """Test various exporters (node-exporter, kube-state-metrics, etc.)"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    results = []
    
    exporters = [
        ("node-exporter", "app.kubernetes.io/name=prometheus-node-exporter"),
        ("kube-state-metrics", "app.kubernetes.io/name=kube-state-metrics"),
        ("pushgateway", "app=pushgateway")
    ]
    
    for exporter_name, label in exporters:
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
                    node_count = node_result["stdout"].strip()
                    output += f" (nodes: {len(lines)}/{node_count})"
        else:
            status = True  # Not critical if optional exporter is missing
            output = f"{exporter_name}: Not deployed"
        
        results.append({
            "name": f"exporter_{exporter_name.replace('-', '_')}",
            "status": status,
            "output": output,
            "severity": "WARNING" if not status and exporter_name != "pushgateway" else "INFO"
        })
    
    return results


def test_prometheus_config_reload() -> List[Dict]:
    """Test Prometheus configuration reload capability"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_config_reload",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "WARNING"
        }]
    
    # Trigger config reload
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -X POST http://localhost:{config['port']}/-/reload 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    status = result["exit_code"] == 0
    
    # Check last reload time
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s http://localhost:{config['port']}/api/v1/status/config 2>/dev/null"
    config_result = run_command(cmd, timeout=10)
    
    output = "Config reload: "
    if status:
        output += "✓ Successful"
        if config_result["exit_code"] == 0:
            try:
                data = json.loads(config_result["stdout"])
                yaml_config = data.get("data", {}).get("yaml", "")
                if yaml_config:
                    output += f"\n  Config size: {len(yaml_config)} bytes"
            except:
                pass
    else:
        output += "✗ Failed"
    
    return [{
        "name": "prometheus_config_reload",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }]


def test_prometheus_federation() -> List[Dict]:
    """Test Prometheus federation endpoint if configured"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_federation",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "INFO"
        }]
    
    # Test federation endpoint
    cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' 'http://localhost:{config['port']}/federate?match[]={{__name__=~\".+\"}}' 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    http_code = result["stdout"] if result["exit_code"] == 0 else "000"
    status = http_code == "200"
    
    output = f"Federation endpoint: HTTP {http_code}"
    
    return [{
        "name": "prometheus_federation",
        "status": status,
        "output": output,
        "severity": "INFO"  # Not critical if federation is not used
    }]


def test_recent_logs() -> List[Dict]:
    """Check recent Prometheus logs for errors"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    pod = get_prometheus_pod()
    
    if not pod:
        return [{
            "name": "prometheus_logs",
            "status": False,
            "output": "No Prometheus pod available",
            "severity": "WARNING"
        }]
    
    # Get last 50 log lines
    cmd = f"kubectl logs -n {namespace} {pod} --tail=50 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "prometheus_logs",
            "status": False,
            "output": "Failed to retrieve logs",
            "severity": "WARNING"
        }]
    
    # Count error and warning messages
    logs = result["stdout"]
    error_count = logs.lower().count("error")
    warning_count = logs.lower().count("warning")
    panic_count = logs.lower().count("panic")
    
    status = panic_count == 0 and error_count < 5  # Allow some errors
    
    output = f"Recent logs analysis:\n"
    output += f"  Errors: {error_count}\n"
    output += f"  Warnings: {warning_count}\n"
    output += f"  Panics: {panic_count}"
    
    # Show sample of recent errors if any
    if error_count > 0:
        error_lines = [l for l in logs.split("\n") if "error" in l.lower()][:2]
        if error_lines:
            output += "\n  Sample errors:\n"
            for line in error_lines:
                # Truncate long lines
                output += f"    {line[:80]}...\n" if len(line) > 80 else f"    {line}\n"
    
    return [{
        "name": "prometheus_logs",
        "status": status,
        "output": output.strip(),
        "severity": "WARNING" if not status else "INFO"
    }]


# Main execution
if __name__ == "__main__":
    all_results = []
    
    config = get_prometheus_config()
    print(f"Using Prometheus configuration:")
    print(f"  Namespace: {config['namespace']}")
    print(f"  Host: {config['host']}")
    print(f"  Port: {config['port']}\n")
    
    # Run all tests
    print("Running Prometheus stack tests...\n")
    
    all_results.extend(test_prometheus_connectivity())
    all_results.extend(test_prometheus_targets())
    all_results.extend(test_prometheus_rules())
    all_results.extend(test_service_monitors())
    all_results.extend(test_prometheus_metrics())
    all_results.extend(test_prometheus_storage())
    all_results.extend(test_alertmanager())
    all_results.extend(test_prometheus_operator())
    all_results.extend(test_exporters())
    all_results.extend(test_prometheus_config_reload())
    all_results.extend(test_prometheus_federation())
    all_results.extend(test_recent_logs())
    
    # Print results
    print("\n" + "="*60)
    print("PROMETHEUS TEST RESULTS")
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
