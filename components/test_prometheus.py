#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_prometheus_clean.py - Prometheus Health Check (ASCII only)
"""

import os
import json
import subprocess
import urllib.request
import urllib.error
import socket
import ssl
import time
from typing import List, Dict, Optional
from datetime import datetime

ssl._create_default_https_context = ssl._create_unverified_context


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


def query_http(url: str, timeout: int = 10) -> Optional[Dict]:
    """Query HTTP endpoint and return JSON response"""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                "status_code": response.getcode(),
                "data": json.loads(response.read().decode())
            }
    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": str(e)}
    except urllib.error.URLError as e:
        return {"status_code": 0, "error": str(e)}
    except Exception as e:
        return {"status_code": 0, "error": str(e)}


def get_prometheus_config() -> Dict:
    """Get Prometheus configuration"""
    namespace = os.getenv("PROMETHEUS_NS", os.getenv("PROMETHEUS_NAMESPACE", "prometheus"))
    
    return {
        "namespace": namespace,
        "prometheus_url": f"http://prometheus-kube-prometheus-prometheus.{namespace}.svc.cluster.local:9090",
        "alertmanager_url": f"http://prometheus-kube-prometheus-alertmanager.{namespace}.svc.cluster.local:9093",
        "pushgateway_url": f"http://pushgateway.{namespace}.svc.cluster.local:9091"
    }


def test_prometheus_api() -> List[Dict]:
    """Test Prometheus API connectivity"""
    config = get_prometheus_config()
    results = []
    
    response = query_http(f"{config['prometheus_url']}/api/v1/query?query=up")
    
    if response and response.get("status_code") == 200:
        data = response.get("data", {})
        if data.get("status") == "success":
            result_count = len(data.get("data", {}).get("result", []))
            output = f"Prometheus API: HEALTHY\n"
            output += f"  Endpoint: {config['prometheus_url']}\n"
            output += f"  Query test returned {result_count} results"
            status = True
        else:
            output = f"Prometheus API: FAILED - API returned non-success status"
            status = False
    else:
        error = response.get("error", "Unknown error") if response else "No response"
        output = f"Prometheus API: FAILED\n  Error: {error}"
        status = False
    
    results.append({
        "name": "prometheus_api",
        "status": status,
        "output": output,
        "severity": "CRITICAL" if not status else "INFO"
    })
    
    config_response = query_http(f"{config['prometheus_url']}/api/v1/status/config")
    if config_response and config_response.get("status_code") == 200:
        yaml_config = config_response.get("data", {}).get("data", {}).get("yaml", "")
        if yaml_config:
            results.append({
                "name": "prometheus_config",
                "status": True,
                "output": f"Configuration loaded: {len(yaml_config)} bytes",
                "severity": "INFO"
            })
    
    return results


def test_prometheus_uptime() -> List[Dict]:
    """Check Prometheus uptime and restarts"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=prometheus --no-headers | grep -v node-exporter | head -1"
    pod_result = run_command(cmd)
    
    if pod_result["exit_code"] != 0:
        return [{
            "name": "prometheus_uptime",
            "status": False,
            "output": "Could not find Prometheus pod",
            "severity": "WARNING"
        }]
    
    pod_info = pod_result["stdout"].split()
    pod_name = pod_info[0] if pod_info else "unknown"
    restart_count = pod_info[3] if len(pod_info) > 3 else "0"
    
    response = query_http(f"{config['prometheus_url']}/api/v1/query?query=process_start_time_seconds{{job='prometheus-kube-prometheus-prometheus'}}")
    
    output = f"Prometheus Uptime:\n"
    output += f"  Pod: {pod_name}\n"
    output += f"  Restart Count: {restart_count}\n"
    
    if response and response.get("status_code") == 200:
        result_data = response.get("data", {}).get("data", {}).get("result", [])
        if result_data:
            start_time = float(result_data[0].get("value", [0, "0"])[1])
            uptime_seconds = time.time() - start_time
            uptime_hours = uptime_seconds / 3600
            output += f"  Uptime: {uptime_hours:.1f} hours\n"
            
            if uptime_hours < 1:
                output += "  WARNING: Recently restarted - metrics may still be initializing"
    
    status = restart_count == "0" or int(restart_count) < 2
    
    return [{
        "name": "prometheus_uptime",
        "status": status,
        "output": output.strip(),
        "severity": "WARNING" if not status else "INFO"
    }]


def test_scrape_targets() -> List[Dict]:
    """Analyze all Prometheus scrape targets"""
    config = get_prometheus_config()
    
    response = query_http(f"{config['prometheus_url']}/api/v1/targets")
    
    if not response or response.get("status_code") != 200:
        return [{
            "name": "scrape_targets",
            "status": False,
            "output": f"Failed to query targets: {response.get('error', 'Unknown') if response else 'No response'}",
            "severity": "CRITICAL"
        }]
    
    targets = response.get("data", {}).get("data", {}).get("activeTargets", [])
    
    targets_by_job = {}
    unhealthy_targets = []
    
    for target in targets:
        job = target.get("labels", {}).get("job", "unknown")
        health = target.get("health", "unknown")
        
        if job not in targets_by_job:
            targets_by_job[job] = {"up": 0, "down": 0, "unknown": 0}
        
        if health == "up":
            targets_by_job[job]["up"] += 1
        elif health == "down":
            targets_by_job[job]["down"] += 1
            unhealthy_targets.append({
                "job": job,
                "instance": target.get("labels", {}).get("instance", "unknown"),
                "error": target.get("lastError", "No error details")[:100]
            })
        else:
            targets_by_job[job]["unknown"] += 1
    
    total_targets = len(targets)
    total_up = sum(j["up"] for j in targets_by_job.values())
    
    output = f"Scrape Targets Summary: {total_up}/{total_targets} healthy\n\n"
    output += "By Job:\n"
    
    for job, counts in sorted(targets_by_job.items()):
        total_job = counts["up"] + counts["down"] + counts["unknown"]
        health_pct = (counts["up"] / total_job * 100) if total_job > 0 else 0
        status_str = "OK" if health_pct == 100 else "WARN" if health_pct >= 50 else "FAIL"
        output += f"  [{status_str}] {job}: {counts['up']}/{total_job} up ({health_pct:.0f}%)\n"
    
    if unhealthy_targets:
        output += "\nUnhealthy Targets (first 5):\n"
        for target in unhealthy_targets[:5]:
            output += f"  - {target['job']}/{target['instance']}\n"
            output += f"    Error: {target['error']}\n"
    
    status = total_up >= total_targets * 0.8 if total_targets > 0 else False
    
    return [{
        "name": "scrape_targets",
        "status": status,
        "output": output.strip(),
        "severity": "WARNING" if not status else "INFO"
    }]


def test_servicemonitors() -> List[Dict]:
    """Test ServiceMonitors and verify they're being scraped"""
    config = get_prometheus_config()
    results = []
    
    cmd = "kubectl get servicemonitors.monitoring.coreos.com -A -o json"
    sm_result = run_command(cmd)
    
    if sm_result["exit_code"] != 0:
        return [{
            "name": "servicemonitors",
            "status": False,
            "output": "Failed to get ServiceMonitors",
            "severity": "WARNING"
        }]
    
    try:
        sm_data = json.loads(sm_result["stdout"])
        servicemonitors = sm_data.get("items", [])
        
        response = query_http(f"{config['prometheus_url']}/api/v1/targets")
        active_jobs = set()
        
        if response and response.get("status_code") == 200:
            targets = response.get("data", {}).get("data", {}).get("activeTargets", [])
            for target in targets:
                job = target.get("labels", {}).get("job", "")
                if job:
                    active_jobs.add(job)
        
        sm_by_namespace = {}
        sm_without_targets = []
        sm_with_targets = []
        
        for sm in servicemonitors:
            metadata = sm.get("metadata", {})
            spec = sm.get("spec", {})
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "unknown")
            
            sm_by_namespace[namespace] = sm_by_namespace.get(namespace, 0) + 1
            
            potential_jobs = [
                name,
                f"{namespace}/{name}",
                name.replace("prometheus-", ""),
                name.replace("-metrics", "")
            ]
            
            has_active_targets = any(job in active_jobs or job in pj for pj in potential_jobs for job in active_jobs)
            
            if has_active_targets:
                sm_with_targets.append(f"{namespace}/{name}")
            else:
                endpoints = spec.get("endpoints", [])
                if not endpoints:
                    sm_without_targets.append(f"{namespace}/{name}: No endpoints defined")
                else:
                    sm_without_targets.append(f"{namespace}/{name}: Not being scraped")
        
        total_sm = len(servicemonitors)
        active_sm = len(sm_with_targets)
        
        output = f"ServiceMonitors: {total_sm} total, {active_sm} active\n\n"
        output += "By Namespace:\n"
        for ns in sorted(sm_by_namespace.keys())[:10]:
            output += f"  {ns}: {sm_by_namespace[ns]}\n"
        
        if sm_without_targets:
            output += f"\nInactive/Misconfigured ServiceMonitors ({len(sm_without_targets)}):\n"
            for sm in sm_without_targets[:10]:
                output += f"  - {sm}\n"
        
        critical_monitors = [
            "prometheus/prometheus-kube-prometheus-prometheus",
            "prometheus/prometheus-kube-state-metrics",
            "prometheus/prometheus-prometheus-node-exporter"
        ]
        
        output += "\nCritical ServiceMonitors:\n"
        for monitor_path in critical_monitors:
            if monitor_path in sm_with_targets:
                output += f"  [OK] {monitor_path}: Active\n"
            else:
                output += f"  [FAIL] {monitor_path}: Not found or inactive\n"
        
        status = active_sm > 0 and active_sm >= total_sm * 0.5
        
        results.append({
            "name": "servicemonitors",
            "status": status,
            "output": output.strip(),
            "severity": "WARNING" if not status else "INFO"
        })
        
    except Exception as e:
        results.append({
            "name": "servicemonitors",
            "status": False,
            "output": f"Error analyzing ServiceMonitors: {str(e)}",
            "severity": "WARNING"
        })
    
    return results


def test_metrics_collection() -> List[Dict]:
    """Verify actual metrics are being collected"""
    config = get_prometheus_config()
    results = []
    
    test_queries = [
        {
            "query": "up",
            "name": "up_metric",
            "description": "Basic up metric",
            "check": lambda r: len(r) > 0
        },
        {
            "query": "container_memory_usage_bytes",
            "name": "container_metrics",
            "description": "Container metrics (from cAdvisor)",
            "check": lambda r: len(r) > 0
        },
        {
            "query": "node_cpu_seconds_total",
            "name": "node_metrics",
            "description": "Node exporter metrics",
            "check": lambda r: len(r) > 0
        },
        {
            "query": "kube_pod_info",
            "name": "kube_state_metrics",
            "description": "Kube-state-metrics",
            "check": lambda r: len(r) > 0
        },
        {
            "query": "prometheus_tsdb_head_samples",
            "name": "prometheus_internal",
            "description": "Prometheus internal metrics",
            "check": lambda r: len(r) > 0
        },
        {
            "query": "rate(prometheus_tsdb_head_samples_appended_total[5m])",
            "name": "ingestion_rate",
            "description": "Sample ingestion rate",
            "check": lambda r: len(r) > 0 and any(float(x.get("value", [0, "0"])[1]) > 0 for x in r)
        }
    ]
    
    for test in test_queries:
        response = query_http(f"{config['prometheus_url']}/api/v1/query?query={test['query']}")
        
        if response and response.get("status_code") == 200:
            result_data = response.get("data", {}).get("data", {}).get("result", [])
            
            if test["check"](result_data):
                if test["name"] == "up_metric":
                    up_count = sum(1 for r in result_data if r.get("value", [None, "0"])[1] == "1")
                    total = len(result_data)
                    output = f"{test['description']}: OK - {up_count}/{total} targets up"
                elif test["name"] == "ingestion_rate":
                    rates = [float(r.get("value", [0, "0"])[1]) for r in result_data]
                    avg_rate = sum(rates) / len(rates) if rates else 0
                    output = f"{test['description']}: OK - {avg_rate:.0f} samples/sec"
                else:
                    output = f"{test['description']}: OK - {len(result_data)} series found"
                status = True
            else:
                output = f"{test['description']}: FAILED - No data or check failed"
                status = False
        else:
            output = f"{test['description']}: FAILED - Query failed"
            status = False
        
        results.append({
            "name": test["name"],
            "status": status,
            "output": output,
            "severity": "WARNING" if not status and test["name"] != "ingestion_rate" else "INFO"
        })
    
    return results


def test_tsdb_health() -> List[Dict]:
    """Check Prometheus TSDB health"""
    config = get_prometheus_config()
    
    response = query_http(f"{config['prometheus_url']}/api/v1/status/tsdb")
    
    if not response or response.get("status_code") != 200:
        return [{
            "name": "tsdb_health",
            "status": False,
            "output": "Failed to query TSDB status",
            "severity": "WARNING"
        }]
    
    tsdb_data = response.get("data", {}).get("data", {})
    head_stats = tsdb_data.get("headStats", {})
    
    series = head_stats.get("numSeries", 0)
    samples = head_stats.get("numSamples", 0)
    chunks = head_stats.get("chunks", 0)
    wal_corruptions = head_stats.get("walCorruptions", 0)
    
    output = f"TSDB Statistics:\n"
    output += f"  Series: {series:,}\n"
    output += f"  Samples: {samples:,}\n"
    output += f"  Chunks: {chunks:,}\n"
    output += f"  WAL Corruptions: {wal_corruptions}\n"
    
    # Check if we have actual data
    if series > 0 and samples == 0:
        output += "\n  WARNING: Have series but no samples - possible recent restart"
    
    status = series > 0 and wal_corruptions == 0
    
    return [{
        "name": "tsdb_health",
        "status": status,
        "output": output.strip(),
        "severity": "WARNING" if not status else "INFO"
    }]


def test_rules() -> List[Dict]:
    """Test Prometheus recording and alerting rules"""
    config = get_prometheus_config()
    
    response = query_http(f"{config['prometheus_url']}/api/v1/rules")
    
    if not response or response.get("status_code") != 200:
        return [{
            "name": "prometheus_rules",
            "status": False,
            "output": "Failed to query rules",
            "severity": "WARNING"
        }]
    
    groups = response.get("data", {}).get("data", {}).get("groups", [])
    
    total_groups = len(groups)
    recording_rules = 0
    alerting_rules = 0
    firing_alerts = []
    pending_alerts = []
    
    for group in groups:
        for rule in group.get("rules", []):
            if rule.get("type") == "recording":
                recording_rules += 1
            elif rule.get("type") == "alerting":
                alerting_rules += 1
                state = rule.get("state")
                if state == "firing":
                    firing_alerts.append({
                        "name": rule.get("name"),
                        "severity": rule.get("labels", {}).get("severity", "unknown")
                    })
                elif state == "pending":
                    pending_alerts.append(rule.get("name"))
    
    output = f"Rules Summary:\n"
    output += f"  Groups: {total_groups}\n"
    output += f"  Recording Rules: {recording_rules}\n"
    output += f"  Alerting Rules: {alerting_rules}\n"
    
    if firing_alerts:
        output += f"\nFiring Alerts ({len(firing_alerts)}):\n"
        for alert in firing_alerts[:10]:
            output += f"  - {alert['name']} (severity: {alert['severity']})\n"
    
    if pending_alerts:
        output += f"\nPending Alerts ({len(pending_alerts)}):\n"
        for alert in pending_alerts[:5]:
            output += f"  - {alert}\n"
    
    status = total_groups > 0 and (recording_rules > 0 or alerting_rules > 0)
    
    return [{
        "name": "prometheus_rules",
        "status": status,
        "output": output.strip(),
        "severity": "INFO"
    }]


def test_exporters() -> List[Dict]:
    """Test various Prometheus exporters"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    results = []
    
    exporters = [
        {
            "name": "node-exporter",
            "query": "up{job=~'.*node.*'}",
            "pod_label": "app.kubernetes.io/name=prometheus-node-exporter"
        },
        {
            "name": "kube-state-metrics", 
            "query": "up{job=~'.*kube-state.*'}",
            "pod_label": "app.kubernetes.io/name=kube-state-metrics"
        },
        {
            "name": "pushgateway",
            "query": "up{job=~'.*pushgateway.*'}",
            "pod_label": "app=pushgateway"
        }
    ]
    
    for exporter in exporters:
        cmd = f"kubectl get pods -n {namespace} -l {exporter['pod_label']} --no-headers"
        pod_result = run_command(cmd)
        
        pod_status = "Not found"
        pod_count = 0
        
        if pod_result["exit_code"] == 0 and pod_result["stdout"]:
            lines = [l for l in pod_result["stdout"].split("\n") if l.strip()]
            running = [l for l in lines if "Running" in l]
            pod_count = len(lines)
            pod_status = f"{len(running)}/{pod_count} running"
        
        response = query_http(f"{config['prometheus_url']}/api/v1/query?query={exporter['query']}")
        
        metrics_status = "No metrics"
        up_count = 0
        
        if response and response.get("status_code") == 200:
            result_data = response.get("data", {}).get("data", {}).get("result", [])
            up_count = sum(1 for r in result_data if r.get("value", [None, "0"])[1] == "1")
            total_targets = len(result_data)
            if total_targets > 0:
                metrics_status = f"{up_count}/{total_targets} targets up"
        
        output = f"{exporter['name']}:\n"
        output += f"  Pods: {pod_status}\n"
        output += f"  Metrics: {metrics_status}"
        
        if exporter["name"] == "node-exporter":
            node_result = run_command("kubectl get nodes --no-headers | wc -l")
            if node_result["exit_code"] == 0:
                node_count = int(node_result["stdout"].strip())
                output += f"\n  Node coverage: {pod_count}/{node_count} nodes"
                status = pod_count == node_count and up_count == pod_count
            else:
                status = up_count > 0
        else:
            status = up_count > 0 or (pod_count > 0 and "pushgateway" in exporter["name"])
        
        results.append({
            "name": f"exporter_{exporter['name'].replace('-', '_')}",
            "status": status,
            "output": output,
            "severity": "WARNING" if not status and exporter["name"] != "pushgateway" else "INFO"
        })
    
    return results


def test_prometheus_operator() -> List[Dict]:
    """Test Prometheus Operator"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    cmd = f"kubectl get pods -n {namespace} | grep -E 'prometheus.*operator' | grep -v node-exporter | head -1"
    pod_result = run_command(cmd)
    
    if pod_result["exit_code"] != 0 or not pod_result["stdout"]:
        return [{
            "name": "prometheus_operator",
            "status": False,
            "output": "Prometheus Operator not found",
            "severity": "CRITICAL"
        }]
    
    pod_line = pod_result["stdout"].strip()
    pod_name = pod_line.split()[0]
    pod_status = pod_line.split()[2] if len(pod_line.split()) > 2 else "Unknown"
    
    output = f"Prometheus Operator:\n"
    output += f"  Pod: {pod_name}\n"
    output += f"  Status: {pod_status}\n"
    
    crds = {
        "prometheuses.monitoring.coreos.com": "Prometheus instances",
        "servicemonitors.monitoring.coreos.com": "ServiceMonitors",
        "prometheusrules.monitoring.coreos.com": "PrometheusRules",
        "alertmanagers.monitoring.coreos.com": "Alertmanagers"
    }
    
    installed_crds = 0
    for crd, description in crds.items():
        cmd = f"kubectl get crd {crd} 2>/dev/null"
        if run_command(cmd)["exit_code"] == 0:
            installed_crds += 1
            
            cmd = f"kubectl get {crd.split('.')[0]} -A --no-headers 2>/dev/null | wc -l"
            count_result = run_command(cmd)
            if count_result["exit_code"] == 0:
                count = int(count_result["stdout"].strip()) if count_result["stdout"].strip().isdigit() else 0
                output += f"  {description}: {count} resources\n"
    
    output += f"\nCRDs: {installed_crds}/{len(crds)} installed"
    
    cmd = f"kubectl logs -n {namespace} {pod_name} --tail=50 2>/dev/null | grep -iE 'error|fail' | wc -l"
    log_result = run_command(cmd)
    if log_result["exit_code"] == 0:
        error_count = int(log_result["stdout"].strip()) if log_result["stdout"].strip().isdigit() else 0
        output += f"\nRecent errors in logs: {error_count}"
    
    status = pod_status == "Running" and installed_crds == len(crds)
    
    return [{
        "name": "prometheus_operator",
        "status": status,
        "output": output.strip(),
        "severity": "CRITICAL" if not status else "INFO"
    }]


def main():
    """Main execution"""
    print("=" * 70)
    print("PROMETHEUS STACK HEALTH CHECK")
    print("=" * 70)
    
    config = get_prometheus_config()
    print(f"Configuration:")
    print(f"  Namespace: {config['namespace']}")
    print(f"  Prometheus URL: {config['prometheus_url']}")
    print(f"  Running from: {socket.gethostname()}")
    print("=" * 70)
    print()
    
    all_results = []
    
    test_functions = [
        ("Prometheus API", test_prometheus_api),
        ("Prometheus Uptime", test_prometheus_uptime),
        ("Scrape Targets", test_scrape_targets),
        ("ServiceMonitors", test_servicemonitors),
        ("Metrics Collection", test_metrics_collection),
        ("TSDB Health", test_tsdb_health),
        ("Rules", test_rules),
        ("Exporters", test_exporters),
        ("Prometheus Operator", test_prometheus_operator)
    ]
    
    for test_name, test_func in test_functions:
        print(f"Testing {test_name}...")
        try:
            results = test_func()
            all_results.extend(results)
        except Exception as e:
            all_results.append({
                "name": test_name.lower().replace(" ", "_"),
                "status": False,
                "output": f"Test crashed: {str(e)}",
                "severity": "WARNING"
            })
    
    print("\n" + "=" * 70)
    print("DETAILED RESULTS")
    print("=" * 70)
    
    by_severity = {"CRITICAL": [], "WARNING": [], "INFO": []}
    for result in all_results:
        severity = result.get("severity", "INFO")
        by_severity[severity].append(result)
    
    for severity in ["CRITICAL", "WARNING", "INFO"]:
        items = by_severity[severity]
        if items:
            print(f"\n{severity} ({len(items)} items):")
            print("-" * 50)
            
            for result in items:
                status_text = "[PASS]" if result["status"] else "[FAIL]"
                print(f"\n{status_text} {result['name']}")
                if result["output"]:
                    for line in result["output"].split("\n"):
                        print(f"  {line}")
    
    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"])
    failed = total - passed
    
    critical_failed = sum(1 for r in by_severity["CRITICAL"] if not r["status"])
    warning_failed = sum(1 for r in by_severity["WARNING"] if not r["status"])
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed} ({passed*100//total if total > 0 else 0}%)")
    print(f"Failed: {failed} ({failed*100//total if total > 0 else 0}%)")
    
    if critical_failed > 0:
        print(f"\nCRITICAL FAILURES: {critical_failed}")
    if warning_failed > 0:
        print(f"WARNINGS: {warning_failed}")
    
    print("=" * 70)
    
    exit(1 if critical_failed > 0 else 0)


if __name__ == "__main__":
    main()
