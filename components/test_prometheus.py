#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_prometheus_json.py - Prometheus Health Check with JSON output
"""

import os
import sys
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
            output = f"Connected to Prometheus at {config['prometheus_url']}, {result_count} targets found"
            status = True
        else:
            output = f"API returned non-success status"
            status = False
    else:
        error = response.get("error", "Unknown error") if response else "No response"
        output = f"Failed to connect: {error}"
        status = False
    
    results.append({
        "name": "prometheus_api",
        "description": "Check Prometheus API connectivity",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    })
    
    config_response = query_http(f"{config['prometheus_url']}/api/v1/status/config")
    if config_response and config_response.get("status_code") == 200:
        yaml_config = config_response.get("data", {}).get("data", {}).get("yaml", "")
        if yaml_config:
            results.append({
                "name": "prometheus_config",
                "description": "Check Prometheus configuration",
                "status": True,
                "output": f"Configuration loaded: {len(yaml_config)} bytes",
                "severity": "info"
            })
    
    return results


def test_scrape_targets() -> List[Dict]:
    """Analyze all Prometheus scrape targets"""
    config = get_prometheus_config()
    
    response = query_http(f"{config['prometheus_url']}/api/v1/targets")
    
    if not response or response.get("status_code") != 200:
        return [{
            "name": "scrape_targets",
            "description": "Check Prometheus scrape targets health",
            "status": False,
            "output": f"Failed to query targets: {response.get('error', 'Unknown') if response else 'No response'}",
            "severity": "critical"
        }]
    
    targets = response.get("data", {}).get("data", {}).get("activeTargets", [])
    
    targets_by_job = {}
    unhealthy_targets = []
    
    for target in targets:
        job = target.get("labels", {}).get("job", "unknown")
        health = target.get("health", "unknown")
        
        if job not in targets_by_job:
            targets_by_job[job] = {"up": 0, "down": 0}
        
        if health == "up":
            targets_by_job[job]["up"] += 1
        elif health == "down":
            targets_by_job[job]["down"] += 1
            unhealthy_targets.append({
                "job": job,
                "instance": target.get("labels", {}).get("instance", "unknown"),
                "error": target.get("lastError", "")[:100]
            })
    
    total_targets = len(targets)
    total_up = sum(j["up"] for j in targets_by_job.values())
    
    output = f"{total_up}/{total_targets} targets healthy"
    if unhealthy_targets:
        output += f", {len(unhealthy_targets)} unhealthy: "
        output += ", ".join([f"{t['job']}/{t['instance']}" for t in unhealthy_targets[:3]])
    
    status = total_up >= total_targets * 0.8 if total_targets > 0 else False
    
    return [{
        "name": "scrape_targets",
        "description": "Check Prometheus scrape targets health",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_servicemonitors() -> List[Dict]:
    """Test ServiceMonitors"""
    config = get_prometheus_config()
    
    cmd = "kubectl get servicemonitors.monitoring.coreos.com -A -o json"
    sm_result = run_command(cmd)
    
    if sm_result["exit_code"] != 0:
        return [{
            "name": "servicemonitors",
            "description": "Check ServiceMonitors configuration",
            "status": False,
            "output": "Failed to get ServiceMonitors",
            "severity": "warning"
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
        
        sm_with_targets = 0
        for sm in servicemonitors:
            name = sm.get("metadata", {}).get("name", "unknown")
            if any(name in job or job in name for job in active_jobs):
                sm_with_targets += 1
        
        total_sm = len(servicemonitors)
        output = f"{total_sm} ServiceMonitors found, {sm_with_targets} active"
        status = sm_with_targets > 0 and sm_with_targets >= total_sm * 0.5
        
        return [{
            "name": "servicemonitors",
            "description": "Check ServiceMonitors configuration",
            "status": status,
            "output": output,
            "severity": "warning" if not status else "info"
        }]
        
    except Exception as e:
        return [{
            "name": "servicemonitors",
            "description": "Check ServiceMonitors configuration",
            "status": False,
            "output": f"Error analyzing ServiceMonitors: {str(e)}",
            "severity": "warning"
        }]


def test_metrics_collection() -> List[Dict]:
    """Verify metrics are being collected"""
    config = get_prometheus_config()
    results = []
    
    test_queries = [
        ("up", "up_metric", "Basic up metric"),
        ("container_memory_usage_bytes", "container_metrics", "Container metrics"),
        ("node_cpu_seconds_total", "node_metrics", "Node exporter metrics"),
        ("kube_pod_info", "kube_state_metrics", "Kube-state-metrics"),
        ("prometheus_tsdb_head_samples", "prometheus_internal", "Prometheus internal metrics"),
        ("rate(prometheus_tsdb_head_samples_appended_total[5m])", "ingestion_rate", "Sample ingestion rate")
    ]
    
    for query, name, description in test_queries:
        response = query_http(f"{config['prometheus_url']}/api/v1/query?query={query}")
        
        if response and response.get("status_code") == 200:
            result_data = response.get("data", {}).get("data", {}).get("result", [])
            
            if result_data:
                if name == "up_metric":
                    up_count = sum(1 for r in result_data if r.get("value", [None, "0"])[1] == "1")
                    total = len(result_data)
                    output = f"{up_count}/{total} targets up"
                elif name == "ingestion_rate":
                    rates = [float(r.get("value", [0, "0"])[1]) for r in result_data]
                    avg_rate = sum(rates) / len(rates) if rates else 0
                    output = f"{avg_rate:.0f} samples/sec"
                else:
                    output = f"{len(result_data)} series found"
                status = True
            else:
                output = "No data"
                status = False
        else:
            output = "Query failed"
            status = False
        
        results.append({
            "name": name,
            "description": description,
            "status": status,
            "output": output,
            "severity": "warning" if not status and name != "ingestion_rate" else "info"
        })
    
    return results


def test_tsdb_health() -> List[Dict]:
    """Check Prometheus TSDB health"""
    config = get_prometheus_config()
    
    response = query_http(f"{config['prometheus_url']}/api/v1/status/tsdb")
    
    if not response or response.get("status_code") != 200:
        return [{
            "name": "tsdb_health",
            "description": "Check TSDB health",
            "status": False,
            "output": "Failed to query TSDB status",
            "severity": "warning"
        }]
    
    tsdb_data = response.get("data", {}).get("data", {})
    head_stats = tsdb_data.get("headStats", {})
    
    series = head_stats.get("numSeries", 0)
    samples = head_stats.get("numSamples", 0)
    chunks = head_stats.get("chunks", 0)
    wal_corruptions = head_stats.get("walCorruptions", 0)
    
    output = f"Series: {series}, Samples: {samples}, Chunks: {chunks}, WAL Corruptions: {wal_corruptions}"
    
    if series > 0 and samples == 0:
        output += " (WARNING: Have series but no samples)"
    
    status = series > 0 and wal_corruptions == 0
    
    return [{
        "name": "tsdb_health",
        "description": "Check TSDB health",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def test_prometheus_operator() -> List[Dict]:
    """Test Prometheus Operator"""
    config = get_prometheus_config()
    namespace = config["namespace"]
    
    cmd = f"kubectl get pods -n {namespace} | grep -E 'prometheus.*operator' | grep -v node-exporter | head -1"
    pod_result = run_command(cmd)
    
    if pod_result["exit_code"] != 0 or not pod_result["stdout"]:
        return [{
            "name": "prometheus_operator",
            "description": "Check Prometheus Operator",
            "status": False,
            "output": "Prometheus Operator not found",
            "severity": "critical"
        }]
    
    pod_line = pod_result["stdout"].strip()
    pod_name = pod_line.split()[0]
    pod_status = pod_line.split()[2] if len(pod_line.split()) > 2 else "Unknown"
    
    # Check CRDs
    crds = ["prometheuses", "servicemonitors", "prometheusrules", "alertmanagers"]
    installed_crds = 0
    
    for crd in crds:
        cmd = f"kubectl get crd {crd}.monitoring.coreos.com 2>/dev/null"
        if run_command(cmd)["exit_code"] == 0:
            installed_crds += 1
    
    output = f"Pod: {pod_name} ({pod_status}), CRDs: {installed_crds}/{len(crds)}"
    status = pod_status == "Running" and installed_crds == len(crds)
    
    return [{
        "name": "prometheus_operator",
        "description": "Check Prometheus Operator",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    }]


def test_prometheus():
    """Run all Prometheus tests and return JSON results"""
    all_results = []
    
    # Run all tests
    all_results.extend(test_prometheus_api())
    all_results.extend(test_scrape_targets())
    all_results.extend(test_servicemonitors())
    all_results.extend(test_metrics_collection())
    all_results.extend(test_tsdb_health())
    all_results.extend(test_prometheus_operator())
    
    return all_results


if __name__ == "__main__":
    results = test_prometheus()
    
    # Output as JSON
    print(json.dumps(results, indent=2))
    
    # Exit code based on critical failures
    critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "critical")
    sys.exit(1 if critical_failures > 0 else 0)
