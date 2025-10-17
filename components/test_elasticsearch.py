#!/usr/bin/env python3
"""
Elasticsearch Metrics Analysis
Analyzes Prometheus metrics from Elasticsearch

ENV VARS:
  ELASTICSEARCH_NS (default: elasticsearch)
  ELASTICSEARCH_METRICS_PORT (default: 9114)

Output: JSON array of test results
"""

import os
import sys
import json
import subprocess
from typing import List, Dict, Any, Optional


def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
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


def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.upper()
    }


def get_service_metrics(namespace: str, service: str, port: int) -> Optional[str]:
    """Get metrics from a service endpoint"""
    cmd = f"curl -s --connect-timeout 5 --max-time 10 http://{service}.{namespace}.svc.cluster.local:{port}/metrics"
    result = run_command(cmd, timeout=15)

    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"]
    return None


def parse_metric_value(metrics_text: str, metric_name: str) -> List[float]:
    """Extract values for a specific metric"""
    values = []
    for line in metrics_text.split('\n'):
        if line.startswith(metric_name) and not line.startswith('#'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    values.append(float(parts[-1]))
                except ValueError:
                    pass
    return values


def count_metrics(metrics_text: str) -> int:
    """Count unique metrics"""
    metrics = set()
    for line in metrics_text.split('\n'):
        if line and not line.startswith('#'):
            metric_name = line.split('{')[0].split()[0]
            if metric_name:
                metrics.add(metric_name)
    return len(metrics)


def test_elasticsearch_metrics() -> List[Dict[str, Any]]:
    """Analyze Elasticsearch exporter metrics"""
    namespace = os.getenv("ELASTICSEARCH_NS", "elasticsearch")
    port = int(os.getenv("ELASTICSEARCH_METRICS_PORT", "9114"))
    service = "elasticsearch-metrics"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "elasticsearch_metrics_availability",
            "Check Elasticsearch metrics exporter availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "elasticsearch_metrics_availability",
        "Check Elasticsearch metrics exporter availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Cluster health
    cluster_up = parse_metric_value(metrics_data, "elasticsearch_cluster_health_up")
    if cluster_up:
        is_up = cluster_up[0] == 1.0
        results.append(create_test_result(
            "elasticsearch_cluster_health",
            "Check Elasticsearch cluster health status",
            is_up,
            "Cluster is UP" if is_up else "Cluster is DOWN",
            "CRITICAL" if not is_up else "INFO"
        ))

    # Cluster status (green=0, yellow=1, red=2)
    cluster_status = parse_metric_value(metrics_data, "elasticsearch_cluster_health_status")
    if cluster_status:
        status_val = int(cluster_status[0])
        status_map = {0: "GREEN", 1: "YELLOW", 2: "RED"}
        status_str = status_map.get(status_val, "UNKNOWN")

        results.append(create_test_result(
            "elasticsearch_cluster_status",
            "Check Elasticsearch cluster status",
            status_val == 0,
            f"Cluster status: {status_str}",
            "CRITICAL" if status_val == 2 else ("WARNING" if status_val == 1 else "INFO")
        ))

    # Active nodes
    active_nodes = parse_metric_value(metrics_data, "elasticsearch_cluster_health_number_of_nodes")
    if active_nodes:
        node_count = int(active_nodes[0])
        results.append(create_test_result(
            "elasticsearch_active_nodes",
            "Check Elasticsearch active nodes count",
            node_count > 0,
            f"{node_count} active nodes",
            "WARNING" if node_count == 0 else "INFO"
        ))

    # Active shards
    active_shards = parse_metric_value(metrics_data, "elasticsearch_cluster_health_active_shards")
    if active_shards:
        shard_count = int(active_shards[0])
        results.append(create_test_result(
            "elasticsearch_active_shards",
            "Check Elasticsearch active shards",
            True,
            f"{shard_count} active shards",
            "INFO"
        ))

    # Relocating shards
    relocating = parse_metric_value(metrics_data, "elasticsearch_cluster_health_relocating_shards")
    if relocating:
        relocating_count = int(relocating[0])
        results.append(create_test_result(
            "elasticsearch_relocating_shards",
            "Check Elasticsearch relocating shards",
            relocating_count == 0,
            f"{relocating_count} shards relocating",
            "WARNING" if relocating_count > 5 else "INFO"
        ))

    # Unassigned shards
    unassigned = parse_metric_value(metrics_data, "elasticsearch_cluster_health_unassigned_shards")
    if unassigned:
        unassigned_count = int(unassigned[0])
        results.append(create_test_result(
            "elasticsearch_unassigned_shards",
            "Check Elasticsearch unassigned shards",
            unassigned_count == 0,
            f"{unassigned_count} unassigned shards",
            "CRITICAL" if unassigned_count > 0 else "INFO"
        ))

    return results


def test_elasticsearch() -> List[Dict[str, Any]]:
    """Run all Elasticsearch metrics tests"""
    all_results = test_elasticsearch_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "elasticsearch_summary",
        "Overall Elasticsearch metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_elasticsearch()
        print(json.dumps(results, indent=2))

        critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
        sys.exit(1 if critical_failures > 0 else 0)

    except Exception as e:
        error_result = [create_test_result(
            "test_execution_error",
            "Test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
