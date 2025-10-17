#!/usr/bin/env python3
"""
Prometheus and Exporters Metrics Analysis
Analyzes Prometheus metrics from various exporters

ENV VARS:
  PROMETHEUS_NS (default: prometheus)

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


def test_prometheus_server_metrics() -> List[Dict[str, Any]]:
    """Analyze Prometheus server metrics"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    service = "prometheus-kube-prometheus-prometheus"
    port = 9090

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "prometheus_server_metrics",
            "Check Prometheus server metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "prometheus_server_metrics",
        "Check Prometheus server metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Active time series
    active_series = parse_metric_value(metrics_data, "prometheus_tsdb_head_series")
    if active_series:
        series_count = int(active_series[0])
        results.append(create_test_result(
            "prometheus_active_series",
            "Check Prometheus active time series",
            True,
            f"{series_count} active time series",
            "INFO"
        ))

    # Sample ingestion rate
    samples = parse_metric_value(metrics_data, "prometheus_tsdb_head_samples_appended_total")
    if samples:
        total_samples = sum(samples)
        results.append(create_test_result(
            "prometheus_samples_ingested",
            "Check Prometheus samples ingested",
            True,
            f"{int(total_samples)} total samples ingested",
            "INFO"
        ))

    # Storage size
    storage_size = parse_metric_value(metrics_data, "prometheus_tsdb_storage_blocks_bytes")
    if storage_size:
        total_size_gb = sum(storage_size) / 1024 / 1024 / 1024
        results.append(create_test_result(
            "prometheus_storage_size",
            "Check Prometheus storage size",
            True,
            f"Storage: {total_size_gb:.2f} GB",
            "INFO"
        ))

    return results


def test_alertmanager_metrics() -> List[Dict[str, Any]]:
    """Analyze Alertmanager metrics"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    service = "prometheus-kube-prometheus-alertmanager"
    port = 9093

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "alertmanager_metrics",
            "Check Alertmanager metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "WARNING"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "alertmanager_metrics",
        "Check Alertmanager metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Active alerts
    alerts = parse_metric_value(metrics_data, "alertmanager_alerts")
    if alerts:
        alert_count = int(sum(alerts))
        results.append(create_test_result(
            "alertmanager_active_alerts",
            "Check Alertmanager active alerts",
            alert_count == 0,
            f"{alert_count} active alerts",
            "WARNING" if alert_count > 0 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "alertmanager_active_alerts",
            "Check Alertmanager active alerts",
            True,
            "Active alerts metric not available",
            "INFO"
        ))

    return results


def test_node_exporter_metrics() -> List[Dict[str, Any]]:
    """Analyze Node Exporter metrics"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    service = "prometheus-node-exporter"
    port = 9100

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "node_exporter_metrics",
            "Check Node Exporter metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "WARNING"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "node_exporter_metrics",
        "Check Node Exporter metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # CPU metrics
    cpu_seconds = parse_metric_value(metrics_data, "node_cpu_seconds_total")
    if cpu_seconds:
        results.append(create_test_result(
            "node_exporter_cpu_metrics",
            "Check Node Exporter CPU metrics",
            True,
            f"Tracking {len(cpu_seconds)} CPU metrics",
            "INFO"
        ))

    # Memory metrics
    mem_total = parse_metric_value(metrics_data, "node_memory_MemTotal_bytes")
    if mem_total:
        mem_gb = mem_total[0] / 1024 / 1024 / 1024
        results.append(create_test_result(
            "node_exporter_memory_metrics",
            "Check Node Exporter memory metrics",
            True,
            f"Total memory: {mem_gb:.2f} GB",
            "INFO"
        ))

    return results


def test_kube_state_metrics() -> List[Dict[str, Any]]:
    """Analyze Kube State Metrics"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    service = "prometheus-kube-state-metrics"
    port = 8080

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "kube_state_metrics",
            "Check Kube State Metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "WARNING"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "kube_state_metrics",
        "Check Kube State Metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Pod metrics
    pod_count = parse_metric_value(metrics_data, "kube_pod_info")
    if pod_count:
        results.append(create_test_result(
            "kube_state_pod_metrics",
            "Check Kube State pod metrics",
            True,
            f"Tracking {len(pod_count)} pods",
            "INFO"
        ))

    # Deployment metrics
    deployment_count = parse_metric_value(metrics_data, "kube_deployment_status_replicas")
    if deployment_count:
        results.append(create_test_result(
            "kube_state_deployment_metrics",
            "Check Kube State deployment metrics",
            True,
            f"Tracking {len(deployment_count)} deployments",
            "INFO"
        ))

    return results


def test_pushgateway_metrics() -> List[Dict[str, Any]]:
    """Analyze Pushgateway metrics"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    service = "pushgateway"
    port = 9091

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "pushgateway_metrics",
            "Check Pushgateway metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "INFO"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "pushgateway_metrics",
        "Check Pushgateway metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    return results


def test_prometheus() -> List[Dict[str, Any]]:
    """Run all Prometheus and exporter metrics tests"""
    all_results = []

    all_results.extend(test_prometheus_server_metrics())
    all_results.extend(test_alertmanager_metrics())
    all_results.extend(test_node_exporter_metrics())
    all_results.extend(test_kube_state_metrics())
    all_results.extend(test_pushgateway_metrics())

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "prometheus_summary",
        "Overall Prometheus metrics summary",
        passed_checks >= total_checks * 0.6,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.6 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_prometheus()
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
