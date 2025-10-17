#!/usr/bin/env python3
"""
Grafana Metrics Analysis
Analyzes Prometheus metrics from Grafana

ENV VARS:
  GRAFANA_NS (default: grafana)
  GRAFANA_PORT (default: 3000)

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
        if line.startswith(metric_name + " ") and not line.startswith('#'):
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


def test_grafana_metrics() -> List[Dict[str, Any]]:
    """Analyze Grafana metrics"""
    namespace = os.getenv("GRAFANA_NS", "grafana")
    port = int(os.getenv("GRAFANA_PORT", "3000"))
    service = "grafana"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "grafana_metrics_availability",
            "Check Grafana metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "grafana_metrics_availability",
        "Check Grafana metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Active users/sessions
    active_users = parse_metric_value(metrics_data, "grafana_stat_totals_dashboard")
    if active_users:
        dashboard_count = int(active_users[0])
        results.append(create_test_result(
            "grafana_dashboards",
            "Check Grafana dashboard count",
            True,
            f"{dashboard_count} dashboards configured",
            "INFO"
        ))

    # Datasources
    datasources = parse_metric_value(metrics_data, "grafana_stat_total_datasources")
    if datasources:
        ds_count = int(datasources[0])
        results.append(create_test_result(
            "grafana_datasources",
            "Check Grafana datasources count",
            ds_count > 0,
            f"{ds_count} datasources configured",
            "WARNING" if ds_count == 0 else "INFO"
        ))

    # Active users
    active_sessions = parse_metric_value(metrics_data, "grafana_stat_active_users")
    if active_sessions:
        user_count = int(active_sessions[0])
        results.append(create_test_result(
            "grafana_active_users",
            "Check Grafana active users",
            True,
            f"{user_count} active users",
            "INFO"
        ))

    # HTTP request duration
    http_duration = parse_metric_value(metrics_data, "grafana_http_request_duration_seconds_sum")
    if http_duration:
        total_duration = sum(http_duration)
        results.append(create_test_result(
            "grafana_http_performance",
            "Check Grafana HTTP request performance",
            True,
            f"Total HTTP request duration: {total_duration:.2f}s",
            "INFO"
        ))

    # Process health
    goroutines = parse_metric_value(metrics_data, "go_goroutines")
    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")

    health_info = []
    if goroutines:
        health_info.append(f"Goroutines: {int(goroutines[0])}")
    if memory:
        health_info.append(f"Memory: {memory[0]/1024/1024:.1f}MB")

    if health_info:
        results.append(create_test_result(
            "grafana_process_health",
            "Check Grafana process health",
            True,
            ", ".join(health_info),
            "INFO"
        ))

    return results


def test_grafana() -> List[Dict[str, Any]]:
    """Run all Grafana metrics tests"""
    all_results = test_grafana_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "grafana_summary",
        "Overall Grafana metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_grafana()
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
