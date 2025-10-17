#!/usr/bin/env python3
"""
GMP Alertmanager Metrics Analysis
Analyzes Prometheus metrics from GMP (Google Managed Prometheus) Alertmanager

ENV VARS:
  GMP_NS (default: gmp-system)
  GMP_ALERTMANAGER_PORT (default: 9093)

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


def test_gmp_alertmanager_metrics() -> List[Dict[str, Any]]:
    """Analyze GMP Alertmanager metrics"""
    namespace = os.getenv("GMP_NS", "gmp-system")
    port = int(os.getenv("GMP_ALERTMANAGER_PORT", "9093"))
    service = "alertmanager"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "gmp_alertmanager_metrics_availability",
            "Check GMP Alertmanager metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "gmp_alertmanager_metrics_availability",
        "Check GMP Alertmanager metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Alertmanager status
    alerts = parse_metric_value(metrics_data, "alertmanager_alerts")
    if alerts:
        active_alerts = int(sum(alerts))
        results.append(create_test_result(
            "gmp_alertmanager_active_alerts",
            "Check GMP Alertmanager active alerts",
            True,
            f"{active_alerts} active alerts",
            "WARNING" if active_alerts > 0 else "INFO"
        ))

    # Silences
    silences = parse_metric_value(metrics_data, "alertmanager_silences")
    if silences:
        active_silences = int(silences[0]) if silences else 0
        results.append(create_test_result(
            "gmp_alertmanager_silences",
            "Check GMP Alertmanager silences",
            True,
            f"{active_silences} active silences",
            "INFO"
        ))

    # Notifications
    notifications = parse_metric_value(metrics_data, "alertmanager_notifications_total")
    if notifications:
        total_notifications = int(sum(notifications))
        results.append(create_test_result(
            "gmp_alertmanager_notifications",
            "Check GMP Alertmanager notifications",
            True,
            f"{total_notifications} total notifications sent",
            "INFO"
        ))

    # Config status
    config_hash = parse_metric_value(metrics_data, "alertmanager_config_hash")
    if config_hash:
        results.append(create_test_result(
            "gmp_alertmanager_config",
            "Check GMP Alertmanager configuration",
            True,
            "Configuration loaded successfully",
            "INFO"
        ))

    return results


def test_gmp_alertmanager() -> List[Dict[str, Any]]:
    """Run all GMP Alertmanager metrics tests"""
    all_results = test_gmp_alertmanager_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "gmp_alertmanager_summary",
        "Overall GMP Alertmanager metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_gmp_alertmanager()
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
