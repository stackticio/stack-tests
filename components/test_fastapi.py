#!/usr/bin/env python3
"""
FastAPI Metrics Analysis
Analyzes Prometheus metrics from FastAPI application

ENV VARS:
  FASTAPI_NS (default: fastapi)
  FASTAPI_PORT (default: 80)

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


def test_fastapi_metrics() -> List[Dict[str, Any]]:
    """Analyze FastAPI metrics"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    port = int(os.getenv("FASTAPI_PORT", "80"))
    service = "fastapi"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "fastapi_metrics_availability",
            "Check FastAPI metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "fastapi_metrics_availability",
        "Check FastAPI metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # App status
    app_status = parse_metric_value(metrics_data, "fastapi_app_status")
    if app_status:
        # Check if ready status is 1.0
        ready = any(val == 1.0 for val in app_status)
        results.append(create_test_result(
            "fastapi_app_status",
            "Check FastAPI application status",
            ready,
            "Application is ready" if ready else "Application not ready",
            "INFO" if ready else "WARNING"
        ))

    # HTTP requests
    http_requests = parse_metric_value(metrics_data, "fastapi_http_requests_total")
    if http_requests:
        total_requests = int(sum(http_requests))
        results.append(create_test_result(
            "fastapi_http_requests",
            "Check FastAPI HTTP requests",
            True,
            f"{total_requests} total HTTP requests processed",
            "INFO"
        ))
    else:
        results.append(create_test_result(
            "fastapi_http_requests",
            "Check FastAPI HTTP requests",
            True,
            "No HTTP requests processed yet",
            "INFO"
        ))

    # Active requests
    active_requests = parse_metric_value(metrics_data, "fastapi_http_active_requests")
    if active_requests:
        active_count = int(sum(active_requests))
        results.append(create_test_result(
            "fastapi_active_requests",
            "Check FastAPI active requests",
            True,
            f"{active_count} active requests",
            "INFO"
        ))

    # Process metrics
    cpu_seconds = parse_metric_value(metrics_data, "process_cpu_seconds_total")
    if cpu_seconds:
        results.append(create_test_result(
            "fastapi_cpu_usage",
            "Check FastAPI CPU usage",
            True,
            f"CPU time: {cpu_seconds[0]:.2f}s",
            "INFO"
        ))

    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")
    if memory:
        memory_mb = memory[0] / 1024 / 1024
        results.append(create_test_result(
            "fastapi_memory_usage",
            "Check FastAPI memory usage",
            True,
            f"Memory: {memory_mb:.1f}MB",
            "INFO"
        ))

    # Python version info
    app_info = parse_metric_value(metrics_data, "fastapi_app_info_info")
    if app_info:
        results.append(create_test_result(
            "fastapi_app_info",
            "Check FastAPI application info",
            True,
            "Application info available",
            "INFO"
        ))

    return results


def test_fastapi() -> List[Dict[str, Any]]:
    """Run all FastAPI metrics tests"""
    all_results = test_fastapi_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "fastapi_summary",
        "Overall FastAPI metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_fastapi()
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
