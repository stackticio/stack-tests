#!/usr/bin/env python3
"""
Metrics Server Analysis
Analyzes Kubernetes metrics-server

ENV VARS:
  METRICS_SERVER_NS (default: kube-system)
  METRICS_SERVER_PORT (default: 443)

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
    """Get metrics from a service endpoint (HTTPS)"""
    cmd = f"curl -s -k --connect-timeout 5 --max-time 10 https://{service}.{namespace}.svc.cluster.local:{port}/metrics"
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


def test_metrics_server() -> List[Dict[str, Any]]:
    """Analyze Metrics Server"""
    namespace = os.getenv("METRICS_SERVER_NS", "kube-system")
    port = int(os.getenv("METRICS_SERVER_PORT", "443"))
    service = "metrics-server"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "metrics_server_availability",
            "Check Metrics Server endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "metrics_server_availability",
        "Check Metrics Server endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # API server requests
    apiserver_requests = parse_metric_value(metrics_data, "apiserver_request_total")
    if apiserver_requests:
        total_requests = int(sum(apiserver_requests))
        results.append(create_test_result(
            "metrics_server_api_requests",
            "Check Metrics Server API requests",
            True,
            f"{total_requests} total API requests",
            "INFO"
        ))

    # Process stats
    cpu_seconds = parse_metric_value(metrics_data, "process_cpu_seconds_total")
    if cpu_seconds:
        results.append(create_test_result(
            "metrics_server_cpu",
            "Check Metrics Server CPU usage",
            True,
            f"CPU usage: {cpu_seconds[0]:.2f}s",
            "INFO"
        ))

    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")
    if memory:
        memory_mb = memory[0] / 1024 / 1024
        results.append(create_test_result(
            "metrics_server_memory",
            "Check Metrics Server memory usage",
            True,
            f"Memory: {memory_mb:.1f}MB",
            "INFO"
        ))

    # Go routines
    goroutines = parse_metric_value(metrics_data, "go_goroutines")
    if goroutines:
        results.append(create_test_result(
            "metrics_server_goroutines",
            "Check Metrics Server goroutines",
            True,
            f"{int(goroutines[0])} active goroutines",
            "INFO"
        ))

    # Summary
    total_checks = len(results)
    passed_checks = sum(1 for r in results if r["status"])

    results.append(create_test_result(
        "metrics_server_summary",
        "Overall Metrics Server summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_metrics_server()
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
