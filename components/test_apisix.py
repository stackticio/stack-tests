#!/usr/bin/env python3
"""
APISIX Metrics Analysis
Analyzes Prometheus metrics from APISIX API Gateway

ENV VARS:
  APISIX_NS (default: ingress-apisix)
  APISIX_METRICS_PORT (default: 9091)

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


def get_pod_ip(namespace: str, label: str) -> Optional[str]:
    """Get pod IP by label"""
    cmd = f"kubectl get pod -n {namespace} -l {label} -o jsonpath='{{.items[0].status.podIP}}'"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip().strip("'")
    return None


def get_metrics_from_pod(pod_ip: str, port: int, path: str) -> Optional[str]:
    """Get metrics from a pod via its IP"""
    cmd = f"curl -s --connect-timeout 5 --max-time 10 http://{pod_ip}:{port}{path}"
    result = run_command(cmd, timeout=15)

    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"]
    return None


def parse_metric_value(metrics_text: str, metric_name: str) -> List[float]:
    """Extract values for a specific metric"""
    values = []
    for line in metrics_text.split('\n'):
        if line.startswith(metric_name + ' ') and not line.startswith('#'):
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


def test_apisix_metrics() -> List[Dict[str, Any]]:
    """Analyze APISIX metrics"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")
    metrics_port = int(os.getenv("APISIX_METRICS_PORT", "9091"))

    results = []

    # Get APISIX pod IP
    pod_ip = get_pod_ip(namespace, "app.kubernetes.io/name=apisix")
    if not pod_ip:
        results.append(create_test_result(
            "apisix_pod_discovery",
            "Check APISIX pod discovery",
            False,
            f"Failed to find APISIX pod in namespace {namespace}",
            "CRITICAL"
        ))
        return results

    results.append(create_test_result(
        "apisix_pod_discovery",
        "Check APISIX pod discovery",
        True,
        f"Found APISIX pod at {pod_ip}",
        "INFO"
    ))

    # Get metrics
    metrics_data = get_metrics_from_pod(pod_ip, metrics_port, "/apisix/prometheus/metrics")

    if not metrics_data:
        results.append(create_test_result(
            "apisix_metrics_availability",
            "Check APISIX metrics endpoint availability",
            False,
            f"Failed to fetch metrics from pod {pod_ip}:{metrics_port}/apisix/prometheus/metrics",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "apisix_metrics_availability",
        "Check APISIX metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Etcd reachability - CRITICAL if etcd is down
    etcd_reachable = parse_metric_value(metrics_data, "apisix_etcd_reachable")
    if etcd_reachable:
        is_reachable = etcd_reachable[0] == 1.0
        results.append(create_test_result(
            "apisix_etcd_reachable",
            "Check APISIX etcd connectivity",
            is_reachable,
            "Etcd is reachable" if is_reachable else "Etcd is UNREACHABLE!",
            "INFO" if is_reachable else "CRITICAL"
        ))

    # HTTP requests total
    http_requests = parse_metric_value(metrics_data, "apisix_http_requests_total")
    if http_requests:
        total_requests = int(sum(http_requests))
        results.append(create_test_result(
            "apisix_http_requests",
            "Check APISIX HTTP request count",
            True,
            f"{total_requests} total HTTP requests processed",
            "INFO"
        ))

    # HTTP status codes - check for high error rates
    http_status_lines = [line for line in metrics_data.split('\n') if line.startswith('apisix_http_status{')]

    status_2xx = sum([float(line.split()[-1]) for line in http_status_lines if 'code="2' in line])
    status_4xx = sum([float(line.split()[-1]) for line in http_status_lines if 'code="4' in line])
    status_5xx = sum([float(line.split()[-1]) for line in http_status_lines if 'code="5' in line])

    if status_2xx + status_4xx + status_5xx > 0:
        total_status = status_2xx + status_4xx + status_5xx
        error_rate_4xx = (status_4xx / total_status * 100) if total_status > 0 else 0
        error_rate_5xx = (status_5xx / total_status * 100) if total_status > 0 else 0

        # WARNING if >10% 4xx or >1% 5xx errors
        has_problem = error_rate_4xx > 10 or error_rate_5xx > 1

        results.append(create_test_result(
            "apisix_error_rate",
            "Check APISIX HTTP error rate",
            not has_problem,
            f"2xx: {int(status_2xx)}, 4xx: {int(status_4xx)} ({error_rate_4xx:.1f}%), 5xx: {int(status_5xx)} ({error_rate_5xx:.1f}%)",
            "WARNING" if has_problem else "INFO"
        ))

    # Nginx connections
    nginx_conn = parse_metric_value(metrics_data, "apisix_nginx_http_current_connections")
    if nginx_conn:
        connections = int(sum(nginx_conn))
        results.append(create_test_result(
            "apisix_connections",
            "Check APISIX active connections",
            True,
            f"{connections} active HTTP connections",
            "INFO"
        ))

    # Bandwidth usage
    bandwidth_lines = [line for line in metrics_data.split('\n') if line.startswith('apisix_bandwidth{')]
    if bandwidth_lines:
        total_bandwidth = sum([float(line.split()[-1]) for line in bandwidth_lines])
        bandwidth_mb = total_bandwidth / 1024 / 1024

        results.append(create_test_result(
            "apisix_bandwidth",
            "Check APISIX bandwidth usage",
            True,
            f"Total bandwidth: {bandwidth_mb:.2f}MB",
            "INFO"
        ))

    # Shared dict capacity - check if running low on memory
    capacity_lines = [line for line in metrics_data.split('\n') if line.startswith('apisix_shared_dict_capacity_bytes{')]
    free_lines = [line for line in metrics_data.split('\n') if line.startswith('apisix_shared_dict_free_space_bytes{')]

    if capacity_lines and free_lines:
        # Check each shared dict
        for cap_line in capacity_lines:
            dict_name = cap_line.split('name="')[1].split('"')[0] if 'name="' in cap_line else "unknown"
            capacity = float(cap_line.split()[-1])

            # Find matching free space line
            free_line = next((l for l in free_lines if f'name="{dict_name}"' in l), None)
            if free_line:
                free_space = float(free_line.split()[-1])
                used_pct = ((capacity - free_space) / capacity * 100) if capacity > 0 else 0

                # WARNING if >80% of shared dict is used
                has_problem = used_pct > 80

                if has_problem:
                    results.append(create_test_result(
                        f"apisix_shared_dict_{dict_name}",
                        f"Check APISIX shared dict '{dict_name}' usage",
                        False,
                        f"{used_pct:.1f}% used - running low on memory!",
                        "WARNING"
                    ))

    return results


def test_apisix() -> List[Dict[str, Any]]:
    """Run all APISIX metrics tests"""
    all_results = test_apisix_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "apisix_summary",
        "Overall APISIX metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_apisix()
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
