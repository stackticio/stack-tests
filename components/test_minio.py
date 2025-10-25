#!/usr/bin/env python3
"""
MinIO Metrics Analysis
Analyzes Prometheus metrics from MinIO

ENV VARS:
  MINIO_NS (default: minio)
  MINIO_PORT (default: 9000)

Output: JSON array of test results
"""

import subprocess
import sys
import json
import os
import re
from typing import Dict, Any, Optional, List


def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.upper()
    }


def run_command(cmd: str, timeout: int = 30) -> Optional[str]:
    """Run a shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        return None


def get_service_metrics(namespace: str, service: str, port: int, path: str = "/minio/v2/metrics/cluster") -> Optional[str]:
    """Get metrics from MinIO service endpoint"""
    cmd = f"curl -s --connect-timeout 5 --max-time 10 http://{service}.{namespace}.svc.cluster.local:{port}{path}"
    return run_command(cmd)


def parse_metric_value(metrics_data: str, metric_name: str) -> Optional[float]:
    """Parse a specific metric value from Prometheus metrics"""
    pattern = rf'{metric_name}(?:\{{[^}}]*\}})?\s+([\d.e+-]+)'
    match = re.search(pattern, metrics_data)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def count_metrics(metrics_data: str) -> int:
    """Count total number of metrics"""
    lines = [line for line in metrics_data.split('\n') if line and not line.startswith('#')]
    return len(lines)


def test_minio_metrics() -> List[Dict[str, Any]]:
    """Analyze MinIO metrics"""
    namespace = os.getenv("MINIO_NS", "minio")
    port = int(os.getenv("MINIO_PORT", "9000"))
    service = "minio"

    results = []

    # Get metrics
    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "minio_metrics_availability",
            "Check MinIO metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}/minio/v2/metrics/cluster",
            "CRITICAL"
        ))
        return results

    # Count total metrics
    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "minio_metrics_availability",
        "Check MinIO metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} metrics from MinIO",
        "INFO"
    ))

    # Check bucket count
    bucket_total = parse_metric_value(metrics_data, "minio_cluster_bucket_total")
    if bucket_total is not None:
        results.append(create_test_result(
            "minio_bucket_count",
            "Check MinIO bucket count",
            bucket_total >= 0,
            f"MinIO has {int(bucket_total)} buckets configured",
            "INFO"
        ))
    else:
        results.append(create_test_result(
            "minio_bucket_count",
            "Check MinIO bucket count",
            False,
            "Failed to parse minio_cluster_bucket_total metric",
            "WARNING"
        ))

    # Check storage capacity
    capacity_free = parse_metric_value(metrics_data, "minio_cluster_capacity_raw_free_bytes")
    capacity_total = parse_metric_value(metrics_data, "minio_cluster_capacity_raw_total_bytes")

    if capacity_free is not None and capacity_total is not None:
        capacity_used = capacity_total - capacity_free
        usage_percent = (capacity_used / capacity_total * 100) if capacity_total > 0 else 0

        # Convert to GB for readability
        free_gb = capacity_free / (1024**3)
        total_gb = capacity_total / (1024**3)
        used_gb = capacity_used / (1024**3)

        results.append(create_test_result(
            "minio_storage_capacity",
            "Check MinIO storage capacity and usage",
            usage_percent < 90,
            f"Storage: {used_gb:.2f}GB used / {total_gb:.2f}GB total ({usage_percent:.1f}% used, {free_gb:.2f}GB free)",
            "WARNING" if usage_percent >= 90 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "minio_storage_capacity",
            "Check MinIO storage capacity and usage",
            False,
            "Failed to parse storage capacity metrics",
            "WARNING"
        ))

    # Check nodes online
    nodes_online = parse_metric_value(metrics_data, "minio_cluster_nodes_online_total")
    if nodes_online is not None:
        results.append(create_test_result(
            "minio_nodes_online",
            "Check MinIO cluster nodes online",
            nodes_online >= 1,
            f"MinIO cluster has {int(nodes_online)} node(s) online",
            "CRITICAL" if nodes_online < 1 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "minio_nodes_online",
            "Check MinIO cluster nodes online",
            False,
            "Failed to parse minio_cluster_nodes_online_total metric",
            "WARNING"
        ))

    # Check disk offline
    disks_offline = parse_metric_value(metrics_data, "minio_cluster_disk_offline_total")
    if disks_offline is not None:
        results.append(create_test_result(
            "minio_disks_offline",
            "Check MinIO disks offline",
            disks_offline == 0,
            f"MinIO has {int(disks_offline)} disk(s) offline",
            "CRITICAL" if disks_offline > 0 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "minio_disks_offline",
            "Check MinIO disks offline",
            True,
            "No disk offline metrics found (likely all disks online)",
            "INFO"
        ))

    return results


def test_minio() -> List[Dict[str, Any]]:
    """Run all MinIO metrics tests"""
    all_results = test_minio_metrics()

    # Add summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "minio_summary",
        "Overall MinIO metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_minio()
        print(json.dumps(results, indent=2))

        # Exit with error if critical failures
        critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
        sys.exit(1 if critical_failures > 0 else 0)
    except Exception as e:
        error_result = create_test_result(
            "minio_test_error",
            "MinIO test execution error",
            False,
            f"Error running MinIO tests: {str(e)}",
            "CRITICAL"
        )
        print(json.dumps([error_result], indent=2))
        sys.exit(1)
