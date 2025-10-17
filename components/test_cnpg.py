#!/usr/bin/env python3
"""
CNPG (CloudNativePG) Metrics Analysis
Analyzes Prometheus metrics from CNPG PostgreSQL cluster

ENV VARS:
  CNPG_NS (default: cnpg)
  CNPG_CLUSTER_NAME (default: cluster-cnpg)
  CNPG_METRICS_PORT (default: 9187)

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


def get_pod_ip(namespace: str, pod_name: str) -> Optional[str]:
    """Get pod IP address"""
    cmd = f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.status.podIP}}'"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    return None


def get_metrics_from_pod(pod_ip: str, port: int) -> Optional[str]:
    """Get metrics from a pod via its IP"""
    cmd = f"curl -s --connect-timeout 5 --max-time 10 http://{pod_ip}:{port}/metrics"
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


def test_cnpg_metrics() -> List[Dict[str, Any]]:
    """Analyze CNPG PostgreSQL metrics"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    cluster_name = os.getenv("CNPG_CLUSTER_NAME", "cluster-cnpg")
    metrics_port = int(os.getenv("CNPG_METRICS_PORT", "9187"))

    # Primary pod is usually cluster-name-1
    pod_name = f"{cluster_name}-1"

    results = []

    # Get pod IP
    pod_ip = get_pod_ip(namespace, pod_name)
    if not pod_ip:
        results.append(create_test_result(
            "cnpg_pod_discovery",
            "Check CNPG pod discovery",
            False,
            f"Failed to get IP for pod {pod_name} in namespace {namespace}",
            "CRITICAL"
        ))
        return results

    results.append(create_test_result(
        "cnpg_pod_discovery",
        "Check CNPG pod discovery",
        True,
        f"Found pod {pod_name} at {pod_ip}",
        "INFO"
    ))

    # Get metrics
    metrics_data = get_metrics_from_pod(pod_ip, metrics_port)

    if not metrics_data:
        results.append(create_test_result(
            "cnpg_metrics_availability",
            "Check CNPG metrics endpoint availability",
            False,
            f"Failed to fetch metrics from pod {pod_name} ({pod_ip}:{metrics_port})",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "cnpg_metrics_availability",
        "Check CNPG metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics from pod {pod_name}",
        "INFO"
    ))

    # Database backends
    backends = parse_metric_value(metrics_data, "cnpg_backends_total")
    if backends:
        total_backends = int(sum(backends))
        results.append(create_test_result(
            "cnpg_backends",
            "Check CNPG database backends",
            True,
            f"{total_backends} database backends connected",
            "INFO"
        ))

    # WAL archiving
    wal_archive = parse_metric_value(metrics_data, "cnpg_pg_stat_archiver_archived_count")
    if wal_archive:
        archived_count = int(wal_archive[0]) if wal_archive else 0
        results.append(create_test_result(
            "cnpg_wal_archiving",
            "Check CNPG WAL archiving",
            True,
            f"{archived_count} WAL files archived",
            "INFO"
        ))

    # Database size
    db_size = parse_metric_value(metrics_data, "cnpg_pg_database_size_bytes")
    if db_size:
        total_size_mb = sum(db_size) / 1024 / 1024
        results.append(create_test_result(
            "cnpg_database_size",
            "Check CNPG database size",
            True,
            f"Total database size: {total_size_mb:.2f}MB",
            "INFO"
        ))

    # Replication lag
    replication_lag = parse_metric_value(metrics_data, "cnpg_pg_replication_lag")
    if replication_lag:
        max_lag = max(replication_lag) if replication_lag else 0
        results.append(create_test_result(
            "cnpg_replication_lag",
            "Check CNPG replication lag",
            max_lag < 10,
            f"Max replication lag: {max_lag:.2f}s",
            "WARNING" if max_lag >= 10 else "INFO"
        ))

    # Backup status
    last_backup = parse_metric_value(metrics_data, "barman_cloud_cloudnative_pg_io_last_available_backup_timestamp")
    if last_backup:
        import time
        backup_age_hours = (time.time() - last_backup[0]) / 3600
        results.append(create_test_result(
            "cnpg_backup_status",
            "Check CNPG backup status",
            backup_age_hours < 48,
            f"Last backup: {backup_age_hours:.1f} hours ago",
            "WARNING" if backup_age_hours >= 48 else "INFO"
        ))

    # Postgres uptime
    uptime = parse_metric_value(metrics_data, "cnpg_pg_postmaster_start_time")
    if uptime:
        import time
        uptime_hours = (time.time() - uptime[0]) / 3600
        results.append(create_test_result(
            "cnpg_uptime",
            "Check CNPG PostgreSQL uptime",
            True,
            f"PostgreSQL uptime: {uptime_hours:.1f} hours",
            "INFO"
        ))

    return results


def test_cnpg() -> List[Dict[str, Any]]:
    """Run all CNPG metrics tests"""
    all_results = test_cnpg_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "cnpg_summary",
        "Overall CNPG metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_cnpg()
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
