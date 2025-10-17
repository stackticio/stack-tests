#!/usr/bin/env python3
"""
RabbitMQ Metrics Analysis
Analyzes Prometheus metrics from RabbitMQ

ENV VARS:
  RABBITMQ_NS (default: rabbitmq-system)
  RABBITMQ_METRICS_PORT (default: 15692)

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


def test_rabbitmq_metrics() -> List[Dict[str, Any]]:
    """Analyze RabbitMQ metrics"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    port = int(os.getenv("RABBITMQ_METRICS_PORT", "15692"))
    service = "rabbitmq"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "rabbitmq_metrics_availability",
            "Check RabbitMQ metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "rabbitmq_metrics_availability",
        "Check RabbitMQ metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Uptime - check if RabbitMQ is running
    uptime = parse_metric_value(metrics_data, "rabbitmq_erlang_uptime_seconds")
    if uptime:
        uptime_hours = uptime[0] / 3600
        results.append(create_test_result(
            "rabbitmq_uptime",
            "Check RabbitMQ uptime",
            True,
            f"RabbitMQ running for {uptime_hours:.1f} hours",
            "INFO"
        ))
    else:
        results.append(create_test_result(
            "rabbitmq_uptime",
            "Check RabbitMQ uptime",
            False,
            "Unable to determine uptime - service may be down",
            "CRITICAL"
        ))
        return results

    # Queue messages ready (unprocessed)
    messages_ready = parse_metric_value(metrics_data, "rabbitmq_queue_messages_ready")
    messages_unacked = parse_metric_value(metrics_data, "rabbitmq_queue_messages_unacked")

    if messages_ready:
        ready_count = int(sum(messages_ready))
        unacked_count = int(sum(messages_unacked)) if messages_unacked else 0
        total_messages = ready_count + unacked_count

        # CRITICAL: Messages piling up with no consumers
        has_problem = ready_count > 1000
        results.append(create_test_result(
            "rabbitmq_queue_messages",
            "Check RabbitMQ queue backlog",
            not has_problem,
            f"{ready_count} ready, {unacked_count} unacked (total: {total_messages})",
            "WARNING" if has_problem else "INFO"
        ))

    # Consumers - CRITICAL if messages but no consumers
    consumers = parse_metric_value(metrics_data, "rabbitmq_queue_consumers")
    if consumers:
        total_consumers = int(sum(consumers))
        has_messages = messages_ready and sum(messages_ready) > 0
        no_consumers = total_consumers == 0

        # Problem: messages waiting but no consumers to process them
        if has_messages and no_consumers:
            results.append(create_test_result(
                "rabbitmq_consumers",
                "Check RabbitMQ consumers",
                False,
                f"0 consumers but {int(sum(messages_ready))} messages waiting!",
                "CRITICAL"
            ))
        else:
            results.append(create_test_result(
                "rabbitmq_consumers",
                "Check RabbitMQ consumers",
                True,
                f"{total_consumers} active consumers",
                "INFO"
            ))

    # Connection churn - check if connections are flapping
    conn_opened = parse_metric_value(metrics_data, "rabbitmq_connections_opened_total")
    conn_closed = parse_metric_value(metrics_data, "rabbitmq_connections_closed_total")
    if conn_opened and conn_closed:
        opened = int(conn_opened[0])
        closed = int(conn_closed[0])
        # If connections are constantly opening/closing, that's a problem
        if closed > 100:
            results.append(create_test_result(
                "rabbitmq_connection_stability",
                "Check RabbitMQ connection stability",
                False,
                f"{closed} connections closed (possible connection flapping)",
                "WARNING"
            ))
        else:
            results.append(create_test_result(
                "rabbitmq_connection_stability",
                "Check RabbitMQ connection stability",
                True,
                f"{opened} opened, {closed} closed",
                "INFO"
            ))

    # Memory usage - check against limit
    memory = parse_metric_value(metrics_data, "rabbitmq_process_resident_memory_bytes")
    memory_limit = parse_metric_value(metrics_data, "rabbitmq_resident_memory_limit_bytes")

    if memory and memory_limit:
        memory_mb = memory[0] / 1024 / 1024
        limit_mb = memory_limit[0] / 1024 / 1024
        memory_pct = (memory[0] / memory_limit[0]) * 100

        # Warning if using >80% of memory limit
        has_problem = memory_pct > 80
        results.append(create_test_result(
            "rabbitmq_memory_usage",
            "Check RabbitMQ memory usage",
            not has_problem,
            f"Memory: {memory_mb:.1f}MB / {limit_mb:.1f}MB ({memory_pct:.1f}% used)",
            "WARNING" if has_problem else "INFO"
        ))

    # Disk space - check against limit
    disk_free = parse_metric_value(metrics_data, "rabbitmq_disk_space_available_bytes")
    disk_limit = parse_metric_value(metrics_data, "rabbitmq_disk_space_available_limit_bytes")

    if disk_free and disk_limit:
        disk_gb = disk_free[0] / 1024 / 1024 / 1024
        limit_gb = disk_limit[0] / 1024 / 1024 / 1024

        # CRITICAL if below disk limit threshold
        below_limit = disk_free[0] < disk_limit[0]
        results.append(create_test_result(
            "rabbitmq_disk_space",
            "Check RabbitMQ disk space",
            not below_limit,
            f"Free: {disk_gb:.2f}GB (limit: {limit_gb:.2f}GB)" + (" - BELOW LIMIT!" if below_limit else ""),
            "CRITICAL" if below_limit else "INFO"
        ))

    # File descriptors - check if running out
    fds_used = parse_metric_value(metrics_data, "rabbitmq_process_open_fds")
    fds_limit = parse_metric_value(metrics_data, "rabbitmq_process_max_fds")

    if fds_used and fds_limit:
        fds_pct = (fds_used[0] / fds_limit[0]) * 100
        has_problem = fds_pct > 80

        results.append(create_test_result(
            "rabbitmq_file_descriptors",
            "Check RabbitMQ file descriptor usage",
            not has_problem,
            f"{int(fds_used[0])}/{int(fds_limit[0])} FDs used ({fds_pct:.1f}%)",
            "WARNING" if has_problem else "INFO"
        ))

    # Erlang processes
    erlang_procs = parse_metric_value(metrics_data, "rabbitmq_erlang_processes_used")
    erlang_limit = parse_metric_value(metrics_data, "rabbitmq_erlang_processes_limit")

    if erlang_procs and erlang_limit:
        proc_pct = (erlang_procs[0] / erlang_limit[0]) * 100
        has_problem = proc_pct > 80

        results.append(create_test_result(
            "rabbitmq_erlang_processes",
            "Check RabbitMQ Erlang process usage",
            not has_problem,
            f"{int(erlang_procs[0])}/{int(erlang_limit[0])} processes ({proc_pct:.1f}%)",
            "WARNING" if has_problem else "INFO"
        ))

    return results


def test_rabbitmq() -> List[Dict[str, Any]]:
    """Run all RabbitMQ metrics tests"""
    all_results = test_rabbitmq_metrics()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "rabbitmq_summary",
        "Overall RabbitMQ metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_rabbitmq()
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
