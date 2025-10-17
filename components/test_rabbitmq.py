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

    # Node status
    rabbitmq_up = parse_metric_value(metrics_data, "rabbitmq_identity_info")
    if rabbitmq_up:
        results.append(create_test_result(
            "rabbitmq_node_status",
            "Check RabbitMQ node status",
            True,
            f"RabbitMQ node is running ({len(rabbitmq_up)} node(s))",
            "INFO"
        ))

    # Queue metrics
    queue_messages = parse_metric_value(metrics_data, "rabbitmq_queue_messages")
    if queue_messages:
        total_messages = int(sum(queue_messages))
        results.append(create_test_result(
            "rabbitmq_queue_messages",
            "Check RabbitMQ queue messages",
            True,
            f"{total_messages} messages in queues",
            "WARNING" if total_messages > 10000 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "rabbitmq_queue_messages",
            "Check RabbitMQ queue messages",
            True,
            "Queue messages metric not available (may not have queues yet)",
            "INFO"
        ))

    # Consumers
    consumers = parse_metric_value(metrics_data, "rabbitmq_queue_consumers")
    if consumers:
        total_consumers = int(sum(consumers))
        results.append(create_test_result(
            "rabbitmq_consumers",
            "Check RabbitMQ consumers",
            True,
            f"{total_consumers} active consumers",
            "INFO"
        ))

    # Connections
    connections = parse_metric_value(metrics_data, "rabbitmq_connections")
    if connections:
        connection_count = int(connections[0]) if connections else 0
        results.append(create_test_result(
            "rabbitmq_connections",
            "Check RabbitMQ connections",
            True,
            f"{connection_count} active connections",
            "INFO"
        ))
    else:
        results.append(create_test_result(
            "rabbitmq_connections",
            "Check RabbitMQ connections",
            True,
            "Connections metric not available",
            "INFO"
        ))

    # Channels
    channels = parse_metric_value(metrics_data, "rabbitmq_channels")
    if channels:
        channel_count = int(channels[0]) if channels else 0
        results.append(create_test_result(
            "rabbitmq_channels",
            "Check RabbitMQ channels",
            True,
            f"{channel_count} active channels",
            "INFO"
        ))

    # Memory usage
    memory = parse_metric_value(metrics_data, "rabbitmq_process_resident_memory_bytes")
    if memory:
        memory_mb = memory[0] / 1024 / 1024
        results.append(create_test_result(
            "rabbitmq_memory_usage",
            "Check RabbitMQ memory usage",
            True,
            f"Memory: {memory_mb:.1f}MB",
            "INFO"
        ))

    # Disk space
    disk_free = parse_metric_value(metrics_data, "rabbitmq_disk_space_available_bytes")
    if disk_free:
        disk_gb = disk_free[0] / 1024 / 1024 / 1024
        results.append(create_test_result(
            "rabbitmq_disk_space",
            "Check RabbitMQ disk space",
            disk_gb > 1.0,
            f"Free disk space: {disk_gb:.2f}GB",
            "WARNING" if disk_gb < 1.0 else "INFO"
        ))

    # Message rates
    publish_rate = parse_metric_value(metrics_data, "rabbitmq_channel_messages_published_total")
    if publish_rate:
        total_published = int(sum(publish_rate))
        results.append(create_test_result(
            "rabbitmq_publish_rate",
            "Check RabbitMQ message publish rate",
            True,
            f"{total_published} messages published",
            "INFO"
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
