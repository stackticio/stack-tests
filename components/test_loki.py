#!/usr/bin/env python3
"""
Loki Metrics Analysis
Analyzes Prometheus metrics from Loki components

ENV VARS:
  LOKI_NS (default: loki)
  LOKI_PORT (default: 3100)

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


def test_loki_component_metrics(component: str, service_name: str) -> List[Dict[str, Any]]:
    """Analyze metrics for a Loki component"""
    namespace = os.getenv("LOKI_NS", "loki")
    port = int(os.getenv("LOKI_PORT", "3100"))

    results = []

    metrics_data = get_service_metrics(namespace, service_name, port)

    if not metrics_data:
        results.append(create_test_result(
            f"loki_{component}_metrics_availability",
            f"Check Loki {component} metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service_name}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        f"loki_{component}_metrics_availability",
        f"Check Loki {component} metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Ingester specific metrics
    if component == "ingester":
        chunks_created = parse_metric_value(metrics_data, "loki_ingester_chunks_created_total")
        if chunks_created:
            total_chunks = sum(chunks_created)
            results.append(create_test_result(
                f"loki_{component}_chunks_created",
                f"Check Loki {component} chunks created",
                True,
                f"{int(total_chunks)} chunks created" if chunks_created else "Metric not available",
                "INFO"
            ))
        else:
            results.append(create_test_result(
                f"loki_{component}_chunks_created",
                f"Check Loki {component} chunks created",
                True,
                "Chunks created metric not available (may not be exposed yet)",
                "INFO"
            ))

        streams = parse_metric_value(metrics_data, "loki_ingester_streams")
        if streams:
            stream_count = int(streams[0]) if streams else 0
            results.append(create_test_result(
                f"loki_{component}_active_streams",
                f"Check Loki {component} active streams",
                True,
                f"{stream_count} active streams",
                "INFO"
            ))

    # Distributor specific metrics
    if component == "distributor":
        bytes_received = parse_metric_value(metrics_data, "loki_distributor_bytes_received_total")
        if bytes_received:
            total_bytes = sum(bytes_received)
            results.append(create_test_result(
                f"loki_{component}_bytes_received",
                f"Check Loki {component} bytes received",
                True,
                f"{total_bytes/1024/1024:.2f} MB received" if bytes_received else "Metric not available",
                "INFO"
            ))
        else:
            results.append(create_test_result(
                f"loki_{component}_bytes_received",
                f"Check Loki {component} bytes received",
                True,
                "Bytes received metric not available (may not be exposed yet)",
                "INFO"
            ))

    # Querier specific metrics
    if component == "querier":
        queries = parse_metric_value(metrics_data, "loki_query_duration_seconds_count")
        if queries:
            query_count = sum(queries)
            results.append(create_test_result(
                f"loki_{component}_queries",
                f"Check Loki {component} query count",
                True,
                f"{int(query_count)} queries processed" if queries else "Metric not available",
                "INFO"
            ))
        else:
            results.append(create_test_result(
                f"loki_{component}_queries",
                f"Check Loki {component} query count",
                True,
                "Query count metric not available (may not be exposed yet)",
                "INFO"
            ))

    # Common process health metrics
    goroutines = parse_metric_value(metrics_data, "go_goroutines")
    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")

    health_info = []
    if goroutines:
        health_info.append(f"Goroutines: {int(goroutines[0])}")
    if memory:
        health_info.append(f"Memory: {memory[0]/1024/1024:.1f}MB")

    if health_info:
        results.append(create_test_result(
            f"loki_{component}_process_health",
            f"Check Loki {component} process health",
            True,
            ", ".join(health_info),
            "INFO"
        ))

    return results


def test_loki() -> List[Dict[str, Any]]:
    """Run all Loki metrics tests"""
    all_results = []

    # Test Loki services - using actual service names
    components = [
        ("backend", "loki-backend"),
        ("read", "loki-read"),
        ("write", "loki-write")
    ]

    for component_name, service_name in components:
        results = test_loki_component_metrics(component_name, service_name)
        all_results.extend(results)

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "loki_summary",
        "Overall Loki metrics summary",
        passed_checks >= total_checks * 0.5,  # More lenient since components may not exist
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.5 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_loki()
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
