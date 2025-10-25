#!/usr/bin/env python3
"""
Keycloak Metrics Analysis
Analyzes Prometheus metrics from Keycloak

ENV VARS:
  KEYCLOAK_NS (default: keycloak)
  KEYCLOAK_PORT (default: 9000)

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


def get_service_metrics(namespace: str, service: str, port: int, path: str = "/metrics") -> Optional[str]:
    """Get metrics from Keycloak service endpoint"""
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


def test_keycloak_metrics() -> List[Dict[str, Any]]:
    """Analyze Keycloak metrics"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")
    port = int(os.getenv("KEYCLOAK_PORT", "9000"))
    service = "kc-server-service"

    results = []

    # Get metrics
    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "keycloak_metrics_availability",
            "Check Keycloak metrics endpoint availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}/metrics",
            "CRITICAL"
        ))
        return results

    # Count total metrics
    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "keycloak_metrics_availability",
        "Check Keycloak metrics endpoint availability",
        True,
        f"Successfully fetched {metric_count} metrics from Keycloak",
        "INFO"
    ))

    # Check JVM memory usage
    jvm_memory_used = parse_metric_value(metrics_data, "jvm_memory_used_bytes")
    jvm_memory_max = parse_metric_value(metrics_data, "jvm_memory_max_bytes")

    if jvm_memory_used is not None and jvm_memory_max is not None and jvm_memory_max > 0:
        memory_usage_percent = (jvm_memory_used / jvm_memory_max * 100)
        memory_used_mb = jvm_memory_used / (1024**2)
        memory_max_mb = jvm_memory_max / (1024**2)

        results.append(create_test_result(
            "keycloak_jvm_memory",
            "Check Keycloak JVM memory usage",
            memory_usage_percent < 90,
            f"JVM Memory: {memory_used_mb:.2f}MB used / {memory_max_mb:.2f}MB max ({memory_usage_percent:.1f}% used)",
            "WARNING" if memory_usage_percent >= 90 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "keycloak_jvm_memory",
            "Check Keycloak JVM memory usage",
            True,
            "JVM memory metrics not available or not applicable",
            "INFO"
        ))

    # Check JVM threads
    jvm_threads_current = parse_metric_value(metrics_data, "jvm_threads_current")
    if jvm_threads_current is not None:
        results.append(create_test_result(
            "keycloak_jvm_threads",
            "Check Keycloak JVM thread count",
            jvm_threads_current < 1000,
            f"JVM has {int(jvm_threads_current)} active threads",
            "WARNING" if jvm_threads_current >= 1000 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "keycloak_jvm_threads",
            "Check Keycloak JVM thread count",
            True,
            "JVM thread metrics not available",
            "INFO"
        ))

    # Check cache evictions
    cache_evictions = parse_metric_value(metrics_data, "vendor_cache_evictions_total")
    if cache_evictions is not None:
        results.append(create_test_result(
            "keycloak_cache_evictions",
            "Check Keycloak cache evictions",
            cache_evictions < 1000,
            f"Cache has {int(cache_evictions)} total evictions",
            "WARNING" if cache_evictions >= 1000 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "keycloak_cache_evictions",
            "Check Keycloak cache evictions",
            True,
            "Cache eviction metrics not available",
            "INFO"
        ))

    # Check HTTP connections
    http_connections = parse_metric_value(metrics_data, "vendor_http_server_active_requests")
    if http_connections is not None:
        results.append(create_test_result(
            "keycloak_http_connections",
            "Check Keycloak active HTTP requests",
            http_connections < 100,
            f"Keycloak has {int(http_connections)} active HTTP requests",
            "WARNING" if http_connections >= 100 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "keycloak_http_connections",
            "Check Keycloak active HTTP requests",
            True,
            "HTTP connection metrics not available",
            "INFO"
        ))

    # Check database pool
    db_pool_active = parse_metric_value(metrics_data, "agroal_active_count")
    db_pool_max = parse_metric_value(metrics_data, "agroal_max_used_count")

    if db_pool_active is not None:
        pool_info = f"Database pool: {int(db_pool_active)} active connections"
        if db_pool_max is not None:
            pool_info += f" (max used: {int(db_pool_max)})"

        results.append(create_test_result(
            "keycloak_db_pool",
            "Check Keycloak database connection pool",
            db_pool_active < 50,
            pool_info,
            "WARNING" if db_pool_active >= 50 else "INFO"
        ))
    else:
        results.append(create_test_result(
            "keycloak_db_pool",
            "Check Keycloak database connection pool",
            True,
            "Database pool metrics not available",
            "INFO"
        ))

    return results


def test_keycloak() -> List[Dict[str, Any]]:
    """Run all Keycloak metrics tests"""
    all_results = test_keycloak_metrics()

    # Add summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "keycloak_summary",
        "Overall Keycloak metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_keycloak()
        print(json.dumps(results, indent=2))

        # Exit with error if critical failures
        critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
        sys.exit(1 if critical_failures > 0 else 0)
    except Exception as e:
        error_result = create_test_result(
            "keycloak_test_error",
            "Keycloak test execution error",
            False,
            f"Error running Keycloak tests: {str(e)}",
            "CRITICAL"
        )
        print(json.dumps([error_result], indent=2))
        sys.exit(1)
