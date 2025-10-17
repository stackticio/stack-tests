#!/usr/bin/env python3
"""
Cert-Manager Metrics Analysis
Analyzes Prometheus metrics from cert-manager services

ENV VARS:
  CERT_MANAGER_NS (default: cert-manager)
  CERT_MANAGER_PORT (default: 9402)

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


def test_cert_manager_controller_metrics() -> List[Dict[str, Any]]:
    """Analyze cert-manager controller metrics"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    port = int(os.getenv("CERT_MANAGER_PORT", "9402"))
    service = "cert-manager"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "cert_manager_controller_metrics",
            "Check cert-manager controller metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "cert_manager_controller_metrics",
        "Check cert-manager controller metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Certificate expiration
    exp_values = parse_metric_value(metrics_data, "certmanager_certificate_expiration_timestamp_seconds")
    if exp_values:
        import time
        current_time = time.time()
        expiring_soon = sum(1 for v in exp_values if 0 < (v - current_time) / 86400 < 30)

        if expiring_soon > 0:
            results.append(create_test_result(
                "cert_manager_certificate_expiration",
                "Check certificate expiration status",
                False,
                f"{len(exp_values)} certificates tracked, {expiring_soon} expiring in <30 days",
                "WARNING"
            ))
        else:
            results.append(create_test_result(
                "cert_manager_certificate_expiration",
                "Check certificate expiration status",
                True,
                f"{len(exp_values)} certificates tracked, all >30 days to expiry",
                "INFO"
            ))

    # Certificate ready status
    ready_values = parse_metric_value(metrics_data, "certmanager_certificate_ready_status")
    if ready_values:
        ready_count = sum(1 for v in ready_values if v == 1.0)
        results.append(create_test_result(
            "cert_manager_certificate_ready",
            "Check certificate ready status",
            ready_count == len(ready_values),
            f"{ready_count}/{len(ready_values)} certificates ready",
            "WARNING" if ready_count < len(ready_values) else "INFO"
        ))

    # Sync call count
    sync_values = parse_metric_value(metrics_data, "certmanager_controller_sync_call_count")
    if sync_values:
        total_syncs = sum(sync_values)
        results.append(create_test_result(
            "cert_manager_sync_operations",
            "Check controller sync operations",
            True,
            f"{int(total_syncs)} total sync operations",
            "INFO"
        ))

    # Process health
    goroutines = parse_metric_value(metrics_data, "go_goroutines")
    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")

    health_info = []
    if goroutines:
        health_info.append(f"Goroutines: {int(goroutines[0])}")
    if memory:
        health_info.append(f"Memory: {memory[0]/1024/1024:.1f}MB")

    if health_info:
        results.append(create_test_result(
            "cert_manager_process_health",
            "Check cert-manager process health",
            True,
            ", ".join(health_info),
            "INFO"
        ))

    return results


def test_cert_manager_cainjector_metrics() -> List[Dict[str, Any]]:
    """Analyze cert-manager CA injector metrics"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    port = int(os.getenv("CERT_MANAGER_PORT", "9402"))
    service = "cert-manager-cainjector"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "cert_manager_cainjector_metrics",
            "Check cert-manager CA injector metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "cert_manager_cainjector_metrics",
        "Check cert-manager CA injector metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Process health
    goroutines = parse_metric_value(metrics_data, "go_goroutines")
    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")

    health_info = []
    if goroutines:
        health_info.append(f"Goroutines: {int(goroutines[0])}")
    if memory:
        health_info.append(f"Memory: {memory[0]/1024/1024:.1f}MB")

    if health_info:
        results.append(create_test_result(
            "cert_manager_cainjector_health",
            "Check CA injector process health",
            True,
            ", ".join(health_info),
            "INFO"
        ))

    return results


def test_cert_manager_webhook_metrics() -> List[Dict[str, Any]]:
    """Analyze cert-manager webhook metrics"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    port = int(os.getenv("CERT_MANAGER_PORT", "9402"))
    service = "cert-manager-webhook"

    results = []

    metrics_data = get_service_metrics(namespace, service, port)

    if not metrics_data:
        results.append(create_test_result(
            "cert_manager_webhook_metrics",
            "Check cert-manager webhook metrics availability",
            False,
            f"Failed to fetch metrics from {service}.{namespace}:{port}",
            "CRITICAL"
        ))
        return results

    metric_count = count_metrics(metrics_data)
    results.append(create_test_result(
        "cert_manager_webhook_metrics",
        "Check cert-manager webhook metrics availability",
        True,
        f"Successfully fetched {metric_count} unique metrics",
        "INFO"
    ))

    # Process health
    goroutines = parse_metric_value(metrics_data, "go_goroutines")
    memory = parse_metric_value(metrics_data, "process_resident_memory_bytes")

    health_info = []
    if goroutines:
        health_info.append(f"Goroutines: {int(goroutines[0])}")
    if memory:
        health_info.append(f"Memory: {memory[0]/1024/1024:.1f}MB")

    if health_info:
        results.append(create_test_result(
            "cert_manager_webhook_health",
            "Check webhook process health",
            True,
            ", ".join(health_info),
            "INFO"
        ))

    return results


def test_cert_manager() -> List[Dict[str, Any]]:
    """Run all cert-manager metrics tests"""
    all_results = []

    all_results.extend(test_cert_manager_controller_metrics())
    all_results.extend(test_cert_manager_cainjector_metrics())
    all_results.extend(test_cert_manager_webhook_metrics())

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_test_result(
        "cert_manager_summary",
        "Overall cert-manager metrics summary",
        passed_checks >= total_checks * 0.7,
        f"{passed_checks}/{total_checks} checks passed ({passed_checks*100//total_checks if total_checks > 0 else 0}%)",
        "INFO" if passed_checks >= total_checks * 0.7 else "WARNING"
    ))

    return all_results


if __name__ == "__main__":
    try:
        results = test_cert_manager()
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
