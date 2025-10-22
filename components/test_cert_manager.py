#!/usr/bin/env python3
"""
Cert-Manager Resource Estimation
Analyzes actual resource usage and provides scaling recommendations

Uses:
- kubectl get pod resources (requests/limits)
- kubectl top (current usage)
- Cert-manager metrics (certificates, sync operations)

ENV VARS:
  CERT_MANAGER_NS (default: cert-manager)
  CERT_MANAGER_PORT (default: 9402)

Output: JSON with resource analysis and recommendations
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


def create_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.upper()
    }


def get_pod_resources(namespace: str, label: str) -> Optional[Dict]:
    """Get pod resource requests and limits"""
    cmd = f"kubectl get pod -n {namespace} -l {label} -o json"
    result = run_command(cmd)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])
            if data.get("items"):
                pod = data["items"][0]
                container = pod["spec"]["containers"][0]
                return {
                    "pod_name": pod["metadata"]["name"],
                    "requests": container.get("resources", {}).get("requests", {}),
                    "limits": container.get("resources", {}).get("limits", {})
                }
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
    return None


def get_pod_current_usage(namespace: str, pod_name: str) -> Optional[Dict]:
    """Get current CPU and memory usage from kubectl top"""
    cmd = f"kubectl top pod {pod_name} -n {namespace} --no-headers"
    result = run_command(cmd)

    if result["exit_code"] == 0 and result["stdout"]:
        parts = result["stdout"].split()
        if len(parts) >= 3:
            return {
                "cpu": parts[1],
                "memory": parts[2]
            }
    return None


def parse_cpu(cpu_str: str) -> float:
    """Parse CPU string to millicores"""
    if not cpu_str:
        return 0.0
    if cpu_str.endswith('m'):
        return float(cpu_str[:-1])
    return float(cpu_str) * 1000


def parse_memory(mem_str: str) -> float:
    """Parse memory string to Mi"""
    if not mem_str:
        return 0.0
    if mem_str.endswith('Ki'):
        return float(mem_str[:-2]) / 1024
    elif mem_str.endswith('Mi'):
        return float(mem_str[:-2])
    elif mem_str.endswith('Gi'):
        return float(mem_str[:-2]) * 1024
    return float(mem_str) / 1024 / 1024


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


def analyze_cert_manager_component(component_name: str, app_label: str) -> List[Dict[str, Any]]:
    """Analyze a cert-manager component's resource usage"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    port = int(os.getenv("CERT_MANAGER_PORT", "9402"))

    results = []

    # Get pod configuration
    pod_resources = get_pod_resources(namespace, f"app.kubernetes.io/name={app_label}")
    if not pod_resources:
        results.append(create_result(
            f"cert_manager_{component_name}_pod_discovery",
            f"Discover cert-manager {component_name} pod configuration",
            False,
            f"Failed to find cert-manager {component_name} pod in namespace {namespace}",
            "CRITICAL"
        ))
        return results

    pod_name = pod_resources["pod_name"]
    requests = pod_resources["requests"]
    limits = pod_resources["limits"]

    results.append(create_result(
        f"cert_manager_{component_name}_pod_discovery",
        f"Discover cert-manager {component_name} pod configuration",
        True,
        f"Found pod: {pod_name} | Requests: CPU={requests.get('cpu', 'N/A')}, Memory={requests.get('memory', 'N/A')} | Limits: CPU={limits.get('cpu', 'N/A')}, Memory={limits.get('memory', 'N/A')}",
        "INFO"
    ))

    # Get current usage from kubectl top
    current_usage = get_pod_current_usage(namespace, pod_name)
    if current_usage:
        cpu_current = parse_cpu(current_usage["cpu"])
        mem_current = parse_memory(current_usage["memory"])

        results.append(create_result(
            f"cert_manager_{component_name}_current_usage",
            f"Check cert-manager {component_name} current resource usage",
            True,
            f"Current usage: CPU={current_usage['cpu']} ({cpu_current}m), Memory={current_usage['memory']} ({mem_current:.1f}Mi)",
            "INFO"
        ))

        # Compare with requests
        if "cpu" in requests:
            cpu_request = parse_cpu(requests["cpu"])
            cpu_usage_pct = (cpu_current / cpu_request * 100) if cpu_request > 0 else 0

            if cpu_usage_pct > 80:
                recommendation = f"INCREASE CPU request from {requests['cpu']} to {int(cpu_current * 1.5)}m"
                severity = "WARNING"
                passed = False
            elif cpu_usage_pct < 20:
                recommendation = f"DECREASE CPU request from {requests['cpu']} to {int(cpu_current * 2)}m"
                severity = "INFO"
                passed = True
            else:
                recommendation = "CPU request is appropriately sized"
                severity = "INFO"
                passed = True

            results.append(create_result(
                f"cert_manager_{component_name}_cpu_sizing",
                f"Analyze cert-manager {component_name} CPU sizing",
                passed,
                f"CPU: {cpu_current:.1f}m / {cpu_request:.1f}m ({cpu_usage_pct:.1f}% utilized) | {recommendation}",
                severity
            ))

        if "memory" in requests:
            mem_request = parse_memory(requests["memory"])
            mem_usage_pct = (mem_current / mem_request * 100) if mem_request > 0 else 0

            if mem_usage_pct > 80:
                recommendation = f"INCREASE memory request from {requests['memory']} to {int(mem_current * 1.5)}Mi"
                severity = "WARNING"
                passed = False
            elif mem_usage_pct < 20:
                recommendation = f"DECREASE memory request from {requests['memory']} to {int(mem_current * 2)}Mi"
                severity = "INFO"
                passed = True
            else:
                recommendation = "Memory request is appropriately sized"
                severity = "INFO"
                passed = True

            results.append(create_result(
                f"cert_manager_{component_name}_memory_sizing",
                f"Analyze cert-manager {component_name} memory sizing",
                passed,
                f"Memory: {mem_current:.1f}Mi / {mem_request:.1f}Mi ({mem_usage_pct:.1f}% utilized) | {recommendation}",
                severity
            ))

    # Get metrics for controller only
    if component_name == "controller":
        service_name = "cert-manager"
        metrics_cmd = f"curl -s http://{service_name}.{namespace}.svc.cluster.local:{port}/metrics"
        metrics_result = run_command(metrics_cmd, timeout=10)

        if metrics_result["exit_code"] == 0 and metrics_result["stdout"]:
            metrics_data = metrics_result["stdout"]

            # Certificate ready status
            ready_values = parse_metric_value(metrics_data, "certmanager_certificate_ready_status")
            if ready_values:
                ready_count = sum(1 for v in ready_values if v == 1.0)
                results.append(create_result(
                    "cert_manager_certificate_ready",
                    "Check certificate ready status",
                    ready_count == len(ready_values),
                    f"{ready_count}/{len(ready_values)} certificates ready",
                    "WARNING" if ready_count < len(ready_values) else "INFO"
                ))

            # Sync operations
            sync_values = parse_metric_value(metrics_data, "certmanager_controller_sync_call_count")
            if sync_values:
                total_syncs = sum(sync_values)
                results.append(create_result(
                    "cert_manager_sync_operations",
                    "Check controller sync operations",
                    True,
                    f"{int(total_syncs)} total sync operations",
                    "INFO"
                ))

    return results


def test_cert_manager() -> List[Dict[str, Any]]:
    """Run cert-manager resource analysis"""
    all_results = []

    # Analyze all three components
    components = [
        ("controller", "cert-manager"),
        ("cainjector", "cainjector"),
        ("webhook", "webhook")
    ]

    for component_name, app_label in components:
        all_results.extend(analyze_cert_manager_component(component_name, app_label))

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_result(
        "cert_manager_resources_summary",
        "Overall cert-manager resource analysis summary",
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
        error_result = [create_result(
            "test_execution_error",
            "Test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
