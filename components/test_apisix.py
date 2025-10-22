#!/usr/bin/env python3
"""
APISIX Resource Estimation
Analyzes actual resource usage and provides scaling recommendations

Uses:
- kubectl get pod resources (requests/limits)
- kubectl top (current usage)
- Prometheus metrics (HTTP request rate, error rate)

ENV VARS:
  APISIX_NS (default: ingress-apisix)
  PROMETHEUS_HOST (default: prometheus.prometheus.svc.cluster.local)
  PROMETHEUS_PORT (default: 9090)

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


def query_prometheus(query: str, prom_host: str, prom_port: int) -> Optional[List[Dict]]:
    """Query Prometheus and return results"""
    url = f"http://{prom_host}:{prom_port}/api/v1/query?query={query}"
    cmd = f"curl -s '{url}'"
    result = run_command(cmd, timeout=15)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])
            if data.get("status") == "success":
                return data.get("data", {}).get("result", [])
        except json.JSONDecodeError:
            pass
    return None


def get_pod_resources(namespace: str, label: str) -> Optional[Dict]:
    """Get pod resource requests and limits"""
    cmd = f"kubectl get pod -n {namespace} -l {label} -o json"
    result = run_command(cmd)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])
            if data.get("items"):
                pod = data["items"][0]
                # Find apisix container (not init containers)
                container = None
                for c in pod["spec"]["containers"]:
                    if "apisix" in c["name"].lower() and "wait" not in c["name"].lower():
                        container = c
                        break

                if container:
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
    cmd = f"kubectl top pod {pod_name} -n {namespace} --no-headers --containers"
    result = run_command(cmd)

    if result["exit_code"] == 0 and result["stdout"]:
        # Parse container-level output and find apisix container
        for line in result["stdout"].split('\n'):
            parts = line.split()
            if len(parts) >= 4 and "apisix" in parts[1].lower() and "wait" not in parts[1].lower():
                return {
                    "cpu": parts[2],
                    "memory": parts[3]
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


def analyze_apisix_resources() -> List[Dict[str, Any]]:
    """Analyze APISIX resource usage and provide recommendations"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")
    prom_host = os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local")
    prom_port = int(os.getenv("PROMETHEUS_PORT", "9090"))

    results = []

    # Get pod configuration
    pod_resources = get_pod_resources(namespace, "app.kubernetes.io/name=apisix")
    if not pod_resources:
        results.append(create_result(
            "apisix_pod_discovery",
            "Discover APISIX pod configuration",
            False,
            f"Failed to find APISIX pod in namespace {namespace}",
            "CRITICAL"
        ))
        return results

    pod_name = pod_resources["pod_name"]
    requests = pod_resources["requests"]
    limits = pod_resources["limits"]

    results.append(create_result(
        "apisix_pod_discovery",
        "Discover APISIX pod configuration",
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
            "apisix_current_usage",
            "Check APISIX current resource usage",
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
                "apisix_cpu_sizing",
                "Analyze APISIX CPU sizing",
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
                "apisix_memory_sizing",
                "Analyze APISIX memory sizing",
                passed,
                f"Memory: {mem_current:.1f}Mi / {mem_request:.1f}Mi ({mem_usage_pct:.1f}% utilized) | {recommendation}",
                severity
            ))

    # Get APISIX pod IP for direct metrics access
    cmd = f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.status.podIP}}'"
    result = run_command(cmd)

    if result["exit_code"] == 0 and result["stdout"]:
        pod_ip = result["stdout"].strip()

        # Get HTTP request rate from APISIX metrics
        metrics_cmd = f"curl -s http://{pod_ip}:9091/apisix/prometheus/metrics"
        metrics_result = run_command(metrics_cmd)

        if metrics_result["exit_code"] == 0 and metrics_result["stdout"]:
            metrics_data = metrics_result["stdout"]

            # Parse total requests
            total_requests = 0
            for line in metrics_data.split('\n'):
                if line.startswith('apisix_http_requests_total '):
                    try:
                        total_requests = int(float(line.split()[-1]))
                        break
                    except ValueError:
                        pass

            if total_requests > 0:
                results.append(create_result(
                    "apisix_traffic_load",
                    "Analyze APISIX traffic load",
                    True,
                    f"Total HTTP requests processed: {total_requests}",
                    "INFO"
                ))

            # Parse error rates
            http_2xx = 0
            http_4xx = 0
            http_5xx = 0

            for line in metrics_data.split('\n'):
                if 'apisix_http_status{' in line and 'code="2' in line:
                    try:
                        http_2xx += int(float(line.split()[-1]))
                    except ValueError:
                        pass
                elif 'apisix_http_status{' in line and 'code="4' in line:
                    try:
                        http_4xx += int(float(line.split()[-1]))
                    except ValueError:
                        pass
                elif 'apisix_http_status{' in line and 'code="5' in line:
                    try:
                        http_5xx += int(float(line.split()[-1]))
                    except ValueError:
                        pass

            total_status = http_2xx + http_4xx + http_5xx
            if total_status > 0:
                error_rate_4xx = (http_4xx / total_status * 100)
                error_rate_5xx = (http_5xx / total_status * 100)

                if error_rate_5xx > 1 or error_rate_4xx > 10:
                    results.append(create_result(
                        "apisix_error_rate",
                        "Analyze APISIX HTTP error rates",
                        False,
                        f"Error rates: 2xx={http_2xx}, 4xx={http_4xx} ({error_rate_4xx:.1f}%), 5xx={http_5xx} ({error_rate_5xx:.1f}%) | High error rate detected",
                        "WARNING"
                    ))
                else:
                    results.append(create_result(
                        "apisix_error_rate",
                        "Analyze APISIX HTTP error rates",
                        True,
                        f"Error rates healthy: 2xx={http_2xx}, 4xx={http_4xx} ({error_rate_4xx:.1f}%), 5xx={http_5xx} ({error_rate_5xx:.1f}%)",
                        "INFO"
                    ))

    return results


def test_apisix() -> List[Dict[str, Any]]:
    """Run APISIX resource analysis"""
    all_results = analyze_apisix_resources()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_result(
        "apisix_resources_summary",
        "Overall APISIX resource analysis summary",
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
        error_result = [create_result(
            "test_execution_error",
            "Test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
