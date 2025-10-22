#!/usr/bin/env python3
"""
RabbitMQ Resource Estimation
Analyzes actual resource usage and provides scaling recommendations

Uses:
- Prometheus metrics (CPU, memory, disk usage over time)
- kubectl get pod resources (requests/limits)
- kubectl top (current usage)
- Service metrics (queue depth, connections, etc.)

ENV VARS:
  RABBITMQ_NS (default: rabbitmq-system)
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
                "cpu": parts[1],  # e.g., "25m"
                "memory": parts[2]  # e.g., "128Mi"
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


def analyze_rabbitmq_resources() -> List[Dict[str, Any]]:
    """Analyze RabbitMQ resource usage and provide recommendations"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    prom_host = os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local")
    prom_port = int(os.getenv("PROMETHEUS_PORT", "9090"))

    results = []

    # Get pod configuration
    pod_resources = get_pod_resources(namespace, "app.kubernetes.io/name=rabbitmq")
    if not pod_resources:
        results.append(create_result(
            "rabbitmq_pod_discovery",
            "Discover RabbitMQ pod configuration",
            False,
            f"Failed to find RabbitMQ pod in namespace {namespace}",
            "CRITICAL"
        ))
        return results

    pod_name = pod_resources["pod_name"]
    requests = pod_resources["requests"]
    limits = pod_resources["limits"]

    results.append(create_result(
        "rabbitmq_pod_discovery",
        "Discover RabbitMQ pod configuration",
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
            "rabbitmq_current_usage",
            "Check RabbitMQ current resource usage",
            True,
            f"Current usage: CPU={current_usage['cpu']} ({cpu_current}m), Memory={current_usage['memory']} ({mem_current:.1f}Mi)",
            "INFO"
        ))

        # Compare with requests/limits
        if "cpu" in requests:
            cpu_request = parse_cpu(requests["cpu"])
            cpu_usage_pct = (cpu_current / cpu_request * 100) if cpu_request > 0 else 0
        else:
            cpu_request = 0
            cpu_usage_pct = 0

        if "memory" in requests:
            mem_request = parse_memory(requests["memory"])
            mem_usage_pct = (mem_current / mem_request * 100) if mem_request > 0 else 0
        else:
            mem_request = 0
            mem_usage_pct = 0

        # CPU analysis
        if cpu_request > 0:
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
                "rabbitmq_cpu_sizing",
                "Analyze RabbitMQ CPU sizing",
                passed,
                f"CPU: {cpu_current:.1f}m / {cpu_request:.1f}m ({cpu_usage_pct:.1f}% utilized) | {recommendation}",
                severity
            ))

        # Memory analysis
        if mem_request > 0:
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
                "rabbitmq_memory_sizing",
                "Analyze RabbitMQ memory sizing",
                passed,
                f"Memory: {mem_current:.1f}Mi / {mem_request:.1f}Mi ({mem_usage_pct:.1f}% utilized) | {recommendation}",
                severity
            ))

    # Query Prometheus for historical metrics (last hour average)
    cpu_query = f'rate(container_cpu_usage_seconds_total{{namespace="{namespace}",pod=~"{pod_name}"}}[1h])'
    cpu_results = query_prometheus(cpu_query, prom_host, prom_port)

    if cpu_results:
        # Convert to millicores (rate is in cores/second, multiply by 1000)
        avg_cpu = sum([float(r["value"][1]) for r in cpu_results]) * 1000
        results.append(create_result(
            "rabbitmq_cpu_trend",
            "Analyze RabbitMQ CPU trend (1 hour avg)",
            True,
            f"Average CPU usage over last hour: {avg_cpu:.1f}m",
            "INFO"
        ))

    # Memory trend
    mem_query = f'container_memory_working_set_bytes{{namespace="{namespace}",pod=~"{pod_name}"}}'
    mem_results = query_prometheus(mem_query, prom_host, prom_port)

    if mem_results:
        avg_mem_bytes = sum([float(r["value"][1]) for r in mem_results]) / len(mem_results)
        avg_mem_mi = avg_mem_bytes / 1024 / 1024
        results.append(create_result(
            "rabbitmq_memory_trend",
            "Analyze RabbitMQ memory trend",
            True,
            f"Memory working set: {avg_mem_mi:.1f}Mi",
            "INFO"
        ))

    # Queue depth analysis for scaling recommendations
    queue_query = 'rabbitmq_queue_messages_ready'
    queue_results = query_prometheus(queue_query, prom_host, prom_port)

    if queue_results:
        total_queued = sum([float(r["value"][1]) for r in queue_results])
        if total_queued > 10000:
            results.append(create_result(
                "rabbitmq_scale_recommendation",
                "RabbitMQ scaling recommendation based on queue depth",
                False,
                f"HIGH queue backlog: {int(total_queued)} messages waiting | RECOMMENDATION: Scale up consumers or add RabbitMQ replicas",
                "WARNING"
            ))
        else:
            results.append(create_result(
                "rabbitmq_scale_recommendation",
                "RabbitMQ scaling recommendation based on queue depth",
                True,
                f"Queue depth healthy: {int(total_queued)} messages",
                "INFO"
            ))

    return results


def test_rabbitmq() -> List[Dict[str, Any]]:
    """Run RabbitMQ resource analysis"""
    all_results = analyze_rabbitmq_resources()

    # Summary
    total_checks = len(all_results)
    passed_checks = sum(1 for r in all_results if r["status"])

    all_results.append(create_result(
        "rabbitmq_resources_summary",
        "Overall RabbitMQ resource analysis summary",
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
        error_result = [create_result(
            "test_execution_error",
            "Test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
