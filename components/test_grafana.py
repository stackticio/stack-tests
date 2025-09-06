#!/usr/bin/env python3
"""
Grafana Health Check Script - Structured version
Tests Grafana configuration dynamically with JSON output format

ENV VARS:
  GRAFANA_NAMESPACE (default: grafana)
  GRAFANA_ADMIN_PASSWORD (optional, for API auth)

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import subprocess
import sys
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

NAMESPACE = os.getenv('GRAFANA_NAMESPACE', 'grafana')
ADMIN_PASSWORD = os.getenv('GRAFANA_ADMIN_PASSWORD', 'admin')

# Try multiple common passwords
DEFAULT_PASSWORDS = ["default_password", "admin", "prom-operator", ADMIN_PASSWORD]

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def run_command(command: str, env: Optional[Dict[str, str]] = None, timeout: int = 10) -> Dict[str, Any]:
    """Run shell command and return results"""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": (completed.stdout or '').strip(),
            "stderr": (completed.stderr or '').strip(),
            "exit_code": completed.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "exit_code": 124}


def ok(proc: Dict[str, Any]) -> bool:
    """Check if command executed successfully"""
    return proc.get("exit_code", 1) == 0


def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }


def get_grafana_pod(namespace: str) -> Optional[str]:
    """Get Grafana pod name"""
    cmd = f"kubectl get pods -n {namespace} --field-selector=status.phase=Running -o name | grep grafana | head -1 | cut -d'/' -f2"
    result = run_command(cmd)
    return result['stdout'] if ok(result) and result['stdout'] else None


# ------------------------------------------------------------
# Test Functions
# ------------------------------------------------------------

def test_grafana_pod() -> List[Dict[str, Any]]:
    """Check Grafana pod status"""
    description = "Check Grafana pod health and readiness"
    tests = []
    
    cmd = f"kubectl get pods -n {NAMESPACE} -o json"
    result = run_command(cmd)
    
    if not ok(result):
        tests.append(create_test_result(
            "grafana_pod_health",
            description,
            False,
            f"Failed to get pods: {result['stderr']}",
            "CRITICAL"
        ))
        return tests
    
    try:
        data = json.loads(result['stdout'])
        grafana_pods = []
        unhealthy_pods = []
        
        for pod in data.get("items", []):
            if "grafana" in pod["metadata"]["name"].lower():
                name = pod["metadata"]["name"]
                status = pod["status"]["phase"]
                ready = all(c.get("ready", False) for c in pod["status"].get("containerStatuses", []))
                
                if status == "Running" and ready:
                    grafana_pods.append(name)
                else:
                    unhealthy_pods.append(f"{name}({status})")
        
        if grafana_pods:
            tests.append(create_test_result(
                "grafana_pod_health",
                description,
                True,
                f"Running pods: {', '.join(grafana_pods)}",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                "grafana_pod_health",
                description,
                False,
                f"No healthy Grafana pods. Found: {', '.join(unhealthy_pods) if unhealthy_pods else 'none'}",
                "CRITICAL"
            ))
            
    except Exception as e:
        tests.append(create_test_result(
            "grafana_pod_health",
            description,
            False,
            f"Failed to parse pod data: {str(e)}",
            "CRITICAL"
        ))
    
    return tests


def test_grafana_service() -> List[Dict[str, Any]]:
    """Check Grafana service and endpoints"""
    description = "Check Grafana service configuration and endpoints"
    tests = []
    
    cmd = f"kubectl get svc grafana -n {NAMESPACE} -o json"
    result = run_command(cmd)
    
    if not ok(result):
        tests.append(create_test_result(
            "grafana_service",
            description,
            False,
            f"Service not found: {result['stderr']}",
            "CRITICAL"
        ))
        return tests
    
    try:
        data = json.loads(result['stdout'])
        svc_type = data["spec"]["type"]
        ports = [f"{p['port']}/{p.get('targetPort', '?')}" for p in data["spec"]["ports"]]
        
        # Check endpoints
        ep_cmd = f"kubectl get endpoints grafana -n {NAMESPACE} -o json"
        ep_result = run_command(ep_cmd)
        ep_count = 0
        
        if ok(ep_result):
            ep_data = json.loads(ep_result['stdout'])
            for subset in ep_data.get("subsets", []):
                ep_count += len(subset.get("addresses", []))
        
        if ep_count > 0:
            tests.append(create_test_result(
                "grafana_service",
                description,
                True,
                f"Type: {svc_type}, Ports: {ports}, Active endpoints: {ep_count}",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                "grafana_service",
                description,
                False,
                f"Service exists but no active endpoints (Type: {svc_type}, Ports: {ports})",
                "CRITICAL"
            ))
            
    except Exception as e:
        tests.append(create_test_result(
            "grafana_service",
            description,
            False,
            f"Failed to check service: {str(e)}",
            "WARNING"
        ))
    
    return tests


def test_grafana_api() -> List[Dict[str, Any]]:
    """Test Grafana API health endpoint"""
    description = "Check Grafana API health status"
    tests = []
    
    pod = get_grafana_pod(NAMESPACE)
    
    if not pod:
        tests.append(create_test_result(
            "grafana_api_health",
            description,
            False,
            "No running Grafana pod found",
            "CRITICAL"
        ))
        return tests
    
    cmd = f"kubectl exec -n {NAMESPACE} {pod} -- wget -qO- --timeout=5 http://localhost:3000/api/health"
    result = run_command(cmd, timeout=15)
    
    if ok(result) and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            db_status = data.get('database', 'unknown')
            version = data.get('version', 'unknown')
            tests.append(create_test_result(
                "grafana_api_health",
                description,
                True,
                f"API healthy - Database: {db_status}, Version: {version}",
                "INFO"
            ))
        except Exception:
            tests.append(create_test_result(
                "grafana_api_health",
                description,
                True,
                "API responding (non-JSON response)",
                "INFO"
            ))
    else:
        tests.append(create_test_result(
            "grafana_api_health",
            description,
            False,
            f"API not responding: {result['stderr'] or 'No response'}",
            "CRITICAL"
        ))
    
    return tests


def test_datasources() -> List[Dict[str, Any]]:
    """Test configured datasources"""
    description = "Check configured datasources in Grafana"
    tests = []
    
    pod = get_grafana_pod(NAMESPACE)
    
    if not pod:
        tests.append(create_test_result(
            "grafana_datasources",
            description,
            False,
            "No pod available to check datasources",
            "WARNING"
        ))
        return tests
    
    datasources = []
    auth_worked = False
    
    for pwd in DEFAULT_PASSWORDS:
        cmd = f"kubectl exec -n {NAMESPACE} {pod} -- curl -s -u admin:{pwd} http://localhost:3000/api/datasources"
        result = run_command(cmd, timeout=15)
        
        if ok(result) and result['stdout'].startswith('['):
            try:
                ds_list = json.loads(result['stdout'])
                auth_worked = True
                for ds in ds_list:
                    datasources.append({
                        "name": ds["name"],
                        "type": ds["type"],
                        "default": ds.get("isDefault", False)
                    })
                break
            except Exception:
                pass
    
    if datasources:
        info = [f"{ds['name']}({ds['type']}{'*' if ds['default'] else ''})" for ds in datasources]
        tests.append(create_test_result(
            "grafana_datasources",
            description,
            True,
            f"Found {len(datasources)} datasource(s): {', '.join(info)}",
            "INFO"
        ))
    elif auth_worked:
        tests.append(create_test_result(
            "grafana_datasources",
            description,
            True,
            "No datasources configured",
            "WARNING"
        ))
    else:
        tests.append(create_test_result(
            "grafana_datasources",
            description,
            False,
            "Could not authenticate to check datasources",
            "WARNING"
        ))
    
    return tests


def test_datasource_health() -> List[Dict[str, Any]]:
    """Test datasource connectivity"""
    description = "Check datasource health and connectivity"
    tests = []
    
    pod = get_grafana_pod(NAMESPACE)
    
    if not pod:
        tests.append(create_test_result(
            "datasource_health",
            description,
            False,
            "No pod available to test datasources",
            "WARNING"
        ))
        return tests
    
    health_status = []
    datasource_types = ["prometheus", "loki", "tempo", "elasticsearch"]
    
    for pwd in DEFAULT_PASSWORDS:
        auth_worked = False
        
        for ds_type in datasource_types:
            cmd = f"kubectl exec -n {NAMESPACE} {pod} -- curl -s -u admin:{pwd} http://localhost:3000/api/datasources/uid/{ds_type}/health"
            result = run_command(cmd, timeout=10)
            
            if ok(result) and result['stdout']:
                auth_worked = True
                if '"status":"OK"' in result['stdout']:
                    health_status.append(f"{ds_type.capitalize()}: OK")
                elif '"status"' in result['stdout']:
                    health_status.append(f"{ds_type.capitalize()}: Failed")
        
        if auth_worked:
            break
    
    if health_status:
        tests.append(create_test_result(
            "datasource_health",
            description,
            True,
            ", ".join(health_status),
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "datasource_health",
            description,
            False,
            "Could not verify datasource health (auth failed or no datasources)",
            "WARNING"
        ))
    
    return tests


def discover_services() -> Dict[str, Dict[str, Any]]:
    """Discover potential datasource services in cluster"""
    services = {}
    
    namespaces = ["prometheus", "loki", "tempo", "monitoring", "elastic", "grafana", "observability"]
    
    for ns in namespaces:
        cmd = f"kubectl get svc -n {ns} -o json 2>/dev/null"
        result = run_command(cmd, timeout=10)
        
        if ok(result):
            try:
                data = json.loads(result['stdout'])
                for svc in data.get("items", []):
                    name = svc["metadata"]["name"]
                    namespace = svc["metadata"]["namespace"]
                    ports = [p["port"] for p in svc["spec"].get("ports", [])]
                    
                    # Identify service type
                    svc_type = "unknown"
                    if "prometheus" in name.lower():
                        svc_type = "prometheus"
                    elif "loki" in name.lower():
                        svc_type = "loki"
                    elif "tempo" in name.lower():
                        svc_type = "tempo"
                    elif "elastic" in name.lower() or "opensearch" in name.lower():
                        svc_type = "elasticsearch"
                    elif "influx" in name.lower():
                        svc_type = "influxdb"
                    
                    if svc_type != "unknown":
                        key = f"{name}.{namespace}"
                        services[key] = {
                            "type": svc_type,
                            "ports": ports,
                            "namespace": namespace,
                            "name": name
                        }
            except Exception:
                pass
    
    return services


def test_connectivity() -> List[Dict[str, Any]]:
    """Test connectivity to discovered datasource services"""
    description = "Check network connectivity to potential datasources"
    tests = []
    
    pod = get_grafana_pod(NAMESPACE)
    
    if not pod:
        tests.append(create_test_result(
            "datasource_connectivity",
            description,
            False,
            "No Grafana pod available for connectivity test",
            "WARNING"
        ))
        return tests
    
    services = discover_services()
    
    if not services:
        tests.append(create_test_result(
            "datasource_connectivity",
            description,
            True,
            "No datasource services discovered in cluster",
            "INFO"
        ))
        return tests
    
    reachable = []
    unreachable = []
    
    for svc_name, svc_info in services.items():
        if svc_info["ports"]:
            port = svc_info["ports"][0]
            cmd = f"kubectl exec -n {NAMESPACE} {pod} -- nc -zv -w2 {svc_name} {port} 2>&1"
            result = run_command(cmd, timeout=5)
            
            if ok(result) or "succeeded" in result['stdout'].lower():
                reachable.append(f"{svc_info['type']}:{svc_info['name']}:{port}")
            else:
                unreachable.append(f"{svc_info['type']}:{svc_info['name']}")
    
    if reachable:
        # Limit output to first 5 for readability
        output = f"Reachable: {', '.join(reachable[:5])}"
        if len(reachable) > 5:
            output += f" (+{len(reachable)-5} more)"
        tests.append(create_test_result(
            "datasource_connectivity",
            description,
            True,
            output,
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "datasource_connectivity",
            description,
            False,
            f"Found {len(services)} service(s), none reachable",
            "WARNING"
        ))
    
    return tests


def test_dashboards() -> List[Dict[str, Any]]:
    """Test dashboard availability"""
    description = "Check configured dashboards"
    tests = []
    
    pod = get_grafana_pod(NAMESPACE)
    dashboard_count = 0
    dashboard_names = []
    
    if pod:
        # Try API first
        for pwd in DEFAULT_PASSWORDS:
            cmd = f"kubectl exec -n {NAMESPACE} {pod} -- curl -s -u admin:{pwd} 'http://localhost:3000/api/search?type=dash-db'"
            result = run_command(cmd, timeout=15)
            
            if ok(result) and result['stdout'].startswith('['):
                try:
                    dashboards = json.loads(result['stdout'])
                    dashboard_count = len(dashboards)
                    dashboard_names = [d["title"] for d in dashboards[:5]]
                    break
                except Exception:
                    pass
        
        # Fallback to filesystem check
        if dashboard_count == 0:
            cmd = f"kubectl exec -n {NAMESPACE} {pod} -- find /var/lib/grafana/dashboards -name '*.json' -type f 2>/dev/null | wc -l"
            result = run_command(cmd, timeout=10)
            
            if ok(result) and result['stdout'].isdigit():
                dashboard_count = int(result['stdout'])
    
    if dashboard_count > 0:
        output = f"Found {dashboard_count} dashboard(s)"
        if dashboard_names:
            output += f": {', '.join(dashboard_names)}"
            if dashboard_count > 5:
                output += "..."
        tests.append(create_test_result(
            "grafana_dashboards",
            description,
            True,
            output,
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "grafana_dashboards",
            description,
            True,
            "No dashboards configured",
            "WARNING"
        ))
    
    return tests


def test_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Check Grafana logs for errors"""
    description = f"Check Grafana logs for errors (last {time_window_minutes}m)"
    tests = []
    
    pod = get_grafana_pod(NAMESPACE)
    
    if not pod:
        tests.append(create_test_result(
            "grafana_logs",
            description,
            False,
            "No pod available to check logs",
            "WARNING"
        ))
        return tests
    
    cmd = f"kubectl logs -n {NAMESPACE} {pod} --tail=500"
    result = run_command(cmd, timeout=15)
    
    if not ok(result):
        tests.append(create_test_result(
            "grafana_logs",
            description,
            False,
            f"Cannot read logs: {result['stderr']}",
            "WARNING"
        ))
        return tests
    
    errors = 0
    critical_errors = 0
    error_samples = []
    
    for line in result['stdout'].split('\n'):
        if '"level":"error"' in line or 'level=error' in line.lower():
            # Filter out non-errors
            if not any(x in line.lower() for x in ['error=<nil>', 'error=null', 'errors=0']):
                errors += 1
                if errors <= 3:  # Keep first 3 error samples
                    error_samples.append(line[:100])
                
                # Check for critical errors
                if any(x in line.lower() for x in ['panic', 'fatal', 'critical']):
                    critical_errors += 1
    
    if critical_errors > 0:
        tests.append(create_test_result(
            "grafana_logs",
            description,
            False,
            f"Found {errors} error(s) including {critical_errors} critical",
            "CRITICAL"
        ))
    elif errors > 50:
        tests.append(create_test_result(
            "grafana_logs",
            description,
            False,
            f"Found {errors} error(s) in logs",
            "WARNING"
        ))
    elif errors > 10:
        tests.append(create_test_result(
            "grafana_logs",
            description,
            True,
            f"Found {errors} error(s) in logs (within threshold)",
            "WARNING"
        ))
    else:
        tests.append(create_test_result(
            "grafana_logs",
            description,
            True,
            f"Found {errors} error(s) in logs",
            "INFO"
        ))
    
    return tests


# ------------------------------------------------------------
# Main test runner
# ------------------------------------------------------------

def test_grafana() -> List[Dict[str, Any]]:
    """Run all Grafana health checks"""
    start_time = time.time()
    results = []
    
    # 1) Pod health - gateway test
    pod_tests = test_grafana_pod()
    results.extend(pod_tests)
    
    # Continue even if pods are unhealthy to gather more info
    
    # 2) Service configuration
    results.extend(test_grafana_service())
    
    # 3) API health
    api_tests = test_grafana_api()
    results.extend(api_tests)
    
    # Only continue with detailed tests if API is responding
    if any(t['status'] for t in api_tests):
        # 4) Datasources
        results.extend(test_datasources())
        
        # 5) Datasource health
        results.extend(test_datasource_health())
        
        # 6) Network connectivity
        results.extend(test_connectivity())
        
        # 7) Dashboards
        results.extend(test_dashboards())
    
    # 8) Logs (always check)
    results.extend(test_logs())
    
    # Add execution time
    execution_time = time.time() - start_time
    results.append(create_test_result(
        "execution_time",
        "Total execution time",
        True,
        f"{execution_time:.2f} seconds",
        "INFO"
    ))
    
    return results


def main():
    """Main entry point with JSON output"""
    try:
        results = test_grafana()
        
        # Output as JSON
        print(json.dumps(results, indent=2))
        
        # Determine exit code based on severity
        critical_count = sum(1 for r in results if not r['status'] and r['severity'] == 'critical')
        warning_count = sum(1 for r in results if r['severity'] == 'warning')
        
        if critical_count > 0:
            sys.exit(1)
        elif warning_count > 0:
            sys.exit(0)
        else:
            sys.exit(0)
            
    except Exception as e:
        # Emergency fallback
        error_result = [{
            "name": "script_error",
            "description": "Script execution error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
