#!/usr/bin/env python3
"""
Grafana Health Check Script - Generic version
Discovers and tests Grafana configuration dynamically
"""

import os
import json
import subprocess
from typing import Dict, List, Optional

def run_command(command: str, timeout: int = 10) -> Dict:
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


def get_grafana_pod(namespace: str) -> Optional[str]:
    """Get Grafana pod name"""
    cmd = f"kubectl get pods -n {namespace} --field-selector=status.phase=Running -o name | grep grafana | head -1 | cut -d'/' -f2"
    result = run_command(cmd)
    return result['stdout'] if result['exit_code'] == 0 and result['stdout'] else None


def test_grafana_pod() -> List[Dict]:
    """Check Grafana pod status"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    cmd = f"kubectl get pods -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "grafana_pod_health",
            "passed": False,
            "output": "Failed to get pods",
            "severity": "CRITICAL"
        }]
    
    try:
        data = json.loads(result['stdout'])
        grafana_pods = []
        
        for pod in data.get("items", []):
            if "grafana" in pod["metadata"]["name"].lower():
                name = pod["metadata"]["name"]
                status = pod["status"]["phase"]
                ready = all(c.get("ready", False) for c in pod["status"].get("containerStatuses", []))
                
                if status == "Running" and ready:
                    grafana_pods.append(name)
        
        if grafana_pods:
            return [{
                "name": "grafana_pod_health",
                "passed": True,
                "output": f"Running: {', '.join(grafana_pods)}",
                "severity": "LOW"
            }]
        else:
            return [{
                "name": "grafana_pod_health",
                "passed": False,
                "output": "No healthy Grafana pods",
                "severity": "CRITICAL"
            }]
    except:
        return [{
            "name": "grafana_pod_health",
            "passed": False,
            "output": "Failed to parse pod data",
            "severity": "CRITICAL"
        }]


def test_grafana_service() -> List[Dict]:
    """Check Grafana service"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    cmd = f"kubectl get svc grafana -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "grafana_service",
            "passed": False,
            "output": "Service not found",
            "severity": "CRITICAL"
        }]
    
    try:
        data = json.loads(result['stdout'])
        svc_type = data["spec"]["type"]
        ports = [f"{p['port']}/{p.get('targetPort', '?')}" for p in data["spec"]["ports"]]
        
        # Check endpoints
        ep_cmd = f"kubectl get endpoints grafana -n {namespace} -o json"
        ep_result = run_command(ep_cmd)
        ep_count = 0
        
        if ep_result['exit_code'] == 0:
            ep_data = json.loads(ep_result['stdout'])
            for subset in ep_data.get("subsets", []):
                ep_count += len(subset.get("addresses", []))
        
        return [{
            "name": "grafana_service",
            "passed": ep_count > 0,
            "output": f"Type: {svc_type}, Ports: {ports}, Endpoints: {ep_count}",
            "severity": "CRITICAL" if ep_count == 0 else "LOW"
        }]
    except:
        return [{
            "name": "grafana_service",
            "passed": False,
            "output": "Failed to check service",
            "severity": "WARNING"
        }]


def test_grafana_api() -> List[Dict]:
    """Test Grafana API"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    pod = get_grafana_pod(namespace)
    
    if not pod:
        return [{
            "name": "grafana_api",
            "passed": False,
            "output": "No running pod",
            "severity": "CRITICAL"
        }]
    
    cmd = f"kubectl exec -n {namespace} {pod} -- wget -qO- --timeout=5 http://localhost:3000/api/health"
    result = run_command(cmd)
    
    if result['exit_code'] == 0 and result['stdout']:
        try:
            data = json.loads(result['stdout'])
            return [{
                "name": "grafana_api",
                "passed": True,
                "output": f"Database: {data.get('database', '?')}, Version: {data.get('version', '?')}",
                "severity": "LOW"
            }]
        except:
            pass
    
    return [{
        "name": "grafana_api",
        "passed": False,
        "output": "API not responding",
        "severity": "CRITICAL"
    }]


def test_datasources() -> List[Dict]:
    """Test datasources"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    pod = get_grafana_pod(namespace)
    
    if not pod:
        return [{
            "name": "grafana_datasources",
            "passed": False,
            "output": "No pod to check",
            "severity": "WARNING"
        }]
    
    # Try API with correct password
    passwords = ["default_password", "admin", "prom-operator"]
    datasources = []
    
    for pwd in passwords:
        cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -u admin:{pwd} http://localhost:3000/api/datasources"
        result = run_command(cmd)
        
        if result['exit_code'] == 0 and result['stdout'].startswith('['):
            try:
                ds_list = json.loads(result['stdout'])
                for ds in ds_list:
                    datasources.append({
                        "name": ds["name"],
                        "type": ds["type"],
                        "default": ds.get("isDefault", False)
                    })
                break
            except:
                pass
    
    if datasources:
        info = [f"{ds['name']}({ds['type']}{'*' if ds['default'] else ''})" for ds in datasources]
        return [{
            "name": "grafana_datasources",
            "passed": True,
            "output": f"Found {len(datasources)}: {', '.join(info)}",
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_datasources",
            "passed": False,
            "output": "No datasources found or auth failed",
            "severity": "WARNING"
        }]


def test_datasource_health() -> List[Dict]:
    """Test datasource health"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    pod = get_grafana_pod(namespace)
    
    if not pod:
        return [{
            "name": "datasource_health",
            "passed": False,
            "output": "No pod to test",
            "severity": "WARNING"
        }]
    
    health_status = []
    passwords = ["default_password", "admin", "prom-operator"]
    
    for pwd in passwords:
        # Test Prometheus health
        cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -u admin:{pwd} http://localhost:3000/api/datasources/uid/prometheus/health"
        result = run_command(cmd)
        
        if result['exit_code'] == 0 and '"status":"OK"' in result['stdout']:
            health_status.append("Prometheus: OK")
            
            # Test Loki
            cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -u admin:{pwd} http://localhost:3000/api/datasources/uid/loki/health"
            result = run_command(cmd)
            
            if '"status":"OK"' in result['stdout']:
                health_status.append("Loki: OK")
            else:
                health_status.append("Loki: Failed")
            break
    
    if health_status:
        return [{
            "name": "datasource_health",
            "passed": True,
            "output": ", ".join(health_status),
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "datasource_health",
            "passed": False,
            "output": "Could not verify datasource health",
            "severity": "WARNING"
        }]


def discover_services() -> Dict:
    """Discover actual services in cluster"""
    services = {}
    
    # Get all services that might be datasources
    namespaces = ["prometheus", "loki", "tempo", "monitoring", "elastic", "grafana"]
    
    for ns in namespaces:
        cmd = f"kubectl get svc -n {ns} -o json 2>/dev/null"
        result = run_command(cmd)
        
        if result['exit_code'] == 0:
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
                    
                    if svc_type != "unknown":
                        key = f"{name}.{namespace}"
                        services[key] = {
                            "type": svc_type,
                            "ports": ports,
                            "namespace": namespace
                        }
            except:
                pass
    
    return services


def test_connectivity() -> List[Dict]:
    """Test connectivity to discovered services"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    pod = get_grafana_pod(namespace)
    
    if not pod:
        return [{
            "name": "connectivity",
            "passed": False,
            "output": "No Grafana pod to test from",
            "severity": "WARNING"
        }]
    
    services = discover_services()
    reachable = []
    
    for svc_name, svc_info in services.items():
        if svc_info["ports"]:
            port = svc_info["ports"][0]
            cmd = f"kubectl exec -n {namespace} {pod} -- nc -zv -w2 {svc_name} {port} 2>&1"
            result = run_command(cmd, timeout=3)
            
            if result['exit_code'] == 0 or "succeeded" in result['stdout'].lower():
                reachable.append(f"{svc_info['type']}:{svc_name}:{port}")
    
    if reachable:
        return [{
            "name": "connectivity",
            "passed": True,
            "output": f"Reachable: {', '.join(reachable[:5])}",
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "connectivity",
            "passed": True,
            "output": f"Found {len(services)} services, none reachable",
            "severity": "WARNING"
        }]


def test_dashboards() -> List[Dict]:
    """Test dashboards"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    pod = get_grafana_pod(namespace)
    
    dashboard_count = 0
    dashboard_names = []
    
    # Try API with correct password
    if pod:
        passwords = ["default_password", "admin", "prom-operator"]
        
        for pwd in passwords:
            cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -u admin:{pwd} 'http://localhost:3000/api/search?type=dash-db'"
            result = run_command(cmd)
            
            if result['exit_code'] == 0 and result['stdout'].startswith('['):
                try:
                    dashboards = json.loads(result['stdout'])
                    dashboard_count = len(dashboards)
                    dashboard_names = [d["title"] for d in dashboards[:5]]
                    break
                except:
                    pass
    
    # Also check filesystem
    if pod and dashboard_count == 0:
        cmd = f"kubectl exec -n {namespace} {pod} -- find /var/lib/grafana/dashboards -name '*.json' -type f 2>/dev/null | wc -l"
        result = run_command(cmd)
        
        if result['exit_code'] == 0 and result['stdout'].isdigit():
            dashboard_count = int(result['stdout'])
    
    if dashboard_count > 0:
        output = f"{dashboard_count} dashboards"
        if dashboard_names:
            output += f": {', '.join(dashboard_names)}"
            if dashboard_count > 5:
                output += "..."
        return [{
            "name": "dashboards",
            "passed": True,
            "output": output,
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "dashboards",
            "passed": True,
            "output": "No dashboards",
            "severity": "WARNING"
        }]


def test_logs() -> List[Dict]:
    """Check logs for errors"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    pod = get_grafana_pod(namespace)
    
    if not pod:
        return [{
            "name": "logs",
            "passed": False,
            "output": "No pod",
            "severity": "WARNING"
        }]
    
    cmd = f"kubectl logs -n {namespace} {pod} --tail=500"
    result = run_command(cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "logs",
            "passed": False,
            "output": "Cannot read logs",
            "severity": "WARNING"
        }]
    
    errors = 0
    for line in result['stdout'].split('\n'):
        if '"level":"error"' in line or 'level=error' in line.lower():
            if not any(x in line.lower() for x in ['error=<nil>', 'error=null', 'errors=0']):
                errors += 1
    
    if errors > 50:
        return [{
            "name": "logs",
            "passed": False,
            "output": f"{errors} errors",
            "severity": "CRITICAL"
        }]
    elif errors > 10:
        return [{
            "name": "logs",
            "passed": True,
            "output": f"{errors} errors",
            "severity": "WARNING"
        }]
    else:
        return [{
            "name": "logs",
            "passed": True,
            "output": f"{errors} errors",
            "severity": "LOW"
        }]


def main():
    print("=" * 60)
    print("GRAFANA HEALTH CHECK")
    print("=" * 60)
    
    tests = [
        test_grafana_pod,
        test_grafana_service,
        test_grafana_api,
        test_datasources,
        test_datasource_health,
        test_connectivity,
        test_dashboards,
        test_logs
    ]
    
    critical = 0
    warning = 0
    passed = 0
    
    for test in tests:
        try:
            results = test()
            for r in results:
                status = "✓" if r["passed"] else "✗"
                print(f"\n{status} {r['name']}")
                print(f"  {r['output']}")
                
                if not r["passed"] and r["severity"] == "CRITICAL":
                    critical += 1
                elif r["severity"] == "WARNING":
                    warning += 1
                else:
                    passed += 1
        except Exception as e:
            print(f"\nError in {test.__name__}: {e}")
    
    print("\n" + "=" * 60)
    print(f"Passed: {passed}, Warnings: {warning}, Critical: {critical}")
    
    if critical > 0:
        print("Status: CRITICAL")
        exit(1)
    elif warning > 0:
        print("Status: WARNING")
        exit(0)
    else:
        print("Status: HEALTHY")
        exit(0)


if __name__ == "__main__":
    main()
