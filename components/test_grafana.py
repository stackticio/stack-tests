#!/usr/bin/env python3
"""
Enhanced Grafana Health Check Script
Tests various aspects of Grafana deployment including dashboards, datasources, and integrations
"""

import os
import json
import subprocess
import re
import time
from typing import Dict, List, Any, Optional, Tuple

def run_command(command: str, env: Dict = None, timeout: int = 10) -> Dict:
    """Helper to run a shell command and capture stdout/stderr/exit code"""
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
            "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "Timeout"}


def get_grafana_credentials(namespace: str) -> Tuple[str, str]:
    """Get Grafana admin credentials from secret"""
    admin_user = "admin"
    admin_pass = "admin"  # default
    
    # Try to get from secret
    secret_cmd = f"kubectl get secret -n {namespace} grafana -o json 2>/dev/null"
    result = run_command(secret_cmd)
    
    if result['exit_code'] == 0 and result['stdout']:
        try:
            secret_data = json.loads(result['stdout'])
            data = secret_data.get("data", {})
            
            # Decode admin-user if exists
            if "admin-user" in data:
                import base64
                admin_user = base64.b64decode(data["admin-user"]).decode('utf-8')
            
            # Decode admin-password if exists
            if "admin-password" in data:
                import base64
                admin_pass = base64.b64decode(data["admin-password"]).decode('utf-8')
        except:
            pass
    
    # Alternative: try prom-operator default
    if admin_pass == "admin":
        admin_pass = "prom-operator"
    
    return admin_user, admin_pass


def get_grafana_pod(namespace: str) -> Optional[str]:
    """Get the first running Grafana pod"""
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=grafana -o jsonpath='{{.items[0].metadata.name}}' 2>/dev/null"
    result = run_command(cmd)
    
    if result['exit_code'] == 0 and result['stdout'].strip():
        return result['stdout'].strip()
    
    # Fallback: grep for grafana pod
    cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | grep Running | head -1 | awk '{{print $1}}'"
    result = run_command(cmd)
    
    if result['stdout'].strip():
        return result['stdout'].strip()
    
    return None


def test_grafana_pod() -> List[Dict]:
    """Check if Grafana pod is running and healthy"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    cmd = f"kubectl get pods -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "grafana_pod_health",
            "description": "Check if Grafana pod is running and healthy",
            "passed": False,
            "output": f"Failed to get pods: {result['stderr']}",
            "severity": "CRITICAL"
        }]
    
    try:
        pods_data = json.loads(result['stdout'])
        grafana_pods = []
        failed_pods = []
        
        for pod in pods_data.get("items", []):
            pod_name = pod["metadata"]["name"]
            pod_status = pod["status"]["phase"]
            
            # Skip test pods
            if "test" in pod_name.lower():
                continue
            
            # Check Grafana pods
            if "grafana" in pod_name.lower():
                ready = all(
                    container.get("ready", False) 
                    for container in pod["status"].get("containerStatuses", [])
                )
                
                restart_count = sum(
                    container.get("restartCount", 0)
                    for container in pod["status"].get("containerStatuses", [])
                )
                
                if pod_status == "Running" and ready:
                    pod_info = pod_name
                    if restart_count > 0:
                        pod_info += f" (restarts: {restart_count})"
                    grafana_pods.append(pod_info)
                else:
                    failed_pods.append(f"{pod_name} (Status: {pod_status}, Ready: {ready}, Restarts: {restart_count})")
        
        if not grafana_pods and not failed_pods:
            return [{
                "name": "grafana_pod_health",
                "description": "Check if Grafana pod is running and healthy",
                "passed": False,
                "output": "No Grafana pods found in namespace",
                "severity": "CRITICAL"
            }]
        
        if failed_pods:
            return [{
                "name": "grafana_pod_health",
                "description": "Check if Grafana pod is running and healthy",
                "passed": False,
                "output": f"Unhealthy Grafana pods: {', '.join(failed_pods)}",
                "severity": "CRITICAL"
            }]
        
        return [{
            "name": "grafana_pod_health",
            "description": "Check if Grafana pod is running and healthy",
            "passed": True,
            "output": f"Healthy pods: {', '.join(grafana_pods)}",
            "severity": "LOW"
        }]
        
    except json.JSONDecodeError as e:
        return [{
            "name": "grafana_pod_health",
            "description": "Check if Grafana pod is running and healthy",
            "passed": False,
            "output": f"Failed to parse pod data: {str(e)}",
            "severity": "CRITICAL"
        }]


def test_grafana_service() -> List[Dict]:
    """Check if Grafana service is configured and has endpoints"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    cmd = f"kubectl get service grafana -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "grafana_service_health",
            "description": "Check if Grafana service is configured and has endpoints",
            "passed": False,
            "output": f"Grafana service not found: {result['stderr']}",
            "severity": "CRITICAL"
        }]
    
    try:
        service_data = json.loads(result['stdout'])
        cluster_ip = service_data["spec"].get("clusterIP", "None")
        service_type = service_data["spec"].get("type", "Unknown")
        ports = service_data["spec"].get("ports", [])
        
        # Check endpoints
        endpoints_cmd = f"kubectl get endpoints grafana -n {namespace} -o json"
        ep_result = run_command(endpoints_cmd)
        
        has_endpoints = False
        endpoint_count = 0
        
        if ep_result['exit_code'] == 0:
            ep_data = json.loads(ep_result['stdout'])
            subsets = ep_data.get("subsets", [])
            if subsets:
                for subset in subsets:
                    addresses = subset.get("addresses", [])
                    endpoint_count += len(addresses)
                has_endpoints = endpoint_count > 0
        
        if not has_endpoints:
            return [{
                "name": "grafana_service_health",
                "description": "Check if Grafana service is configured and has endpoints",
                "passed": False,
                "output": "Grafana service has no endpoints - no pods are serving traffic",
                "severity": "CRITICAL"
            }]
        
        port_info = ", ".join([f"{p.get('port')}→{p.get('targetPort')}" for p in ports])
        output = f"Service Type: {service_type}, ClusterIP: {cluster_ip}, Ports: [{port_info}], Endpoints: {endpoint_count}"
        
        return [{
            "name": "grafana_service_health",
            "description": "Check if Grafana service is configured and has endpoints",
            "passed": True,
            "output": output,
            "severity": "LOW"
        }]
        
    except Exception as e:
        return [{
            "name": "grafana_service_health",
            "description": "Check if Grafana service is configured and has endpoints",
            "passed": False,
            "output": f"Failed to check service: {str(e)}",
            "severity": "WARNING"
        }]


def test_grafana_api() -> List[Dict]:
    """Check if Grafana API is accessible and responding"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    pod_name = get_grafana_pod(namespace)
    if not pod_name:
        return [{
            "name": "grafana_api_health",
            "description": "Check if Grafana API is accessible and responding",
            "passed": False,
            "output": "Could not find Grafana pod to test API",
            "severity": "CRITICAL"
        }]
    
    # Check health endpoint
    health_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -m 5 http://localhost:3000/api/health"
    health_result = run_command(health_cmd, timeout=10)
    
    if health_result['exit_code'] == 0 and health_result['stdout']:
        try:
            health_data = json.loads(health_result['stdout'])
            db_status = health_data.get("database", "unknown")
            version = health_data.get("version", "unknown")
            commit = health_data.get("commit", "")
            
            output = f"API healthy, Database: {db_status}, Version: {version}"
            
            if "ok" in str(db_status).lower():
                return [{
                    "name": "grafana_api_health",
                    "description": "Check if Grafana API is accessible and responding",
                    "passed": True,
                    "output": output,
                    "severity": "LOW"
                }]
            else:
                return [{
                    "name": "grafana_api_health",
                    "description": "Check if Grafana API is accessible and responding",
                    "passed": False,
                    "output": f"API responded but database status is unhealthy: {db_status}",
                    "severity": "WARNING"
                }]
        except:
            pass
    
    # Fallback: check if port is listening
    port_check_cmd = f"kubectl exec -n {namespace} {pod_name} -- timeout 2 nc -zv localhost 3000 2>&1"
    port_result = run_command(port_check_cmd, timeout=5)
    
    if port_result['exit_code'] == 0 or "succeeded" in port_result['stdout'].lower() or "connected" in port_result['stdout'].lower():
        return [{
            "name": "grafana_api_health",
            "description": "Check if Grafana API is accessible and responding",
            "passed": True,
            "output": "Grafana is listening on port 3000",
            "severity": "LOW"
        }]
    
    return [{
        "name": "grafana_api_health",
        "description": "Check if Grafana API is accessible and responding",
        "passed": False,
        "output": "Grafana API is not responding on port 3000",
        "severity": "CRITICAL"
    }]


def test_grafana_datasources() -> List[Dict]:
    """Check and identify all configured datasources in Grafana"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    pod_name = get_grafana_pod(namespace)
    if not pod_name:
        return [{
            "name": "grafana_datasources",
            "description": "Check and identify all configured datasources in Grafana",
            "passed": False,
            "output": "Could not find Grafana pod to check datasources",
            "severity": "CRITICAL"
        }]
    
    admin_user, admin_pass = get_grafana_credentials(namespace)
    datasources_found = {}
    
    # Try multiple authentication combinations
    auth_combinations = [
        (admin_user, admin_pass),
        ("admin", "admin"),
        ("admin", "prom-operator"),
    ]
    
    for user, passwd in auth_combinations:
        # Query datasources via API
        ds_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -m 5 -u {user}:{passwd} http://localhost:3000/api/datasources"
        ds_result = run_command(ds_cmd, timeout=10)
        
        if ds_result['exit_code'] == 0 and ds_result['stdout']:
            try:
                response = ds_result['stdout']
                # Check if we got an auth error
                if "Unauthorized" in response or "invalid username or password" in response.lower():
                    continue
                
                if response.startswith('['):
                    datasources = json.loads(response)
                    for ds in datasources:
                        ds_name = ds.get("name", "unknown")
                        ds_type = ds.get("type", "unknown")
                        ds_url = ds.get("url", "")
                        ds_default = ds.get("isDefault", False)
                        ds_uid = ds.get("uid", "")
                        
                        datasources_found[ds_name] = {
                            "type": ds_type,
                            "url": ds_url,
                            "default": ds_default,
                            "uid": ds_uid
                        }
                    
                    # If we found datasources, break the loop
                    if datasources_found:
                        break
            except:
                pass
    
    # Also check ConfigMaps for datasource provisioning
    cm_cmd = f"kubectl get configmap -n {namespace} -o json"
    cm_result = run_command(cm_cmd)
    
    provisioned_datasources = []
    if cm_result['exit_code'] == 0:
        try:
            cm_data = json.loads(cm_result['stdout'])
            for cm in cm_data.get("items", []):
                cm_name = cm["metadata"]["name"]
                
                # Check for datasource provisioning ConfigMaps
                if "datasource" in cm_name.lower():
                    for key, value in cm.get("data", {}).items():
                        if "datasources:" in value or "apiVersion:" in value:
                            # Parse YAML content
                            if "prometheus" in value.lower():
                                provisioned_datasources.append("Prometheus")
                            if "loki" in value.lower():
                                provisioned_datasources.append("Loki")
                            if "tempo" in value.lower():
                                provisioned_datasources.append("Tempo")
                            if "elasticsearch" in value.lower():
                                provisioned_datasources.append("Elasticsearch")
        except:
            pass
    
    # Combine results
    if datasources_found:
        output_parts = [f"Active datasources: {len(datasources_found)}"]
        
        # Group by type
        by_type = {}
        for name, info in datasources_found.items():
            ds_type = info["type"]
            if ds_type not in by_type:
                by_type[ds_type] = []
            by_type[ds_type].append(name)
        
        for ds_type, names in sorted(by_type.items()):
            output_parts.append(f"{ds_type}: {', '.join(names[:2])}{'...' if len(names) > 2 else ''}")
        
        # Find default datasource
        default_ds = [name for name, info in datasources_found.items() if info.get("default")]
        if default_ds:
            output_parts.append(f"Default: {default_ds[0]}")
        
        return [{
            "name": "grafana_datasources",
            "description": "Check and identify all configured datasources in Grafana",
            "passed": True,
            "output": " | ".join(output_parts),
            "severity": "LOW"
        }]
    elif provisioned_datasources:
        return [{
            "name": "grafana_datasources",
            "description": "Check and identify all configured datasources in Grafana",
            "passed": True,
            "output": f"Datasources provisioned via ConfigMap: {', '.join(set(provisioned_datasources))} (API access requires authentication)",
            "severity": "WARNING"
        }]
    else:
        return [{
            "name": "grafana_datasources",
            "description": "Check and identify all configured datasources in Grafana",
            "passed": False,
            "output": "No datasources found - check authentication or datasource provisioning",
            "severity": "CRITICAL"
        }]


def test_grafana_datasource_connectivity() -> List[Dict]:
    """Verify that Grafana can connect to its configured datasources"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    pod_name = get_grafana_pod(namespace)
    if not pod_name:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": False,
            "output": "Could not find Grafana pod to test connectivity",
            "severity": "WARNING"
        }]
    
    admin_user, admin_pass = get_grafana_credentials(namespace)
    connectivity_results = []
    failed_datasources = []
    
    # Try to test datasource health via API
    for user, passwd in [(admin_user, admin_pass), ("admin", "admin"), ("admin", "prom-operator")]:
        ds_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -m 5 -u {user}:{passwd} http://localhost:3000/api/datasources"
        ds_result = run_command(ds_cmd, timeout=10)
        
        if ds_result['exit_code'] == 0 and ds_result['stdout'] and ds_result['stdout'].startswith('['):
            try:
                datasources = json.loads(ds_result['stdout'])
                
                for ds in datasources:
                    ds_id = ds.get("id")
                    ds_name = ds.get("name", "unknown")
                    ds_type = ds.get("type", "unknown")
                    
                    # Test datasource health
                    health_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -m 5 -u {user}:{passwd} -X GET 'http://localhost:3000/api/datasources/{ds_id}/health'"
                    health_result = run_command(health_cmd, timeout=10)
                    
                    if health_result['exit_code'] == 0 and health_result['stdout']:
                        try:
                            health_data = json.loads(health_result['stdout'])
                            status = health_data.get("status", "")
                            message = health_data.get("message", "")
                            
                            if status == "OK" or "success" in status.lower():
                                connectivity_results.append(f"{ds_name}({ds_type}): ✓ Connected")
                            else:
                                failed_datasources.append(f"{ds_name}({ds_type}): {message or status}")
                        except:
                            connectivity_results.append(f"{ds_name}({ds_type}): Configured")
                
                if connectivity_results or failed_datasources:
                    break
            except:
                pass
    
    # Test common endpoints directly from pod
    common_endpoints = [
        ("prometheus-kube-prometheus-prometheus", "9090", "Prometheus"),
        ("prometheus", "9090", "Prometheus"),
        ("loki", "3100", "Loki"),
        ("tempo", "3100", "Tempo"),
    ]
    
    for host, port, name in common_endpoints:
        for ns in ["prometheus", "loki", "tempo", "monitoring", namespace]:
            test_cmd = f"kubectl exec -n {namespace} {pod_name} -- timeout 2 nc -zv {host}.{ns} {port} 2>&1"
            test_result = run_command(test_cmd, timeout=5)
            
            if test_result['exit_code'] == 0 or "succeeded" in test_result['stdout'].lower() or "connected" in test_result['stdout'].lower():
                connectivity_results.append(f"{name} endpoint reachable at {host}.{ns}:{port}")
                break
    
    if failed_datasources:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": False,
            "output": f"Failed: {', '.join(failed_datasources[:3])} | Working: {', '.join(connectivity_results[:2])}",
            "severity": "WARNING"
        }]
    elif connectivity_results:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": True,
            "output": f"Connected: {', '.join(connectivity_results[:5])}{'...' if len(connectivity_results) > 5 else ''}",
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": True,
            "output": "Datasource connectivity check requires authentication",
            "severity": "WARNING"
        }]


def test_grafana_dashboards() -> List[Dict]:
    """Check if dashboards are provisioned in Grafana"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    dashboard_count = 0
    dashboard_names = []
    
    # Check for dashboard ConfigMaps
    cm_cmd = f"kubectl get configmap -n {namespace} -o json"
    cm_result = run_command(cm_cmd)
    
    if cm_result['exit_code'] == 0:
        try:
            cm_data = json.loads(cm_result['stdout'])
            
            for cm in cm_data.get("items", []):
                cm_name = cm["metadata"]["name"]
                
                # Look for dashboard ConfigMaps
                if "dashboard" in cm_name.lower():
                    for key, value in cm.get("data", {}).items():
                        if ".json" in key.lower() or '"dashboard"' in str(value)[:1000]:
                            dashboard_count += 1
                            dashboard_names.append(key.replace('.json', ''))
        except:
            pass
    
    # Try to get dashboards via API
    pod_name = get_grafana_pod(namespace)
    if pod_name:
        admin_user, admin_pass = get_grafana_credentials(namespace)
        
        for user, passwd in [(admin_user, admin_pass), ("admin", "admin"), ("admin", "prom-operator")]:
            dash_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -m 5 -u {user}:{passwd} 'http://localhost:3000/api/search?type=dash-db'"
            dash_result = run_command(dash_cmd, timeout=10)
            
            if dash_result['exit_code'] == 0 and dash_result['stdout']:
                try:
                    if dash_result['stdout'].startswith('['):
                        dashboards = json.loads(dash_result['stdout'])
                        api_dashboard_count = len(dashboards)
                        
                        for dash in dashboards[:10]:
                            title = dash.get("title", "Untitled")
                            if title not in dashboard_names:
                                dashboard_names.append(title)
                        
                        dashboard_count = max(dashboard_count, api_dashboard_count)
                        break
                except:
                    pass
    
    if dashboard_count > 0:
        output_parts = [f"Total dashboards: {dashboard_count}"]
        
        if dashboard_names:
            sample_names = dashboard_names[:5]
            output_parts.append(f"Examples: {', '.join(sample_names)}{'...' if len(dashboard_names) > 5 else ''}")
        
        return [{
            "name": "grafana_dashboards",
            "description": "Check if dashboards are provisioned in Grafana",
            "passed": True,
            "output": " | ".join(output_parts),
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_dashboards",
            "description": "Check if dashboards are provisioned in Grafana",
            "passed": True,
            "output": "No pre-provisioned dashboards found (may be created manually or require authentication)",
            "severity": "WARNING"
        }]


def test_grafana_logs() -> List[Dict]:
    """Analyze Grafana logs for errors, warnings, and startup issues"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    pod_name = get_grafana_pod(namespace)
    if not pod_name:
        return [{
            "name": "grafana_logs_health",
            "description": "Analyze Grafana logs for errors, warnings, and startup issues",
            "passed": False,
            "output": "Could not find Grafana pod to check logs",
            "severity": "WARNING"
        }]
    
    # Get recent logs
    logs_cmd = f"kubectl logs -n {namespace} {pod_name} --tail=500 2>/dev/null"
    logs_result = run_command(logs_cmd, timeout=15)
    
    if logs_result['exit_code'] != 0:
        return [{
            "name": "grafana_logs_health",
            "description": "Analyze Grafana logs for errors, warnings, and startup issues",
            "passed": False,
            "output": "Failed to retrieve Grafana logs",
            "severity": "WARNING"
        }]
    
    # Analyze logs
    error_count = 0
    warning_count = 0
    startup_complete = False
    datasource_errors = []
    auth_errors = []
    critical_errors = []
    
    for line in logs_result['stdout'].split('\n'):
        line_lower = line.lower()
        
        # Check for successful startup
        if any(x in line_lower for x in ['http server listen', 'server is running', 'starting grafana', 'http server: listening']):
            startup_complete = True
        
        # Skip non-error lines
        if any(skip in line_lower for skip in ['error=<nil>', 'error=null', 'errors=0', 'error_log', 'no error']):
            continue
        
        # Count errors
        if 'error' in line_lower or 'failed' in line_lower:
            error_count += 1
            
            # Categorize errors
            if 'datasource' in line_lower or 'data source' in line_lower:
                if len(datasource_errors) < 3:
                    datasource_errors.append(line.strip()[:100])
            elif any(x in line_lower for x in ['auth', 'unauthorized', 'permission', 'forbidden']):
                if len(auth_errors) < 3:
                    auth_errors.append(line.strip()[:100])
            elif any(x in line_lower for x in ['panic', 'fatal', 'critical']):
                if len(critical_errors) < 3:
                    critical_errors.append(line.strip()[:100])
        
        # Count warnings
        elif 'warning' in line_lower or 'warn' in line_lower:
            warning_count += 1
    
    # Build output
    issues = []
    severity = "LOW"
    passed = True
    
    if not startup_complete:
        # Double-check if Grafana is actually running
        api_check_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -m 2 http://localhost:3000/api/health 2>/dev/null | grep -q ok"
        api_result = run_command(api_check_cmd, timeout=5)
        
        if api_result['exit_code'] != 0:
            issues.append("Grafana startup not confirmed in logs")
            severity = "WARNING"
    
    if critical_errors:
        issues.append(f"Critical errors found: {len(critical_errors)}")
        severity = "CRITICAL"
        passed = False
    
    if error_count > 20:
        issues.append(f"{error_count} errors in logs")
        severity = "WARNING" if error_count < 50 else "CRITICAL"
        if error_count > 50:
            passed = False
    
    # Add error categories
    if datasource_errors:
        issues.append(f"Datasource errors: {len(datasource_errors)}")
    if auth_errors:
        # Auth errors might be normal (failed login attempts)
        if len(auth_errors) > 10:
            issues.append(f"Many auth errors: {len(auth_errors)} (could be failed login attempts)")
    
    if warning_count > 100:
        issues.append(f"{warning_count} warnings")
    
    if issues:
        return [{
            "name": "grafana_logs_health",
            "description": "Analyze Grafana logs for errors, warnings, and startup issues",
            "passed": passed,
            "output": " | ".join(issues),
            "severity": severity
        }]
    else:
        return [{
            "name": "grafana_logs_health",
            "description": "Analyze Grafana logs for errors, warnings, and startup issues",
            "passed": True,
            "output": f"Logs are clean - Grafana running normally (warnings: {warning_count})",
            "severity": "LOW"
        }]


def test_grafana_auth() -> List[Dict]:
    """Check Grafana authentication and security settings"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    auth_info = []
    
    # Check for auth secrets
    auth_cmd = f"kubectl get secret -n {namespace} -o json"
    result = run_command(auth_cmd)
    
    if result['exit_code'] == 0:
        try:
            secret_data = json.loads(result['stdout'])
            for secret in secret_data.get("items", []):
                secret_name = secret["metadata"]["name"]
                
                # Check for Grafana admin credentials
                if "grafana" in secret_name.lower():
                    data_keys = list(secret.get("data", {}).keys())  # Convert to list to avoid set subscript error
                    if "admin-user" in data_keys or "admin-password" in data_keys:
                        auth_info.append("Admin credentials configured")
                
                # Check for external auth
                if any(x in secret_name.lower() for x in ["oauth", "ldap", "saml", "oidc"]):
                    for auth_type in ["oauth", "ldap", "saml", "oidc"]:
                        if auth_type in secret_name.lower():
                            auth_info.append(f"{auth_type.upper()} configured")
                            break
        except:
            pass
    
    # Check ConfigMap for auth settings
    auth_cm_cmd = f"kubectl get configmap -n {namespace} -o json"
    cm_result = run_command(auth_cm_cmd)
    
    if cm_result['exit_code'] == 0:
        try:
            cm_data = json.loads(cm_result['stdout'])
            for cm in cm_data.get("items", []):
                if "grafana" in cm["metadata"]["name"].lower():
                    grafana_ini = cm.get("data", {}).get("grafana.ini", "")
                    
                    if grafana_ini:
                        # Check for auth configurations
                        auth_checks = [
                            ("[auth.ldap]", "LDAP auth"),
                            ("[auth.generic_oauth]", "OAuth"),
                            ("[auth.github]", "GitHub auth"),
                            ("[auth.google]", "Google auth"),
                            ("[auth.azuread]", "Azure AD"),
                            ("allow_sign_up = false", "Sign-up disabled"),
                            ("disable_login_form = true", "SSO only")
                        ]
                        
                        for check, desc in auth_checks:
                            if check in grafana_ini:
                                auth_info.append(desc)
        except:
            pass
    
    if auth_info:
        # Remove duplicates
        auth_info = list(set(auth_info))
        return [{
            "name": "grafana_auth",
            "description": "Check Grafana authentication and security settings",
            "passed": True,
            "output": f"Authentication: {', '.join(auth_info)}",
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_auth",
            "description": "Check Grafana authentication and security settings",
            "passed": True,
            "output": "Using default authentication - consider configuring SSO for production",
            "severity": "WARNING"
        }]


def main():
    """Run all Grafana health checks"""
    print("=" * 60)
    print("GRAFANA HEALTH CHECK")
    print("=" * 60)
    
    # Run all tests
    test_functions = [
        test_grafana_pod,
        test_grafana_service,
        test_grafana_api,
        test_grafana_datasources,
        test_grafana_datasource_connectivity,
        test_grafana_dashboards,
        test_grafana_logs,
        test_grafana_auth,
    ]
    
    all_results = []
    critical_count = 0
    warning_count = 0
    passed_count = 0
    
    for test_func in test_functions:
        try:
            results = test_func()
            all_results.extend(results)
            
            for result in results:
                if not result["passed"]:
                    if result["severity"] == "CRITICAL":
                        critical_count += 1
                    elif result["severity"] == "WARNING":
                        warning_count += 1
                else:
                    passed_count += 1
                
                # Print result
                status = "✓" if result["passed"] else "✗"
                severity_indicator = {
                    "CRITICAL": "🔴",
                    "WARNING": "🟡",
                    "LOW": "🟢"
                }.get(result["severity"], "")
                
                print(f"\n{status} {severity_indicator} {result['description']}")
                print(f"  {result['output']}")
        except Exception as e:
            print(f"\nError executing test {test_func.__name__}: {str(e)}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total checks: {len(all_results)}")
    print(f"Passed: {passed_count}")
    print(f"Critical issues: {critical_count}")
    print(f"Warnings: {warning_count}")
    
    # Overall health status
    if critical_count > 0:
        print("\n⚠️  CRITICAL: Grafana has critical issues that need immediate attention")
        exit(1)
    elif warning_count > 0:
        print("\n⚠️  WARNING: Grafana is operational but has issues that should be addressed")
        exit(0)
    else:
        print("\n✅ HEALTHY: Grafana is operating normally")
        exit(0)


if __name__ == "__main__":
    main()
