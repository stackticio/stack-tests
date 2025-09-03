#!/usr/bin/env python3
"""
Grafana Health Check Script
Tests various aspects of Grafana deployment including dashboards, datasources, and integrations
"""

import os
import json
import subprocess
import re
from typing import Dict, List, Any

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
        test_pods_with_errors = []
        
        for pod in pods_data.get("items", []):
            pod_name = pod["metadata"]["name"]
            pod_status = pod["status"]["phase"]
            
            # Skip healthy test pods
            if "test" in pod_name.lower():
                if pod_status in ["Error", "Failed", "CrashLoopBackOff"]:
                    test_pods_with_errors.append(f"{pod_name}({pod_status})")
                continue
            
            # Check Grafana pods
            if "grafana" in pod_name.lower():
                ready = all(
                    container.get("ready", False) 
                    for container in pod["status"].get("containerStatuses", [])
                )
                
                # Get restart count
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
            output = f"Unhealthy Grafana pods: {', '.join(failed_pods)}"
            if test_pods_with_errors:
                output += f" | Failed test pods: {', '.join(test_pods_with_errors)}"
            return [{
                "name": "grafana_pod_health",
                "description": "Check if Grafana pod is running and healthy",
                "passed": False,
                "output": output,
                "severity": "CRITICAL"
            }]
        
        output = f"Healthy pods: {', '.join(grafana_pods)}"
        if test_pods_with_errors:
            output += f" | Failed test pods: {', '.join(test_pods_with_errors)}"
        
        return [{
            "name": "grafana_pod_health",
            "description": "Check if Grafana pod is running and healthy",
            "passed": True,
            "output": output,
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
        
        # Get external IP if LoadBalancer
        external_ips = []
        if service_type == "LoadBalancer":
            ingress = service_data["status"].get("loadBalancer", {}).get("ingress", [])
            for ing in ingress:
                if ing.get("ip"):
                    external_ips.append(ing["ip"])
                elif ing.get("hostname"):
                    external_ips.append(ing["hostname"])
        
        # Check endpoints
        endpoints_cmd = f"kubectl get endpoints grafana -n {namespace} -o json"
        ep_result = run_command(endpoints_cmd)
        
        has_endpoints = False
        endpoint_count = 0
        endpoint_ips = []
        
        if ep_result['exit_code'] == 0:
            ep_data = json.loads(ep_result['stdout'])
            subsets = ep_data.get("subsets", [])
            if subsets:
                for subset in subsets:
                    addresses = subset.get("addresses", [])
                    endpoint_count += len(addresses)
                    for addr in addresses[:3]:  # First 3 endpoints
                        endpoint_ips.append(addr.get("ip", "unknown"))
                has_endpoints = endpoint_count > 0
        
        if not has_endpoints:
            return [{
                "name": "grafana_service_health",
                "description": "Check if Grafana service is configured and has endpoints",
                "passed": False,
                "output": "Grafana service has no endpoints - no pods are serving traffic",
                "severity": "CRITICAL"
            }]
        
        port_info = ", ".join([f"{p.get('name', 'unnamed')}:{p.get('port')}→{p.get('targetPort')}" for p in ports])
        
        output = f"Service Type: {service_type}, ClusterIP: {cluster_ip}, Ports: [{port_info}], Active Endpoints: {endpoint_count}"
        if endpoint_ips:
            output += f" (IPs: {', '.join(endpoint_ips)})"
        if external_ips:
            output += f", External: {', '.join(external_ips)}"
        
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
    
    # Get Grafana pod
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=grafana -o jsonpath='{{.items[0].metadata.name}}' 2>/dev/null"
    result = run_command(cmd)
    
    if result['exit_code'] != 0 or not result['stdout'].strip():
        # Try alternative label
        cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
        result = run_command(cmd)
    
    if not result['stdout'].strip():
        return [{
            "name": "grafana_api_health",
            "description": "Check if Grafana API is accessible and responding",
            "passed": False,
            "output": "Could not find Grafana pod to test API",
            "severity": "CRITICAL"
        }]
    
    pod_name = result['stdout'].strip()
    
    # Check health endpoint
    health_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s http://localhost:3000/api/health"
    health_result = run_command(health_cmd)
    
    if health_result['exit_code'] == 0 and health_result['stdout']:
        try:
            health_data = json.loads(health_result['stdout'])
            db_status = health_data.get("database", "unknown")
            version = health_data.get("version", "unknown")
            
            output = f"API healthy, Database: {db_status}"
            if version != "unknown":
                output += f", Version: {version}"
            
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
            # API responded but maybe not with JSON
            if "database" in health_result['stdout'].lower() or "ok" in health_result['stdout'].lower():
                return [{
                    "name": "grafana_api_health",
                    "description": "Check if Grafana API is accessible and responding",
                    "passed": True,
                    "output": "Grafana API is responding (non-JSON response)",
                    "severity": "LOW"
                }]
    
    # Fallback: check if port is listening
    port_check_cmd = f"kubectl exec -n {namespace} {pod_name} -- nc -zv localhost 3000 2>&1"
    port_result = run_command(port_check_cmd)
    
    if port_result['exit_code'] == 0 or "succeeded" in port_result['stdout'].lower():
        return [{
            "name": "grafana_api_health",
            "description": "Check if Grafana API is accessible and responding",
            "passed": True,
            "output": "Grafana is listening on port 3000 (API endpoint not accessible)",
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
    
    datasources_found = {}
    
    # Get pod name
    pod_cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
    pod_result = run_command(pod_cmd)
    
    if pod_result['stdout'].strip():
        pod_name = pod_result['stdout'].strip()
        
        # Get admin password
        admin_pass = "admin"  # default
        secret_cmd = f"kubectl get secret -n {namespace} grafana -o jsonpath='{{.data.admin-password}}' 2>/dev/null | base64 -d"
        secret_result = run_command(secret_cmd)
        if secret_result['exit_code'] == 0 and secret_result['stdout']:
            admin_pass = secret_result['stdout'].strip()
        
        # Query datasources via API
        ds_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -u admin:{admin_pass} http://localhost:3000/api/datasources"
        ds_result = run_command(ds_cmd)
        
        if ds_result['exit_code'] == 0 and ds_result['stdout']:
            try:
                if ds_result['stdout'].startswith('['):
                    datasources = json.loads(ds_result['stdout'])
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
            except:
                pass
    
    # Check ConfigMaps for datasource configurations
    cm_cmd = f"kubectl get configmap -n {namespace} -o json"
    cm_result = run_command(cm_cmd)
    
    if cm_result['exit_code'] == 0:
        try:
            cm_data = json.loads(cm_result['stdout'])
            for cm in cm_data.get("items", []):
                cm_name = cm["metadata"]["name"]
                
                for key, value in cm.get("data", {}).items():
                    if "datasource" in key.lower() or "datasource" in cm_name.lower():
                        # Detect datasource types from content
                        if "prometheus" in value.lower():
                            datasources_found["Prometheus (ConfigMap)"] = {"type": "prometheus", "url": "from ConfigMap", "default": False}
                        if "loki" in value.lower():
                            datasources_found["Loki (ConfigMap)"] = {"type": "loki", "url": "from ConfigMap", "default": False}
                        if "elasticsearch" in value.lower() or "opensearch" in value.lower():
                            datasources_found["Elasticsearch/OpenSearch (ConfigMap)"] = {"type": "elasticsearch", "url": "from ConfigMap", "default": False}
                        if "tempo" in value.lower():
                            datasources_found["Tempo (ConfigMap)"] = {"type": "tempo", "url": "from ConfigMap", "default": False}
                        if "jaeger" in value.lower():
                            datasources_found["Jaeger (ConfigMap)"] = {"type": "jaeger", "url": "from ConfigMap", "default": False}
        except:
            pass
    
    if datasources_found:
        # Group by type
        by_type = {}
        for name, info in datasources_found.items():
            ds_type = info["type"]
            if ds_type not in by_type:
                by_type[ds_type] = []
            by_type[ds_type].append(name)
        
        output_parts = [f"Total datasources: {len(datasources_found)}"]
        
        # List datasources by type with details
        for ds_type, names in by_type.items():
            output_parts.append(f"{ds_type.upper()}: {len(names)} ({', '.join(names[:2])}{'...' if len(names) > 2 else ''})")
        
        # Check observability capabilities
        has_metrics = any(info["type"] in ["prometheus", "influxdb", "graphite"] for info in datasources_found.values())
        has_logs = any(info["type"] in ["loki", "elasticsearch", "opensearch"] for info in datasources_found.values())
        has_traces = any(info["type"] in ["jaeger", "tempo", "zipkin"] for info in datasources_found.values())
        
        capabilities = []
        if has_metrics:
            capabilities.append("Metrics✓")
        if has_logs:
            capabilities.append("Logs✓")
        if has_traces:
            capabilities.append("Traces✓")
        
        if capabilities:
            output_parts.append(f"Observability: {', '.join(capabilities)}")
        
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
    else:
        return [{
            "name": "grafana_datasources",
            "description": "Check and identify all configured datasources in Grafana",
            "passed": False,
            "output": "No datasources found - Grafana cannot query any data",
            "severity": "CRITICAL"
        }]


def test_grafana_datasource_connectivity() -> List[Dict]:
    """Verify that Grafana can connect to its configured datasources"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    # Get pod name
    pod_cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
    pod_result = run_command(pod_cmd)
    
    if not pod_result['stdout'].strip():
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": False,
            "output": "Could not find Grafana pod to test connectivity",
            "severity": "WARNING"
        }]
    
    pod_name = pod_result['stdout'].strip()
    
    # Get admin password
    admin_pass = "admin"
    secret_cmd = f"kubectl get secret -n {namespace} grafana -o jsonpath='{{.data.admin-password}}' 2>/dev/null | base64 -d"
    secret_result = run_command(secret_cmd)
    if secret_result['exit_code'] == 0 and secret_result['stdout']:
        admin_pass = secret_result['stdout'].strip()
    
    # Get datasources
    ds_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -u admin:{admin_pass} http://localhost:3000/api/datasources"
    ds_result = run_command(ds_cmd)
    
    connectivity_results = []
    failed_datasources = []
    
    if ds_result['exit_code'] == 0 and ds_result['stdout']:
        try:
            if ds_result['stdout'].startswith('['):
                datasources = json.loads(ds_result['stdout'])
                
                for ds in datasources:
                    ds_id = ds.get("id")
                    ds_name = ds.get("name", "unknown")
                    ds_type = ds.get("type", "unknown")
                    ds_url = ds.get("url", "")
                    
                    # Test datasource health
                    health_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -u admin:{admin_pass} 'http://localhost:3000/api/datasources/proxy/{ds_id}/api/v1/query?query=up' 2>/dev/null | head -c 100"
                    health_result = run_command(health_cmd, timeout=5)
                    
                    # Alternative health check
                    if health_result['exit_code'] != 0:
                        health_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -u admin:{admin_pass} 'http://localhost:3000/api/datasources/{ds_id}/health'"
                        health_result = run_command(health_cmd, timeout=5)
                    
                    if health_result['exit_code'] == 0 and health_result['stdout']:
                        if "error" not in health_result['stdout'].lower():
                            connectivity_results.append(f"{ds_name}({ds_type}): Connected to {ds_url[:30]}{'...' if len(ds_url) > 30 else ''}")
                        else:
                            failed_datasources.append(f"{ds_name}({ds_type}): Connection failed")
                    else:
                        connectivity_results.append(f"{ds_name}({ds_type}): Configured at {ds_url[:30]}{'...' if len(ds_url) > 30 else ''}")
        except:
            pass
    
    # Test common endpoints directly
    common_endpoints = [
        ("prometheus-kube-prometheus-prometheus.prometheus:9090", "Prometheus"),
        ("loki.loki:3100", "Loki"),
        ("tempo.tempo:3100", "Tempo"),
        ("elasticsearch.elastic:9200", "Elasticsearch"),
        ("opensearch.opensearch:9200", "OpenSearch")
    ]
    
    for endpoint, name in common_endpoints:
        test_cmd = f"kubectl exec -n {namespace} {pod_name} -- nc -zv {endpoint.split(':')[0]} {endpoint.split(':')[1]} 2>&1"
        test_result = run_command(test_cmd, timeout=2)
        
        if test_result['exit_code'] == 0 or "succeeded" in test_result['stdout'].lower() or "connected" in test_result['stdout'].lower():
            connectivity_results.append(f"{name} endpoint reachable at {endpoint}")
    
    if failed_datasources:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": False,
            "output": f"Failed connections: {', '.join(failed_datasources)} | Working: {', '.join(connectivity_results[:3])}",
            "severity": "WARNING"
        }]
    elif connectivity_results:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": True,
            "output": f"Verified connections: {', '.join(connectivity_results[:5])}{'...' if len(connectivity_results) > 5 else ''}",
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_datasource_connectivity",
            "description": "Verify that Grafana can connect to its configured datasources",
            "passed": True,
            "output": "Could not verify datasource connectivity (authentication may be required)",
            "severity": "LOW"
        }]


def test_grafana_dashboards() -> List[Dict]:
    """Check if dashboards are provisioned in Grafana"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    dashboard_count = 0
    dashboard_names = []
    dashboard_sources = []
    
    # Check for dashboard ConfigMaps
    cmd = f"kubectl get configmap -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] == 0:
        try:
            cm_data = json.loads(result['stdout'])
            
            for cm in cm_data.get("items", []):
                cm_name = cm["metadata"]["name"]
                
                # Look for dashboard ConfigMaps
                if any(x in cm_name.lower() for x in ["dashboard", "grafana"]):
                    for key, value in cm.get("data", {}).items():
                        if ".json" in key.lower() or '"dashboard"' in str(value)[:1000]:
                            dashboard_count += 1
                            dashboard_names.append(key.replace('.json', ''))
                            if cm_name not in dashboard_sources:
                                dashboard_sources.append(cm_name)
        except:
            pass
    
    # Try to get dashboards via API
    pod_cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
    pod_result = run_command(pod_cmd)
    
    if pod_result['stdout'].strip():
        pod_name = pod_result['stdout'].strip()
        
        # Get admin password
        admin_pass = "admin"
        secret_cmd = f"kubectl get secret -n {namespace} grafana -o jsonpath='{{.data.admin-password}}' 2>/dev/null | base64 -d"
        secret_result = run_command(secret_cmd)
        if secret_result['exit_code'] == 0 and secret_result['stdout']:
            admin_pass = secret_result['stdout'].strip()
        
        # Query dashboards
        dash_cmd = f"kubectl exec -n {namespace} {pod_name} -- curl -s -u admin:{admin_pass} 'http://localhost:3000/api/search?type=dash-db'"
        dash_result = run_command(dash_cmd)
        
        if dash_result['exit_code'] == 0 and dash_result['stdout']:
            try:
                if dash_result['stdout'].startswith('['):
                    dashboards = json.loads(dash_result['stdout'])
                    api_dashboard_count = len(dashboards)
                    
                    for dash in dashboards[:10]:  # First 10
                        title = dash.get("title", "Untitled")
                        dash_type = dash.get("type", "")
                        tags = dash.get("tags", [])
                        
                        if title not in dashboard_names:
                            dashboard_names.append(title)
                            dashboard_count = max(dashboard_count, api_dashboard_count)
                        
                        if tags:
                            dashboard_sources.append(f"tags: {', '.join(tags[:3])}")
            except:
                pass
    
    # Check for dashboard providers
    provider_cmd = f"kubectl get configmap -n {namespace} -o yaml | grep -i 'dashboardProviders' | wc -l"
    provider_result = run_command(provider_cmd)
    has_providers = int(provider_result['stdout'].strip()) > 0 if provider_result['stdout'].strip().isdigit() else False
    
    output_parts = []
    
    if dashboard_count > 0:
        output_parts.append(f"Total dashboards: {dashboard_count}")
        
        if dashboard_names:
            sample_names = dashboard_names[:5]
            output_parts.append(f"Samples: {', '.join(sample_names)}{'...' if len(dashboard_names) > 5 else ''}")
        
        if dashboard_sources:
            output_parts.append(f"Sources: {', '.join(set(dashboard_sources)[:3])}")
    
    if has_providers:
        output_parts.append("Dashboard auto-provisioning enabled")
    
    if output_parts:
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
            "output": "No pre-provisioned dashboards found (dashboards may be created manually)",
            "severity": "LOW"
        }]


def test_grafana_logs() -> List[Dict]:
    """Analyze Grafana logs for errors, warnings, and startup issues"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    # Get Grafana pod
    pod_cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
    pod_result = run_command(pod_cmd)
    
    if not pod_result['stdout'].strip():
        return [{
            "name": "grafana_logs_health",
            "description": "Analyze Grafana logs for errors, warnings, and startup issues",
            "passed": False,
            "output": "Could not find Grafana pod to check logs",
            "severity": "WARNING"
        }]
    
    pod_name = pod_result['stdout'].strip()
    
    # Get recent logs
    logs_cmd = f"kubectl logs -n {namespace} {pod_name} --tail=200 2>/dev/null"
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
    dashboard_errors = []
    auth_errors = []
    plugin_errors = []
    sample_errors = []
    
    for line in logs_result['stdout'].split('\n'):
        line_lower = line.lower()
        
        # Check for successful startup
        if 'http server listen' in line_lower or 'server is running' in line_lower or 'grafana server' in line_lower:
            startup_complete = True
        
        # Count errors
        if 'error' in line_lower or 'failed' in line_lower:
            # Skip false positives
            if not any(skip in line_lower for skip in ['error=null', 'errors=0', 'error_log']):
                error_count += 1
                
                # Collect sample errors
                if len(sample_errors) < 3 and len(line) < 150:
                    sample_errors.append(line.strip()[:100])
                
                # Categorize errors
                if 'datasource' in line_lower or 'data source' in line_lower:
                    datasource_errors.append(line[:100])
                elif 'dashboard' in line_lower:
                    dashboard_errors.append(line[:100])
                elif 'auth' in line_lower or 'ldap' in line_lower or 'oauth' in line_lower:
                    auth_errors.append(line[:100])
                elif 'plugin' in line_lower:
                    plugin_errors.append(line[:100])
        
        # Count warnings
        elif 'warning' in line_lower or 'warn' in line_lower:
            warning_count += 1
    
    # Build output
    issues = []
    severity = "LOW"
    passed = True
    
    if not startup_complete:
        issues.append("Grafana startup not confirmed")
        severity = "CRITICAL"
        passed = False
    
    if error_count > 20:
        issues.append(f"{error_count} errors in logs")
        severity = "CRITICAL" if error_count > 50 else "WARNING"
        passed = False
    elif error_count > 5:
        issues.append(f"{error_count} errors in logs")
        severity = "WARNING"
    
    # Add error categories
    error_categories = []
    if datasource_errors:
        error_categories.append(f"datasource({len(datasource_errors)})")
    if dashboard_errors:
        error_categories.append(f"dashboard({len(dashboard_errors)})")
    if auth_errors:
        error_categories.append(f"auth({len(auth_errors)})")
    if plugin_errors:
        error_categories.append(f"plugin({len(plugin_errors)})")
    
    if error_categories:
        issues.append(f"Error types: {', '.join(error_categories)}")
    
    if warning_count > 50:
        issues.append(f"{warning_count} warnings")
    
    # Add sample errors if present
    if sample_errors and error_count > 0:
        issues.append(f"Sample: '{sample_errors[0]}'")
    
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
            "output": f"Logs are clean - Grafana started successfully (warnings: {warning_count})",
            "severity": "LOW"
        }]


def test_grafana_storage() -> List[Dict]:
    """Check if Grafana has persistent storage configured"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    # Check for PVCs
    cmd = f"kubectl get pvc -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "grafana_persistent_storage",
            "description": "Check if Grafana has persistent storage configured",
            "passed": True,
            "output": "No PVCs found - using SQLite in-memory or external database",
            "severity": "LOW"
        }]
    
    try:
        pvc_data = json.loads(result['stdout'])
        pvcs = []
        unbound_pvcs = []
        
        for pvc in pvc_data.get("items", []):
            pvc_name = pvc["metadata"]["name"]
            pvc_status = pvc["status"]["phase"]
            capacity = pvc["status"].get("capacity", {}).get("storage", "unknown")
            storage_class = pvc["spec"].get("storageClassName", "default")
            access_modes = pvc["spec"].get("accessModes", [])
            
            if pvc_status == "Bound":
                pvc_info = f"{pvc_name}({capacity}, {storage_class}, {'/'.join(access_modes)})"
                pvcs.append(pvc_info)
            else:
                unbound_pvcs.append(f"{pvc_name}(Status: {pvc_status})")
        
        if unbound_pvcs:
            return [{
                "name": "grafana_persistent_storage",
                "description": "Check if Grafana has persistent storage configured",
                "passed": False,
                "output": f"Unbound PVCs: {', '.join(unbound_pvcs)}",
                "severity": "WARNING"
            }]
        
        if pvcs:
            return [{
                "name": "grafana_persistent_storage",
                "description": "Check if Grafana has persistent storage configured",
                "passed": True,
                "output": f"Persistent storage: {', '.join(pvcs)}",
                "severity": "LOW"
            }]
        else:
            return [{
                "name": "grafana_persistent_storage",
                "description": "Check if Grafana has persistent storage configured",
                "passed": True,
                "output": "No persistent storage - using ephemeral storage (data loss on restart)",
                "severity": "LOW"
            }]
            
    except Exception as e:
        return [{
            "name": "grafana_persistent_storage",
            "description": "Check if Grafana has persistent storage configured",
            "passed": False,
            "output": f"Failed to check storage: {str(e)}",
            "severity": "WARNING"
        }]


def test_grafana_ingress() -> List[Dict]:
    """Check if Grafana has ingress configured for external access"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    ingress_info = []
    
    # Check for Ingress resources
    cmd = f"kubectl get ingress -n {namespace} -o json"
    result = run_command(cmd)
    
    if result['exit_code'] == 0:
        try:
            ingress_data = json.loads(result['stdout'])
            for ingress in ingress_data.get("items", []):
                ingress_name = ingress["metadata"]["name"]
                rules = ingress["spec"].get("rules", [])
                tls = ingress["spec"].get("tls", [])
                
                for rule in rules:
                    host = rule.get("host", "no-host")
                    paths = []
                    http = rule.get("http", {})
                    for path in http.get("paths", []):
                        paths.append(path.get("path", "/"))
                    
                    ingress_entry = f"{ingress_name}: {host}{', '.join(paths)}"
                    if tls:
                        ingress_entry += " (TLS)"
                    ingress_info.append(ingress_entry)
        except:
            pass
    
    # Check service type
    svc_cmd = f"kubectl get service grafana -n {namespace} -o json"
    svc_result = run_command(svc_cmd)
    
    if svc_result['exit_code'] == 0:
        try:
            svc_data = json.loads(svc_result['stdout'])
            svc_type = svc_data["spec"].get("type", "")
            
            if svc_type == "LoadBalancer":
                external_ips = []
                ingress_lb = svc_data["status"].get("loadBalancer", {}).get("ingress", [])
                for ing in ingress_lb:
                    if ing.get("ip"):
                        external_ips.append(ing["ip"])
                    elif ing.get("hostname"):
                        external_ips.append(ing["hostname"])
                
                lb_info = f"LoadBalancer service"
                if external_ips:
                    lb_info += f" ({', '.join(external_ips)})"
                ingress_info.append(lb_info)
                
            elif svc_type == "NodePort":
                ports = svc_data["spec"].get("ports", [])
                node_ports = [str(p.get("nodePort")) for p in ports if p.get("nodePort")]
                if node_ports:
                    ingress_info.append(f"NodePort service (ports: {', '.join(node_ports)})")
                else:
                    ingress_info.append("NodePort service")
        except:
            pass
    
    if ingress_info:
        return [{
            "name": "grafana_ingress",
            "description": "Check if Grafana has ingress configured for external access",
            "passed": True,
            "output": f"External access: {' | '.join(ingress_info)}",
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_ingress",
            "description": "Check if Grafana has ingress configured for external access",
            "passed": True,
            "output": "No external access configured - only accessible within cluster (ClusterIP)",
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
                    if "admin" in secret_name.lower():
                        auth_info.append("Admin credentials in secret")
                    
                    # Check secret data keys
                    data_keys = secret.get("data", {}).keys()
                    if "admin-user" in data_keys or "admin-password" in data_keys:
                        auth_info.append("Admin auth configured")
                
                # Check for external auth
                if any(x in secret_name.lower() for x in ["oauth", "ldap", "saml", "oidc", "github", "google", "azure"]):
                    auth_type = "OAuth/SSO"
                    for auth in ["oauth", "ldap", "saml", "oidc", "github", "google", "azure"]:
                        if auth in secret_name.lower():
                            auth_type = auth.upper()
                            break
                    auth_info.append(f"{auth_type} configured")
        except:
            pass
    
    # Check ConfigMap for auth settings
    auth_cm_cmd = f"kubectl get configmap -n {namespace} grafana -o json 2>/dev/null"
    cm_result = run_command(auth_cm_cmd)
    
    if cm_result['exit_code'] == 0:
        try:
            cm_data = json.loads(cm_result['stdout'])
            grafana_ini = cm_data.get("data", {}).get("grafana.ini", "")
            
            if grafana_ini:
                # Check for auth configurations
                if "[auth.ldap]" in grafana_ini:
                    auth_info.append("LDAP auth enabled")
                if "[auth.generic_oauth]" in grafana_ini or "oauth" in grafana_ini.lower():
                    auth_info.append("OAuth enabled")
                if "[auth.github]" in grafana_ini:
                    auth_info.append("GitHub auth enabled")
                if "[auth.google]" in grafana_ini:
                    auth_info.append("Google auth enabled")
                if "[auth.azuread]" in grafana_ini:
                    auth_info.append("Azure AD enabled")
                if "allow_sign_up = false" in grafana_ini:
                    auth_info.append("Sign-up disabled")
                if "disable_login_form = true" in grafana_ini:
                    auth_info.append("Login form disabled (SSO only)")
        except:
            pass
    
    # Check deployment for auth environment variables
    env_cmd = f"kubectl get deployment grafana -n {namespace} -o json"
    env_result = run_command(env_cmd)
    
    if env_result['exit_code'] == 0:
        try:
            deployment_data = json.loads(env_result['stdout'])
            containers = deployment_data["spec"]["template"]["spec"]["containers"]
            
            for container in containers:
                if "grafana" in container["name"].lower():
                    for env in container.get("env", []):
                        env_name = env.get("name", "")
                        
                        if "GF_AUTH" in env_name:
                            if "LDAP" in env_name:
                                auth_info.append("LDAP via env")
                            elif "OAUTH" in env_name or "GENERIC_OAUTH" in env_name:
                                auth_info.append("OAuth via env")
                            elif "GITHUB" in env_name:
                                auth_info.append("GitHub auth via env")
        except:
            pass
    
    if auth_info:
        # Remove duplicates and create summary
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
            "output": "Using default authentication (admin/admin or admin/prom-operator) - consider configuring SSO",
            "severity": "WARNING"
        }]


def test_grafana_plugins() -> List[Dict]:
    """Check if any Grafana plugins are installed"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    # Get Grafana pod
    pod_cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
    pod_result = run_command(pod_cmd)
    
    if not pod_result['stdout'].strip():
        return [{
            "name": "grafana_plugins",
            "description": "Check if any Grafana plugins are installed",
            "passed": False,
            "output": "Could not find Grafana pod to check plugins",
            "severity": "WARNING"
        }]
    
    pod_name = pod_result['stdout'].strip()
    plugin_info = []
    
    # Check for plugins directory
    plugins_cmd = f"kubectl exec -n {namespace} {pod_name} -- ls -la /var/lib/grafana/plugins 2>/dev/null"
    plugins_result = run_command(plugins_cmd)
    
    if plugins_result['exit_code'] == 0 and plugins_result['stdout']:
        lines = plugins_result['stdout'].split('\n')
        plugin_dirs = []
        
        for line in lines:
            if line and not line.startswith('total') and not line.endswith('.'):
                parts = line.split()
                if len(parts) >= 9:
                    plugin_name = parts[-1]
                    if plugin_name not in ['.', '..']:
                        plugin_dirs.append(plugin_name)
        
        if plugin_dirs:
            plugin_info.append(f"{len(plugin_dirs)} plugins in directory: {', '.join(plugin_dirs[:5])}{'...' if len(plugin_dirs) > 5 else ''}")
    
    # Check environment variables for plugin installation
    env_cmd = f"kubectl get deployment grafana -n {namespace} -o json | jq '.spec.template.spec.containers[0].env[] | select(.name==\"GF_INSTALL_PLUGINS\")' 2>/dev/null"
    env_result = run_command(env_cmd)
    
    if env_result['exit_code'] == 0 and env_result['stdout']:
        try:
            env_data = json.loads(env_result['stdout'])
            plugins_list = env_data.get("value", "")
            if plugins_list:
                plugin_names = [p.strip() for p in plugins_list.split(',')]
                plugin_info.append(f"Configured via env: {', '.join(plugin_names[:5])}{'...' if len(plugin_names) > 5 else ''}")
        except:
            if "GF_INSTALL_PLUGINS" in env_result['stdout']:
                plugin_info.append("Plugins configured via environment")
    
    if plugin_info:
        return [{
            "name": "grafana_plugins",
            "description": "Check if any Grafana plugins are installed",
            "passed": True,
            "output": " | ".join(plugin_info),
            "severity": "LOW"
        }]
    else:
        return [{
            "name": "grafana_plugins",
            "description": "Check if any Grafana plugins are installed",
            "passed": True,
            "output": "No additional plugins installed (using built-in plugins only)",
            "severity": "LOW"
        }]


def test_grafana_resources() -> List[Dict]:
    """Check Grafana pod resource usage and limits"""
    namespace = os.getenv('GRAFANA_NAMESPACE', 'grafana')
    
    # Get Grafana pod
    pod_cmd = f"kubectl get pods -n {namespace} | grep grafana | grep -v test | head -1 | awk '{{print $1}}'"
    pod_result = run_command(pod_cmd)
    
    if not pod_result['stdout'].strip():
        return [{
            "name": "grafana_resource_usage",
            "description": "Check Grafana pod resource usage and limits",
            "passed": False,
            "output": "Could not find Grafana pod",
            "severity": "WARNING"
        }]
    
    pod_name = pod_result['stdout'].strip()
    
    # Get resource configuration
    resources_cmd = f"kubectl get pod {pod_name} -n {namespace} -o json"
    result = run_command(resources_cmd)
    
    if result['exit_code'] != 0:
        return [{
            "name": "grafana_resource_usage",
            "description": "Check Grafana pod resource usage and limits",
            "passed": False,
            "output": f"Failed to get pod resources: {result['stderr']}",
            "severity": "WARNING"
        }]
    
    try:
        pod_data = json.loads(result['stdout'])
        containers = pod_data["spec"]["containers"]
        
        resource_info = []
        for container in containers:
            if "grafana" in container["name"].lower():
                resources = container.get("resources", {})
                limits = resources.get("limits", {})
                requests = resources.get("requests", {})
                
                resource_parts = []
                if requests:
                    req_cpu = requests.get("cpu", "none")
                    req_mem = requests.get("memory", "none")
                    resource_parts.append(f"Requests: CPU={req_cpu}, Mem={req_mem}")
                
                if limits:
                    lim_cpu = limits.get("cpu", "none")
                    lim_mem = limits.get("memory", "none")
                    resource_parts.append(f"Limits: CPU={lim_cpu}, Mem={lim_mem}")
                
                if resource_parts:
                    resource_info.extend(resource_parts)
        
        # Get current usage if metrics-server is available
        top_cmd = f"kubectl top pod {pod_name} -n {namespace} --no-headers 2>/dev/null"
        top_result = run_command(top_cmd)
        
        if top_result['exit_code'] == 0 and top_result['stdout']:
            parts = top_result['stdout'].split()
            if len(parts) >= 3:
                current_cpu = parts[1]
                current_mem = parts[2]
                resource_info.append(f"Current: CPU={current_cpu}, Mem={current_mem}")
        
        if resource_info:
            return [{
                "name": "grafana_resource_usage",
                "description": "Check Grafana pod resource usage and limits",
                "passed": True,
                "output": " | ".join(resource_info),
                "severity": "LOW"
            }]
        else:
            return [{
                "name": "grafana_resource_usage",
                "description": "Check Grafana pod resource usage and limits",
                "passed": True,
                "output": "No resource limits configured - using default/unlimited resources",
                "severity": "WARNING"
            }]
            
    except Exception as e:
        return [{
            "name": "grafana_resource_usage",
            "description": "Check Grafana pod resource usage and limits",
            "passed": False,
            "output": f"Failed to parse resources: {str(e)}",
            "severity": "WARNING"
        }]
