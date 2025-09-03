

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ArgoCD Health Check Script
Tests various aspects of ArgoCD deployment and applications
Returns results in JSON format with no external dependencies
"""

import subprocess
import json
import sys
import re
from typing import Dict, List
from datetime import datetime
from collections import defaultdict
import os

NAMESPACE = "argocd"
TEST_RESULTS = []
    
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
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "exit_code": completed.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "exit_code": 124}

def test_argocd_pods() -> List[Dict]:
    """Check if all ArgoCD core components are running"""
    name = "argocd_pods_health"
    
    cmd = f"kubectl get pods -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to get pods: {stderr}",
            "severity": "WARNING"  
        }]
    
    try:
        pods_data = json.loads(stdout)
        unhealthy_pods = []
        component_status = {}
        
        # Define critical components
        critical_components = [
            "application-controller",
            "repo-server",
            "server",
            "redis"
        ]
        
        for pod in pods_data.get("items", []):
            pod_name = pod["metadata"]["name"]
            pod_status = pod["status"]["phase"]
            
            # Get component from labels
            labels = pod["metadata"].get("labels", {})
            component = labels.get("app.kubernetes.io/component", "unknown")
            
            # Check if all containers are ready
            ready = all(
                container.get("ready", False) 
                for container in pod["status"].get("containerStatuses", [])
            )
            
            component_status[component] = {
                "pod": pod_name,
                "status": pod_status,
                "ready": ready
            }
            
            if pod_status != "Running" or not ready:
                unhealthy_pods.append(f"{pod_name} (Component: {component}, Status: {pod_status}, Ready: {ready})")
        
        # Check for missing critical components
        missing_components = []
        for comp in critical_components:
            if comp not in component_status:
                missing_components.append(comp)
        
        if missing_components:
            return [{
                "name": name,
                "status": False,
                "output": f"Missing critical components: {', '.join(missing_components)}",
                "severity": "CRITICAL"  
            }]
        
        if unhealthy_pods:
            return [{
                "name": name,
                "status": False,
                "output": f"Unhealthy pods found: {', '.join(unhealthy_pods)}",
                "severity": "CRITICAL"  
            }]
        
        total_pods = len(pods_data.get("items", []))
        components_list = ', '.join([f"{k}:OK" for k in component_status.keys()])
        return [{
                "name": name,
                "status": True,
                "output": f"All {total_pods} ArgoCD pods are healthy. Components: {components_list}",
                "severity": "INFO"  
            }]
        
    except json.JSONDecodeError as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to parse pod data: {str(e)}",
                "severity": "CRITICAL"  
            }]

def test_applications_sync_status() -> List[Dict]:
    """Check sync status of all ArgoCD applications"""
    name = "applications_sync_status"
    
    cmd = f"kubectl get Application -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to get applications: {stderr}",
                "severity": "WARNING"  
            }]
    
    try:
        apps_data = json.loads(stdout)
        sync_stats = defaultdict(list)
        
        for app in apps_data.get("items", []):
            app_name = app["metadata"]["name"]
            sync_status = app.get("status", {}).get("sync", {}).get("status", "Unknown")
            
            sync_stats[sync_status].append(app_name)
        
        total_apps = len(apps_data.get("items", []))
        
        # Build detailed output
        output_lines = [f"Total applications: {total_apps}"]
        
        # Determine severity based on sync status
        severity = "INFO"
        passed = True
        
        if sync_stats.get("Synced"):
            output_lines.append(f"[OK] Synced ({len(sync_stats['Synced'])}): {', '.join(sync_stats['Synced'][:5])}")
        
        if sync_stats.get("OutOfSync"):
            output_lines.append(f"[WARN] OutOfSync ({len(sync_stats['OutOfSync'])}): {', '.join(sync_stats['OutOfSync'])}")
            severity = "WARNING"
            passed = False
        
        if sync_stats.get("Unknown"):
            output_lines.append(f"[?] Unknown ({len(sync_stats['Unknown'])}): {', '.join(sync_stats['Unknown'])}")
            if len(sync_stats['Unknown']) > total_apps * 0.5:  # More than 50% unknown
                severity = "CRITICAL"
                passed = False
        
        # Check for other statuses
        other_statuses = [s for s in sync_stats.keys() if s not in ["Synced", "OutOfSync", "Unknown"]]
        if other_statuses:
            for status in other_statuses:
                output_lines.append(f"[*] {status} ({len(sync_stats[status])}): {', '.join(sync_stats[status])}")
        
        output = " | ".join(output_lines)
        
        # If all apps are synced, mark as passed
        if len(sync_stats.get("Synced", [])) == total_apps:
            passed = True
            severity = "INFO"
            output = f"All {total_apps} applications are synced successfully"
        
        return [{
                "name": name,
                "status": passed,
                "output": output,
                "severity": severity  
            }]
        
    except Exception as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to parse application data: {str(e)}",
                "severity": "WARNING"  
            }]

def test_applications_health_status() -> List[Dict]:
    """Check health status of all ArgoCD applications"""
    name = "applications_health_status"
    
    cmd = f"kubectl get Application -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to get applications: {stderr}",
                "severity": "WARNING"  
            }]
    
    try:
        apps_data = json.loads(stdout)
        health_stats = defaultdict(list)
        
        for app in apps_data.get("items", []):
            app_name = app["metadata"]["name"]
            health_status = app.get("status", {}).get("health", {}).get("status", "Unknown")
            
            health_stats[health_status].append(app_name)
        
        total_apps = len(apps_data.get("items", []))
        
        # Build detailed output
        output_lines = [f"Total applications: {total_apps}"]
        
        # Determine severity based on health status
        severity = "INFO"
        passed = True
        
        if health_stats.get("Healthy"):
            output_lines.append(f"[OK] Healthy ({len(health_stats['Healthy'])}): {', '.join(health_stats['Healthy'][:5])}")
        
        if health_stats.get("Degraded"):
            output_lines.append(f"[WARN] Degraded ({len(health_stats['Degraded'])}): {', '.join(health_stats['Degraded'])}")
            severity = "WARNING"
            passed = False
        
        if health_stats.get("Progressing"):
            output_lines.append(f"[PROG] Progressing ({len(health_stats['Progressing'])}): {', '.join(health_stats['Progressing'])}")
            # Progressing is not necessarily bad
        
        if health_stats.get("Missing"):
            output_lines.append(f"[ERR] Missing ({len(health_stats['Missing'])}): {', '.join(health_stats['Missing'])}")
            severity = "CRITICAL"
            passed = False
        
        if health_stats.get("Unknown"):
            output_lines.append(f"[?] Unknown ({len(health_stats['Unknown'])}): {', '.join(health_stats['Unknown'])}")
        
        if health_stats.get("Suspended"):
            output_lines.append(f"[PAUSE] Suspended ({len(health_stats['Suspended'])}): {', '.join(health_stats['Suspended'])}")
        
        output = " | ".join(output_lines)
        
        # If most apps are healthy or progressing, consider it acceptable
        healthy_count = len(health_stats.get("Healthy", [])) + len(health_stats.get("Progressing", []))
        if healthy_count >= total_apps * 0.7:  # 70% healthy/progressing
            if not health_stats.get("Missing"):  # No missing apps
                passed = True
                if health_stats.get("Degraded"):
                    severity = "WARNING"
                else:
                    severity = "INFO"
        
        return [{
                "name": name,
                "status": passed,
                "output": output,
                "severity": severity  
            }]
        
    except Exception as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to parse application health data: {str(e)}",
                "severity": "WARNING"  
            }]

def test_argocd_server_api() -> List[Dict]:
    """Check if ArgoCD Server API is responding"""
    name = "argocd_server_api_health"
    
    # Get server pod
    cmd = f"kubectl get pods -n {NAMESPACE} -l app.kubernetes.io/component=server -o jsonpath='{{.items[0].metadata.name}}'"
    pod_name, stderr, returncode = run_command(cmd)
    
    if returncode != 0 or not pod_name.strip():
        return [{
                "name": name,
                "status": False,
                "output": "ArgoCD Server pod not found",
                "severity": "CRITICAL"  
            }]
    
    pod_name = pod_name.strip()
    
    # Check API health endpoint
    api_check_cmd = f"kubectl exec -n {NAMESPACE} {pod_name} -- curl -s -k https://localhost:8080/api/v1/applications"
    stdout, stderr, returncode = run_command(api_check_cmd)
    
    if returncode == 0:
        # Check if response is valid JSON (API is working)
        try:
            json.loads(stdout)
            return [{
                "name": name,
                "status": True,
                "output": f"ArgoCD Server API is healthy and responding (pod: {pod_name})",
                "severity": "INFO"  
            }]
        except:
            return [{
                "name": name,
                "status": True,
                "output": f"ArgoCD Server is running but API response format unexpected (pod: {pod_name})",
                "severity": "WARNING"  
            }]
    else:
        return [{
                "name": name,
                "status": False,
                "output": f"ArgoCD Server API is not responding properly",
                "severity": "CRITICAL"  
            }]

def test_redis_connectivity() -> List[Dict]:
    """Check if Redis is accessible and functioning"""
    name = "redis_connectivity"
    
    # Get redis pod
    cmd = f"kubectl get pods -n {NAMESPACE} -l app.kubernetes.io/component=redis -o jsonpath='{{.items[0].metadata.name}}'"
    pod_name, stderr, returncode = run_command(cmd)
    
    if returncode != 0 or not pod_name.strip():
        return [{
                "name": name,
                "status": False,
                "output": f"ArgoCD Server API is not responding properly",
                "severity": "CRITICAL"  
            }]
    
    pod_name = pod_name.strip()
    
    # Check Redis ping
    redis_check_cmd = f"kubectl exec -n {NAMESPACE} {pod_name} -- redis-cli ping"
    stdout, stderr, returncode = run_command(redis_check_cmd)
    
    if returncode == 0 and "PONG" in stdout:
        # Check Redis memory usage
        memory_cmd = f"kubectl exec -n {NAMESPACE} {pod_name} -- redis-cli info memory | grep used_memory_human"
        mem_stdout, _, _ = run_command(memory_cmd)
        
        memory_info = ""
        if mem_stdout:
            memory_info = f", Memory: {mem_stdout.strip().split(':')[-1]}"
        
        return [{
                "name": name,
                "status": True,
                "output": f"Redis is healthy and responding (pod: {pod_name}{memory_info})",
                "severity": "INFO"  
            }]
    else:
        return [{
                "name": name,
                "status": False,
                "output": f"Redis is not responding to ping",
                "severity": "CRITICAL"  
            }]

def test_repo_server_connectivity() -> List[Dict]:
    """Check if Repository Server is functioning properly"""
    name = "repo_server_health"
    
    # Get repo server pod
    cmd = f"kubectl get pods -n {NAMESPACE} -l app.kubernetes.io/component=repo-server -o jsonpath='{{.items[0].metadata.name}}'"
    pod_name, stderr, returncode = run_command(cmd)
    
    if returncode != 0 or not pod_name.strip():
        return [{
                "name": name,
                "status": False,
                "output": "Repository Server pod not found",
                "severity": "CRITICAL"  
            }]
    
    pod_name = pod_name.strip()
    
    # Check recent logs for errors
    log_cmd = f"kubectl logs -n {NAMESPACE} {pod_name} --tail=100 2>/dev/null | grep -E 'error|Error|ERROR' | wc -l"
    error_count, _, _ = run_command(log_cmd)
    
    try:
        error_count = int(error_count.strip())
    except:
        error_count = 0
    
    # Check if repo server is processing manifests (look for successful operations)
    success_cmd = f"kubectl logs -n {NAMESPACE} {pod_name} --tail=100 2>/dev/null | grep -E 'success|Success|generated|Generated' | wc -l"
    success_count, _, _ = run_command(success_cmd)
    
    try:
        success_count = int(success_count.strip())
    except:
        success_count = 0
    
    if error_count > 20:
        return [{
                "name": name,
                "status": False,
                "output": f"Repository Server has {error_count} errors in recent logs (pod: {pod_name})",
                "severity": "WARNING"  
            }]
    elif success_count > 0:
        return [{
                "name": name,
                "status": True,
                "output": f"Repository Server is processing manifests successfully (pod: {pod_name})",
                "severity": "INFO"  
            }]
    else:
        return [{
                "name": name,
                "status": True,
                "output": f"Repository Server is running (pod: {pod_name})",
                "severity": "INFO"  
            }]

def test_application_controller() -> List[Dict]:
    """Check if Application Controller is functioning properly"""
    name = "application_controller_health"
    
    # Get application controller pod
    cmd = f"kubectl get pods -n {NAMESPACE} -l app.kubernetes.io/component=application-controller -o jsonpath='{{.items[0].metadata.name}}'"
    pod_name, stderr, returncode = run_command(cmd)
    
    if returncode != 0 or not pod_name.strip():
        return [{
                "name": name,
                "status": False,
                "output": "Application Controller pod not found",
                "severity": "CRITICAL"  
            }]
    
    pod_name = pod_name.strip()
    
    # Check for reconciliation errors
    error_cmd = f"kubectl logs -n {NAMESPACE} {pod_name} --tail=200 2>/dev/null | grep -E 'Failed to reconcile|reconciliation error|error syncing' | wc -l"
    error_count, _, _ = run_command(error_cmd)
    
    try:
        error_count = int(error_count.strip())
    except:
        error_count = 0
    
    # Check for successful reconciliations
    success_cmd = f"kubectl logs -n {NAMESPACE} {pod_name} --tail=200 2>/dev/null | grep -E 'Reconciliation completed|successfully synced|Synced application' | wc -l"
    success_count, _, _ = run_command(success_cmd)
    
    try:
        success_count = int(success_count.strip())
    except:
        success_count = 0
    
    if error_count > 50:
        return [{
                "name": name,
                "status": False,
                "output": f"Application Controller has {error_count} reconciliation errors in recent logs",
                "severity": "CRITICAL"  
            }]
    elif error_count > 10:
        return [{
                "name": name,
                "status": True,
                "output": f"Application Controller is running with {error_count} errors in recent logs",
                "severity": "WARNING"  
            }]
    else:
        return [{
                "name": name,
                "status": True,
                "output": f"Application Controller is healthy, {success_count} successful operations in recent logs",
                "severity": "INFO"  
            }]

def test_failed_applications() -> List[Dict]:
    """Analyze failed or degraded applications for root causes"""
    name = "failed_applications_analysis"
    
    cmd = f"kubectl get Application -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to get applications: {stderr}",
                "severity": "WARNING"  
            }]
    
    try:
        apps_data = json.loads(stdout)
        problematic_apps = []
        
        for app in apps_data.get("items", []):
            app_name = app["metadata"]["name"]
            health_status = app.get("status", {}).get("health", {}).get("status", "Unknown")
            sync_status = app.get("status", {}).get("sync", {}).get("status", "Unknown")
            
            if health_status in ["Degraded", "Missing"] or sync_status == "OutOfSync":
                # Get more details about the problem
                conditions = app.get("status", {}).get("conditions", [])
                operation_state = app.get("status", {}).get("operationState", {})
                
                problem_details = {
                    "name": app_name,
                    "health": health_status,
                    "sync": sync_status,
                    "message": ""
                }
                
                # Check for error messages
                if operation_state.get("message"):
                    problem_details["message"] = operation_state["message"][:100]  # First 100 chars
                elif conditions:
                    for condition in conditions:
                        if condition.get("message"):
                            problem_details["message"] = condition["message"][:100]
                            break
                
                problematic_apps.append(problem_details)
        
        if not problematic_apps:
            return [{
                "name": name,
                "status": True,
                "output": "No failed or degraded applications found",
                "severity": "INFO"  
            }]
        else:
            # Format output
            output_lines = [f"Found {len(problematic_apps)} problematic applications:"]
            for app in problematic_apps[:5]:  # Show first 5
                msg = f" - {app['name']}: Health={app['health']}, Sync={app['sync']}"
                if app['message']:
                    msg += f", Error: {app['message']}"
                output_lines.append(msg)
            
            if len(problematic_apps) > 5:
                output_lines.append(f"... and {len(problematic_apps) - 5} more")
            
            severity = "CRITICAL" if any(a['health'] == "Missing" for a in problematic_apps) else "WARNING"
            
            return [{
                "name": name,
                "status": False,
                "output": "\n".join(output_lines),
                "severity": severity  
            }]
            
    except Exception as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to analyze application failures: {str(e)}",
                "severity": "WARNING"  
            }]

def test_argocd_certificates() -> List[Dict]:
    """Check ArgoCD TLS certificates and secrets"""
    name = "certificates_health"
    
    # Check for ArgoCD server TLS secret
    cmd = f"kubectl get secret -n {NAMESPACE} argocd-server-tls -o json 2>/dev/null"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        # Try alternative secret names
        alt_cmd = f"kubectl get secret -n {NAMESPACE} -l app.kubernetes.io/component=server | grep tls"
        alt_stdout, _, alt_returncode = run_command(alt_cmd)
        
        if alt_returncode != 0:
            return [{
                "name": name,
                "status": True,
                "output": "No TLS certificates configured (running in HTTP mode)",
                "severity": "INFO"  
            }]
    
    try:
        if stdout:
            secret_data = json.loads(stdout)
            # Check if certificate data exists
            if "data" in secret_data and "tls.crt" in secret_data["data"]:
                return [{
                    "name": name,
                    "status": True,
                    "output": "TLS certificates are configured for ArgoCD Server",
                    "severity": "INFO"  
                }]
            else:
                return [{
                    "name": name,
                    "status": False,
                    "output": "TLS secret exists but certificate data is missing",
                    "severity": "WARNING"  
                }]
        else:
            return [{
                    "name": name,
                    "status": True,
                    "output": "ArgoCD is running without TLS (HTTP mode)",
                    "severity": "INFO"  
                }]
            
    except Exception as e:
        return [{
                "name": name,
                "status": True,
                "output": f"Could not verify certificate status: {str(e)}",
                "severity": "INFO"  
            }]

def test_argocd_rbac() -> List[Dict]:
    """Check ArgoCD RBAC and ServiceAccount configuration"""
    name = "rbac_configuration"
    
    # Check for ArgoCD service accounts
    cmd = f"kubectl get serviceaccount -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to get service accounts: {stderr}",
                "severity": "WARNING"  
            }]
    
    try:
        sa_data = json.loads(stdout)
        argocd_sas = []
        
        for sa in sa_data.get("items", []):
            sa_name = sa["metadata"]["name"]
            if "argocd" in sa_name.lower():
                argocd_sas.append(sa_name)
        
        if not argocd_sas:
            return [{
                "name": name,
                "status": False,
                "output": "No ArgoCD service accounts found",
                "severity": "CRITICAL"  
            }]
        
        # Check for cluster role bindings
        crb_cmd = f"kubectl get clusterrolebinding -o json | grep -c '{NAMESPACE}'"
        crb_count, _, _ = run_command(crb_cmd)
        
        try:
            crb_count = int(crb_count.strip())
        except:
            crb_count = 0
        
        return [{
                "name": name,
                "status": True,
                "output": f"Found {len(argocd_sas)} ArgoCD service accounts and {crb_count} cluster role bindings",
                "severity": "INFO"  
            }]
        
    except Exception as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to check RBAC configuration: {str(e)}",
                "severity": "WARNING"  
            }]

