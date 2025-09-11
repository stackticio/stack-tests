#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cert-Manager Health Check Script
Tests cert-manager components, certificates, issuers, and certificate requests
Returns results in JSON format with no external dependencies
"""

import subprocess
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import re
from typing import Dict, List
import os

NAMESPACE = "cert-manager"
TEST_RESULTS = []
        
def run_command(command: str, env: Dict = None, timeout: int = 10) -> tuple:
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
        # Return as tuple to match original usage
        return (completed.stdout.strip(), completed.stderr.strip(), completed.returncode)
    except subprocess.TimeoutExpired:
        return ("", "Timeout", 124)

def test_certmanager_pods() -> List[Dict]:
    """Check if all cert-manager components are running"""
    name = "certmanager_pods_health"
    
    cmd = f"kubectl get pods -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to get pods: {stderr}",
            "severity": "CRITICAL" 
        }]
    try:
        pods_data = json.loads(stdout)
        component_status = {}
        unhealthy_pods = []
        
        # Required components
        required_components = ["controller", "webhook", "cainjector"]
        
        for pod in pods_data.get("items", []):
            pod_name = pod["metadata"]["name"]
            pod_status = pod["status"]["phase"]
            
            # Skip completed jobs
            if "startupapicheck" in pod_name.lower():
                continue
            
            # Get component from labels
            labels = pod["metadata"].get("labels", {})
            component = labels.get("app.kubernetes.io/component", "unknown")
            
            # Check if all containers are ready
            ready = all(
                container.get("ready", False) 
                for container in pod["status"].get("containerStatuses", [])
            )
            
            # Check restart count
            restart_count = sum(
                container.get("restartCount", 0)
                for container in pod["status"].get("containerStatuses", [])
            )
            
            component_status[component] = {
                "pod": pod_name,
                "status": pod_status,
                "ready": ready,
                "restarts": restart_count
            }
            
            if pod_status != "Running" or not ready:
                unhealthy_pods.append(f"{pod_name} (Component: {component}, Status: {pod_status})")
            elif restart_count > 5:
                unhealthy_pods.append(f"{pod_name} (Component: {component}, Restarts: {restart_count})")
        
        # Check for missing components
        missing_components = []
        for comp in required_components:
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
        
        # Build status summary
        status_summary = []
        for comp, status in component_status.items():
            status_summary.append(f"{comp}: OK (restarts: {status['restarts']})")
        
        return [{
                "name": name,
                "status": True,
                "output": f"All cert-manager components healthy: {', '.join(status_summary)}",
                "severity": "INFO" 
            }]
        
    except json.JSONDecodeError as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to parse pod data: {str(e)}",
                "severity": "CRITICAL" 
            }]

def test_webhook_service() -> List[Dict]:
    """Check if cert-manager webhook service is configured and accessible"""
    name = "webhook_service_health"
    
    cmd = f"kubectl get service cert-manager-webhook -n {NAMESPACE} -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": False,
                "output": "Webhook service not found",
                "severity": "CRITICAL" 
            }]
    
    try:
        service_data = json.loads(stdout)
        ports = service_data["spec"].get("ports", [])
        
        # Check if webhook port (443) is configured
        webhook_port = None
        for port in ports:
            if port.get("port") == 443:
                webhook_port = port
                break
        
        if not webhook_port:
            return [{
                "name": name,
                "status": False,
                "output": "Webhook port 443 not configured",
                "severity": "CRITICAL" 
            }]
        
        # Check endpoints
        endpoints_cmd = f"kubectl get endpoints cert-manager-webhook -n {NAMESPACE} -o json"
        ep_stdout, _, ep_returncode = run_command(endpoints_cmd)
        
        if ep_returncode == 0:
            ep_data = json.loads(ep_stdout)
            subsets = ep_data.get("subsets", [])
            if not subsets or not subsets[0].get("addresses"):
                return [{
                    "name": name,
                    "status": False,
                    "output": "Webhook service has no endpoints",
                    "severity": "CRITICAL" 
                }]
        
        return [{
            "name": name,
            "status": True,
            "output": "Webhook service is configured and has endpoints on port 443",
            "severity": "INFO" 
        }]
        
    except Exception as e:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to check webhook service: {str(e)}",
            "severity": "WARNING" 
        }]

def test_cluster_issuers() -> List[Dict]:
    """Check ClusterIssuers configuration and readiness"""
    name = "cluster_issuers_health"
    
    cmd = "kubectl get clusterissuer -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        # No ClusterIssuers might be OK if using namespace issuers
        return [{
            "name": name,
            "status": True,
            "output": "No ClusterIssuers found (may be using namespace-scoped Issuers)",
            "severity": "INFO" 
        }]
    
    try:
        issuers_data = json.loads(stdout)
        issuers_status = {}
        failed_issuers = []
        
        for issuer in issuers_data.get("items", []):
            issuer_name = issuer["metadata"]["name"]
            issuer_type = issuer["spec"].get("acme", {}) and "ACME" or \
                            issuer["spec"].get("ca", {}) and "CA" or \
                            issuer["spec"].get("selfSigned", {}) and "SelfSigned" or \
                            issuer["spec"].get("vault", {}) and "Vault" or "Unknown"
            
            # Check status conditions
            conditions = issuer.get("status", {}).get("conditions", [])
            ready = False
            error_msg = ""
            
            for condition in conditions:
                if condition.get("type") == "Ready":
                    ready = condition.get("status") == "True"
                    if not ready:
                        error_msg = condition.get("message", "Unknown error")
                    break
            
            issuers_status[issuer_name] = {
                "type": issuer_type,
                "ready": ready,
                "error": error_msg
            }
            
            if not ready:
                failed_issuers.append(f"{issuer_name} ({issuer_type}): {error_msg[:50]}")
        
        if not issuers_data.get("items"):
            return [{
                "name": name,
                "status": True,
                "output": "No ClusterIssuers configured",
                "severity": "INFO" 
            }]
        
        if failed_issuers:
            return [{
                "name": name,
                "status": False,
                "output": f"Failed ClusterIssuers: {', '.join(failed_issuers)}",
                "severity": "WARNING" 
            }]
        
        # Build summary
        issuer_summary = [f"{name} ({info['type']})" for name, info in issuers_status.items() if info['ready']]
        
        return [{
            "name": name,
            "status": True,
            "output": f"All {len(issuer_summary)} ClusterIssuers ready: {', '.join(issuer_summary)}",
            "severity": "INFO" 
        }]
        
    except Exception as e:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to check ClusterIssuers: {str(e)}",
            "severity": "WARNING" 
        }]

def test_namespace_issuers() -> List[Dict]:
    """Check namespace-scoped Issuers across all namespaces"""
    name = "namespace_issuers_health"
    
    cmd = "kubectl get issuer --all-namespaces -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": True,
            "output": "No namespace Issuers found",
            "severity": "INFO" 
        }]
    
    try:
        issuers_data = json.loads(stdout)
        issuers_by_namespace = defaultdict(list)
        failed_issuers = []
        
        for issuer in issuers_data.get("items", []):
            issuer_name = issuer["metadata"]["name"]
            issuer_namespace = issuer["metadata"]["namespace"]
            
            # Check readiness
            conditions = issuer.get("status", {}).get("conditions", [])
            ready = False
            error_msg = ""
            
            for condition in conditions:
                if condition.get("type") == "Ready":
                    ready = condition.get("status") == "True"
                    if not ready:
                        error_msg = condition.get("message", "Unknown error")
                    break
            
            if ready:
                issuers_by_namespace[issuer_namespace].append(issuer_name)
            else:
                failed_issuers.append(f"{issuer_namespace}/{issuer_name}: {error_msg[:40]}")
        
        total_issuers = len(issuers_data.get("items", []))
        
        if total_issuers == 0:
            return [{
                "name": name,
                "status": True,
                "output": "No namespace Issuers configured",
                "severity": "INFO" 
            }]
        
        output = f"Found {total_issuers} Issuers across {len(issuers_by_namespace)} namespaces"
        
        if failed_issuers:
            output += f" | Failed: {', '.join(failed_issuers[:3])}"
            severity = "WARNING"
            passed = False
        else:
            severity = "INFO"
            passed = True
        
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
            "output": f"Failed to check namespace Issuers: {str(e)}",
            "severity": "WARNING" 
        }]

def test_certificates() -> List[Dict]:
    """Check all certificates for readiness and expiration"""
    name = "certificates_health"
    
    cmd = "kubectl get certificate --all-namespaces -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": True,
            "output": "No certificates found",
            "severity": "INFO" 
        }]
    
    try:
        certs_data = json.loads(stdout)
        cert_stats = {
            "ready": [],
            "not_ready": [],
            "expiring_soon": [],
            "expired": []
        }
        
        for cert in certs_data.get("items", []):
            cert_name = cert["metadata"]["name"]
            cert_namespace = cert["metadata"]["namespace"]
            full_name = f"{cert_namespace}/{cert_name}"
            
            # Check readiness
            conditions = cert.get("status", {}).get("conditions", [])
            ready = False
            error_msg = ""
            
            for condition in conditions:
                if condition.get("type") == "Ready":
                    ready = condition.get("status") == "True"
                    if not ready:
                        error_msg = condition.get("message", "Unknown error")
                    break
            
            # Check expiration
            not_after = cert.get("status", {}).get("notAfter")
            renewal_time = cert.get("status", {}).get("renewalTime")
            
            if not_after:
                # Parse expiration date (format: 2024-01-01T00:00:00Z)
                try:
                    expiry_date = datetime.strptime(not_after[:19], "%Y-%m-%dT%H:%M:%S")
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        cert_stats["expired"].append(f"{full_name} (expired {-days_until_expiry} days ago)")
                    elif days_until_expiry < 30:
                        cert_stats["expiring_soon"].append(f"{full_name} (expires in {days_until_expiry} days)")
                except:
                    pass
            
            if ready:
                cert_stats["ready"].append(full_name)
            else:
                cert_stats["not_ready"].append(f"{full_name}: {error_msg[:40]}")
        
        total_certs = len(certs_data.get("items", []))
        
        if total_certs == 0:
            return [{
                "name": name,
                "status": True,
                "output": "No certificates configured",
                "severity": "INFO" 
            }]
        
        # Build output
        output_parts = [f"Total: {total_certs} certificates"]
        severity = "INFO"
        passed = True
        
        if cert_stats["ready"]:
            output_parts.append(f"Ready: {len(cert_stats['ready'])}")
        
        if cert_stats["not_ready"]:
            output_parts.append(f"Not Ready: {len(cert_stats['not_ready'])} - {', '.join(cert_stats['not_ready'][:2])}")
            severity = "WARNING"
            passed = False
        
        if cert_stats["expired"]:
            output_parts.append(f"EXPIRED: {', '.join(cert_stats['expired'])}")
            severity = "CRITICAL"
            passed = False
        
        if cert_stats["expiring_soon"]:
            output_parts.append(f"Expiring Soon: {', '.join(cert_stats['expiring_soon'][:2])}")
            if severity != "CRITICAL":
                severity = "WARNING"
        
        return [{
            "name": name,
            "status": passed,
            "output": " | ".join(output_parts),
            "severity": severity 
        }]
        
    except Exception as e:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to check certificates: {str(e)}",
            "severity": "WARNING" 
        }]

def test_certificate_requests() -> List[Dict]:
    """Check for pending or failed certificate requests"""
    name = "certificate_requests_health"
    
    cmd = "kubectl get certificaterequest --all-namespaces -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": True,
            "output": "No certificate requests found",
            "severity": "INFO" 
        }]
    
    try:
        requests_data = json.loads(stdout)
        request_stats = {
            "approved": 0,
            "denied": 0,
            "pending": [],
            "failed": []
        }
        
        for req in requests_data.get("items", []):
            req_name = req["metadata"]["name"]
            req_namespace = req["metadata"]["namespace"]
            full_name = f"{req_namespace}/{req_name}"
            
            # Check conditions
            conditions = req.get("status", {}).get("conditions", [])
            
            approved = False
            denied = False
            ready = False
            failed_msg = ""
            
            for condition in conditions:
                cond_type = condition.get("type")
                cond_status = condition.get("status")
                
                if cond_type == "Approved" and cond_status == "True":
                    approved = True
                elif cond_type == "Denied" and cond_status == "True":
                    denied = True
                    failed_msg = condition.get("message", "")
                elif cond_type == "Ready" and cond_status == "True":
                    ready = True
                elif cond_type == "Failed" and cond_status == "True":
                    failed_msg = condition.get("message", "")
            
            if approved and ready:
                request_stats["approved"] += 1
            elif denied:
                request_stats["denied"] += 1
                request_stats["failed"].append(f"{full_name}: {failed_msg[:40]}")
            elif failed_msg:
                request_stats["failed"].append(f"{full_name}: {failed_msg[:40]}")
            elif not approved:
                # Check age
                creation_time = req["metadata"]["creationTimestamp"]
                try:
                    created = datetime.strptime(creation_time[:19], "%Y-%m-%dT%H:%M:%S")
                    age_minutes = (datetime.now() - created).total_seconds() / 60
                    if age_minutes > 5:  # Pending for more than 5 minutes
                        request_stats["pending"].append(f"{full_name} (pending {int(age_minutes)} min)")
                except:
                    request_stats["pending"].append(full_name)
        
        total_requests = len(requests_data.get("items", []))
        
        if total_requests == 0:
            return [{
                "name": name,
                "status": True,
                "output": "No certificate requests found",
                "severity": "INFO" 
            }]
        
        # Build output
        output_parts = [f"Total: {total_requests} requests"]
        severity = "INFO"
        passed = True
        
        if request_stats["approved"] > 0:
            output_parts.append(f"Approved: {request_stats['approved']}")
        
        if request_stats["pending"]:
            output_parts.append(f"Pending: {', '.join(request_stats['pending'][:3])}")
            severity = "WARNING"
            passed = False
        
        if request_stats["failed"]:
            output_parts.append(f"Failed: {', '.join(request_stats['failed'][:3])}")
            severity = "CRITICAL"
            passed = False
        
        if request_stats["denied"] > 0:
            output_parts.append(f"Denied: {request_stats['denied']}")
            severity = "WARNING"
            passed = False
        
        return [{
                "name": name,
                "status": passed,
                "output": " | ".join(output_parts),
                "severity": severity
            }]
        
    except Exception as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to check certificate requests: {str(e)}",
                "severity": "WARNING"
            }]

def test_acme_orders() -> List[Dict]:
    """Check ACME orders status for Let's Encrypt certificates"""
    name = "acme_orders_health"
    
    cmd = "kubectl get order --all-namespaces -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": True,
                "output": "No ACME orders found (not using ACME issuers)",
                "severity": "INFO"
            }]
    
    try:
        orders_data = json.loads(stdout)
        order_stats = {
            "valid": 0,
            "pending": [],
            "failed": []
        }
        
        for order in orders_data.get("items", []):
            order_name = order["metadata"]["name"]
            order_namespace = order["metadata"]["namespace"]
            full_name = f"{order_namespace}/{order_name}"
            
            state = order.get("status", {}).get("state", "unknown")
            
            if state == "valid":
                order_stats["valid"] += 1
            elif state == "pending":
                # Check age
                creation_time = order["metadata"]["creationTimestamp"]
                try:
                    created = datetime.strptime(creation_time[:19], "%Y-%m-%dT%H:%M:%S")
                    age_minutes = (datetime.now() - created).total_seconds() / 60
                    order_stats["pending"].append(f"{full_name} ({int(age_minutes)} min)")
                except:
                    order_stats["pending"].append(full_name)
            elif state in ["errored", "failed", "invalid"]:
                reason = order.get("status", {}).get("reason", "Unknown")
                order_stats["failed"].append(f"{full_name}: {reason[:30]}")
        
        total_orders = len(orders_data.get("items", []))
        
        if total_orders == 0:
            return [{
                "name": name,
                "status": True,
                "output": "No ACME orders (not using Let's Encrypt)",
                "severity": "INFO"
            }]
        
        # Build output
        output_parts = [f"Total: {total_orders} ACME orders"]
        severity = "INFO"
        passed = True
        
        if order_stats["valid"] > 0:
            output_parts.append(f"Valid: {order_stats['valid']}")
        
        if order_stats["pending"]:
            output_parts.append(f"Pending: {', '.join(order_stats['pending'][:3])}")
            if any('min' in p and int(p.split('(')[1].split()[0]) > 10 for p in order_stats["pending"]):
                severity = "WARNING"
        
        if order_stats["failed"]:
            output_parts.append(f"Failed: {', '.join(order_stats['failed'][:3])}")
            severity = "CRITICAL"
            passed = False
        
        return [{
                "name": name,
                "status": passed,
                "output": " | ".join(output_parts),
                "severity": severity
            }]
    
        
    except Exception as e:
        return [{
                "name": name,
                "status": False,
                "output": f"Failed to check ACME orders: {str(e)}",
                "severity": "WARNING"
            }]

def test_webhook_tls() -> List[Dict]:
    """Check cert-manager webhook TLS certificate validity"""
    name = "webhook_tls_certificate"
    
    # Check for webhook TLS secret
    cmd = f"kubectl get secret cert-manager-webhook-ca -n {NAMESPACE} -o json 2>/dev/null"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        # Try alternative secret name
        cmd = f"kubectl get secret -n {NAMESPACE} -l app.kubernetes.io/component=webhook -o json"
        stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
                "name": name,
                "status": False,
                "output": "Webhook TLS secret not found",
                "severity": "CRITICAL"
            }]
    try:
        secret_data = json.loads(stdout)
        
        # If it's a list of secrets, find the TLS one
        if "items" in secret_data:
            for secret in secret_data.get("items", []):
                if secret.get("type") == "kubernetes.io/tls" or "tls.crt" in secret.get("data", {}):
                    secret_data = secret
                    break
        
        if "tls.crt" in secret_data.get("data", {}):
            return [{
                "name": name,
                "status": True,
                "output": "Webhook TLS certificate is configured",
                "severity": "INFO"
            }]
        else:
            return [{
                "name": name,
                "status": False,
                "output": "Webhook TLS certificate data not found in secret",
                "severity": "WARNING"
            }]
            
    except Exception as e:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to check webhook TLS: {str(e)}",
            "severity": "WARNING"
        }]

def test_certmanager_logs() -> List[Dict]:
    """Check cert-manager controller logs for errors and warnings"""
    name = "certmanager_logs_analysis"
    
    # Get controller pod
    cmd = f"kubectl get pods -n {NAMESPACE} -l app.kubernetes.io/component=controller -o jsonpath='{{.items[0].metadata.name}}'"
    pod_name, _, returncode = run_command(cmd)
    
    if returncode != 0 or not pod_name.strip():
        return [{
            "name": name,
            "status": False,
            "output": "Could not find cert-manager controller pod",
            "severity": "WARNING"
        }]
    
    pod_name = pod_name.strip()
    
    # Get recent logs
    logs_cmd = f"kubectl logs -n {NAMESPACE} {pod_name} --tail=500 2>/dev/null"
    logs_stdout, _, logs_returncode = run_command(logs_cmd)
    
    if logs_returncode != 0:
        return [{
            "name": name,
            "status": False,
            "output": "Failed to retrieve controller logs",
            "severity": "WARNING"
        }]
    
    # Analyze logs
    log_stats = {
        "errors": 0,
        "warnings": 0,
        "acme_errors": [],
        "dns_errors": [],
        "issuer_errors": [],
        "certificate_errors": []
    }
    
    for line in logs_stdout.split('\n')[-200:]:  # Analyze last 200 lines
        line_lower = line.lower()
        
        if 'error' in line_lower:
            log_stats["errors"] += 1
            
            if 'acme' in line_lower or 'letsencrypt' in line_lower:
                log_stats["acme_errors"].append(line[:100])
            elif 'dns' in line_lower or 'route53' in line_lower or 'cloudflare' in line_lower:
                log_stats["dns_errors"].append(line[:100])
            elif 'issuer' in line_lower:
                log_stats["issuer_errors"].append(line[:100])
            elif 'certificate' in line_lower:
                log_stats["certificate_errors"].append(line[:100])
                
        elif 'warn' in line_lower:
            log_stats["warnings"] += 1
    
    # Build output
    issues = []
    severity = "INFO"
    passed = True
    
    if log_stats["errors"] > 50:
        issues.append(f"{log_stats['errors']} errors in recent logs")
        severity = "CRITICAL"
        passed = False
    elif log_stats["errors"] > 10:
        issues.append(f"{log_stats['errors']} errors in recent logs")
        severity = "WARNING"
        passed = False
    
    if log_stats["acme_errors"]:
        issues.append(f"ACME/Let's Encrypt errors: {len(log_stats['acme_errors'])}")
    
    if log_stats["dns_errors"]:
        issues.append(f"DNS challenge errors: {len(log_stats['dns_errors'])}")
    
    if log_stats["issuer_errors"]:
        issues.append(f"Issuer errors: {len(log_stats['issuer_errors'])}")
    
    if log_stats["certificate_errors"]:
        issues.append(f"Certificate errors: {len(log_stats['certificate_errors'])}")
    
    if issues:
        return [{
            "name": name,
            "status": passed,
            "output": f"Log issues found: {', '.join(issues)}",
            "severity": severity
        }]
    else:
        return [{
            "name": name,
            "status": True,
            "output": f"Logs are clean ({log_stats['warnings']} warnings, {log_stats['errors']} errors)",
            "severity": "INFO"
        }]

def test_validating_webhook() -> List[Dict]:
    """Check cert-manager ValidatingWebhookConfiguration"""
    name = "validating_webhook_config"
    
    cmd = "kubectl get validatingwebhookconfiguration cert-manager-webhook -o json"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": False,
            "output": "ValidatingWebhookConfiguration not found",
            "severity": "CRITICAL"
        }]
    
    try:
        webhook_data = json.loads(stdout)
        webhooks = webhook_data.get("webhooks", [])
        
        if not webhooks:
            return [{
                "name": name,
                "status": False,
                "output": "No webhooks configured in ValidatingWebhookConfiguration",
                "severity": "CRITICAL"
            }]
        
        # Check each webhook
        webhook_info = []
        for webhook in webhooks:
            webhook_name = webhook.get("name", "unknown")
            rules = webhook.get("rules", [])
            webhook_info.append(f"{webhook_name} ({len(rules)} rules)")
        
        return [{
            "name": name,
            "status": True,  # FIX: Changed from False to True
            "output": f"ValidatingWebhook configured: {', '.join(webhook_info)}",
            "severity": "INFO"
        }]
        
    except Exception as e:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to check ValidatingWebhookConfiguration: {str(e)}",
            "severity": "WARNING"
        }]

def test_api_resources() -> List[Dict]:
    """Check if cert-manager Custom Resource Definitions are installed"""
    name = "api_resources"
    
    # Check for cert-manager API resources
    cmd = "kubectl api-resources | grep cert-manager | wc -l"
    stdout, stderr, returncode = run_command(cmd)
    
    if returncode != 0:
        return [{
            "name": name,
            "status": False,
            "output": "Failed to check API resources",
            "severity": "WARNING"
        }]
    
    try:
        resource_count = int(stdout.strip())
        
        if resource_count == 0:
            return [{
                "name": name,
                "status": False,
                "output": "No cert-manager API resources found - CRDs may not be installed",
                "severity": "CRITICAL"
            }]
        
        # Check specific CRDs
        expected_crds = [
            "certificates.cert-manager.io",
            "certificaterequests.cert-manager.io",
            "issuers.cert-manager.io",
            "clusterissuers.cert-manager.io",
            "orders.acme.cert-manager.io",
            "challenges.acme.cert-manager.io"
        ]
        
        found_crds = []
        for crd in expected_crds:
            check_cmd = f"kubectl get crd {crd} 2>/dev/null | grep -c {crd}"
            check_stdout, _, check_returncode = run_command(check_cmd)
            if check_returncode == 0 and check_stdout.strip() == "1":
                found_crds.append(crd.split('.')[0])
        
        if len(found_crds) < 4:  # At least 4 core CRDs should be present
            return [{
                "name": name,
                "status": False,
                "output": f"Missing core CRDs. Found: {', '.join(found_crds)}",
                "severity": "CRITICAL"
            }]
        
        return [{
            "name": name,
            "status": True,
            "output": f"All cert-manager CRDs installed: {', '.join(found_crds)}",
            "severity": "INFO"
        }]
        
    except Exception as e:
        return [{
            "name": name,
            "status": False,
            "output": f"Failed to check CRDs: {str(e)}",
            "severity": "WARNING"
        }]
