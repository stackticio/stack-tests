#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_argocd_dynamic.py - Dynamic ArgoCD tester that discovers and tests all applications
Tests ArgoCD server health, application sync status, and resource health

ENV VARS:
  ARGOCD_NS (default: argocd)
  ARGOCD_SERVER (default: argo-cd-argocd-server)
  ARGOCD_PORT (default: 80)
  ARGOCD_USERNAME (default: admin)
  ARGOCD_PASSWORD (default: fetched from secret)
  ARGOCD_INSECURE (default: true)

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import sys
import json
import subprocess
import base64
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

# ------------------------------------------------------------
# Utilities & configuration
# ------------------------------------------------------------

def run_command(command: str, env: Optional[Dict[str, str]] = None, timeout: int = 30) -> Dict[str, Any]:
    """Run a shell command and capture stdout/stderr/exit code."""
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


def get_config() -> Dict[str, str]:
    """Get configuration from environment or defaults"""
    # Try to get admin password from secret
    password_cmd = "kubectl get secret argocd-secret -n argocd -o jsonpath='{.data.admin\\.password}' 2>/dev/null"
    result = run_command(password_cmd)
    
    admin_password = ""
    if ok(result) and result["stdout"]:
        try:
            admin_password = base64.b64decode(result["stdout"]).decode('utf-8')
        except:
            admin_password = os.getenv("ARGOCD_PASSWORD", "admin")
    
    return {
        "namespace": os.getenv("ARGOCD_NS", "argocd"),
        "server": os.getenv("ARGOCD_SERVER", "argo-cd-argocd-server"),
        "port": os.getenv("ARGOCD_PORT", "80"),
        "username": os.getenv("ARGOCD_USERNAME", "admin"),
        "password": admin_password or os.getenv("ARGOCD_PASSWORD", "admin"),
        "insecure": os.getenv("ARGOCD_INSECURE", "true").lower() == "true"
    }


def kubectl_get_json(resource: str, namespace: str = None, name: str = None) -> Dict[str, Any]:
    """Get Kubernetes resource as JSON"""
    ns_flag = f"-n {namespace}" if namespace else "-A"
    resource_name = name if name else ""
    
    cmd = f"kubectl get {resource} {resource_name} {ns_flag} -o json 2>/dev/null"
    result = run_command(cmd)
    
    if ok(result) and result["stdout"]:
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {}
    return {}


# ------------------------------------------------------------
# Result helper
# ------------------------------------------------------------

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }


# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def check_argocd_deployment() -> List[Dict[str, Any]]:
    """Test ArgoCD deployment components"""
    config = get_config()
    tests: List[Dict[str, Any]] = []
    
    # Core ArgoCD components
    components = [
        ("application-controller", "Controls application lifecycle", True),
        ("server", "API and UI server", True),
        ("repo-server", "Repository server", True),
        ("redis", "Cache and session storage", True),
        ("applicationset-controller", "ApplicationSet controller", False),
        ("image-updater", "Image updater", False)
    ]
    
    for component, description, critical in components:
        deployment_name = f"argo-cd-argocd-{component}"
        deployment = kubectl_get_json("deployment", config["namespace"], deployment_name)
        
        if deployment and "spec" in deployment:
            spec_replicas = deployment["spec"].get("replicas", 0)
            ready_replicas = deployment.get("status", {}).get("readyReplicas", 0)
            status = ready_replicas == spec_replicas and spec_replicas > 0
            output = f"{'✓' if status else '✗'} {ready_replicas}/{spec_replicas} replicas ready"
            severity = "critical" if (critical and not status) else "warning" if not status else "info"
        else:
            status = False
            output = "✗ Deployment not found"
            severity = "critical" if critical else "warning"
        
        tests.append(create_test_result(
            f"deployment_{component}",
            f"ArgoCD {description}",
            status,
            output,
            severity
        ))
    
    return tests


def check_argocd_services() -> List[Dict[str, Any]]:
    """Test ArgoCD services availability"""
    config = get_config()
    tests: List[Dict[str, Any]] = []
    
    services = kubectl_get_json("service", config["namespace"])
    
    if services and "items" in services:
        for svc in services["items"]:
            svc_name = svc["metadata"]["name"]
            svc_type = svc["spec"].get("type", "Unknown")
            ports = svc["spec"].get("ports", [])
            
            port_info = ", ".join([f"{p.get('port')}:{p.get('targetPort', 'N/A')}" for p in ports])
            
            tests.append(create_test_result(
                f"service_{svc_name.replace('-', '_')}",
                f"Service: {svc_name}",
                True,
                f"✓ {svc_type} - Ports: {port_info}",
                "info"
            ))
    else:
        tests.append(create_test_result(
            "services_check",
            "ArgoCD services",
            False,
            "✗ No services found",
            "critical"
        ))
    
    return tests


def check_argocd_server_health() -> List[Dict[str, Any]]:
    """Test ArgoCD server health endpoint"""
    config = get_config()
    tests: List[Dict[str, Any]] = []
    
    # Try to access health endpoint through kubectl exec
    cmd = f"""kubectl exec -n {config['namespace']} deployment/argo-cd-argocd-server -- \
        curl -s -o /dev/null -w '%{{http_code}}' http://localhost:8080/healthz 2>/dev/null"""
    
    result = run_command(cmd, timeout=15)
    
    if ok(result):
        http_code = result["stdout"].strip()
        status = http_code == "200"
        output = f"{'✓' if status else '✗'} HTTP {http_code}"
        severity = "critical" if not status else "info"
    else:
        status = False
        output = "✗ Health check failed"
        severity = "critical"
    
    tests.append(create_test_result(
        "server_health",
        "ArgoCD server health endpoint",
        status,
        output,
        severity
    ))
    
    return tests


def check_applications() -> List[Dict[str, Any]]:
    """Test all ArgoCD applications"""
    tests: List[Dict[str, Any]] = []
    
    applications = kubectl_get_json("application.argoproj.io", "argocd")
    
    if not applications or "items" not in applications:
        tests.append(create_test_result(
            "application_discovery",
            "Application discovery",
            False,
            "✗ No applications found",
            "critical"
        ))
        return tests
    
    app_count = len(applications["items"])
    tests.append(create_test_result(
        "application_discovery",
        "Application discovery",
        True,
        f"✓ Found {app_count} applications",
        "info"
    ))
    
    # Test each application
    for app in applications["items"]:
        metadata = app.get("metadata", {})
        spec = app.get("spec", {})
        status = app.get("status", {})
        
        app_name = metadata.get("name", "unknown")
        sync_status = status.get("sync", {}).get("status", "Unknown")
        health_status = status.get("health", {}).get("status", "Unknown")
        operation_state = status.get("operationState", {}).get("phase", "")
        resources = status.get("resources", [])
        
        # Application sync status
        is_synced = sync_status == "Synced"
        sync_severity = "critical" if sync_status == "OutOfSync" else "warning" if sync_status == "Unknown" else "info"
        
        tests.append(create_test_result(
            f"app_{app_name}_sync",
            f"Application {app_name} sync status",
            is_synced,
            f"{'✓' if is_synced else '✗'} Sync: {sync_status}",
            sync_severity
        ))
        
        # Application health status
        is_healthy = health_status in ["Healthy", "Progressing"]
        health_severity = "critical" if health_status in ["Degraded", "Missing"] else "warning" if health_status == "Unknown" else "info"
        
        tests.append(create_test_result(
            f"app_{app_name}_health",
            f"Application {app_name} health status",
            is_healthy,
            f"{'✓' if is_healthy else '✗'} Health: {health_status}",
            health_severity
        ))
        
        # Test resources by kind
        if resources:
            resources_by_kind = defaultdict(list)
            for resource in resources:
                kind = resource.get("kind", "Unknown")
                resources_by_kind[kind].append(resource)
            
            # Only test first 3 resource kinds to avoid too many tests
            for kind, res_list in list(resources_by_kind.items())[:3]:
                healthy_count = sum(1 for r in res_list if r.get("health", {}).get("status") == "Healthy")
                total_count = len(res_list)
                
                all_healthy = healthy_count == total_count
                severity = "critical" if healthy_count == 0 else "warning" if healthy_count < total_count else "info"
                
                tests.append(create_test_result(
                    f"app_{app_name}_resources_{kind.lower()}",
                    f"{app_name} - {kind} resources",
                    all_healthy,
                    f"{'✓' if all_healthy else '⚠'} {healthy_count}/{total_count} healthy",
                    severity
                ))
    
    return tests


def check_application_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Check logs for critical applications"""
    tests: List[Dict[str, Any]] = []
    config = get_config()
    
    # Check logs for ArgoCD components
    components = ["application-controller", "server", "repo-server"]
    
    error_patterns = [
        r'level=error',
        r'level=fatal',
        r'Failed to sync',
        r'Error syncing',
        r'authentication failed',
        r'permission denied',
        r'OutOfSync',
    ]
    
    for component in components:
        deployment_name = f"argo-cd-argocd-{component}"
        
        # Get pod name
        cmd = f"kubectl get pods -n {config['namespace']} -l app.kubernetes.io/component={component} -o jsonpath='{{.items[0].metadata.name}}' 2>/dev/null"
        result = run_command(cmd, timeout=10)
        
        if not ok(result) or not result["stdout"]:
            tests.append(create_test_result(
                f"logs_{component}",
                f"Log analysis for {component}",
                False,
                f"✗ Pod not found",
                "warning"
            ))
            continue
        
        pod_name = result["stdout"]
        
        # Get logs
        log_cmd = f"kubectl logs -n {config['namespace']} {pod_name} --since={time_window_minutes}m 2>&1 | tail -200"
        log_result = run_command(log_cmd, timeout=20)
        
        errors_found: List[str] = []
        if log_result["stdout"]:
            for line in log_result["stdout"].splitlines():
                if any(re.search(pat, line, re.IGNORECASE) for pat in error_patterns):
                    errors_found.append(line[:200])
        
        if errors_found:
            tests.append(create_test_result(
                f"logs_{component}",
                f"Log analysis for {component} (last {time_window_minutes}m)",
                False,
                f"⚠ Found {len(errors_found)} error lines",
                "warning"
            ))
        else:
            tests.append(create_test_result(
                f"logs_{component}",
                f"Log analysis for {component} (last {time_window_minutes}m)",
                True,
                f"✓ No critical errors detected",
                "info"
            ))
    
    return tests


def check_argocd_cli_access() -> List[Dict[str, Any]]:
    """Test ArgoCD CLI access through stack-agent"""
    tests: List[Dict[str, Any]] = []
    config = get_config()
    
    # Test if argocd CLI is available in stack-agent
    cmd = "kubectl exec -n stack-agent deployment/stack-agent -- which argocd 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if ok(result) and result["stdout"]:
        tests.append(create_test_result(
            "argocd_cli_available",
            "ArgoCD CLI availability in stack-agent",
            True,
            f"✓ ArgoCD CLI found at {result['stdout']}",
            "info"
        ))
        
        # Try to login and list apps
        login_cmd = f"""kubectl exec -n stack-agent deployment/stack-agent -- \
            argocd login {config['server']}:{config['port']} \
            --username {config['username']} \
            --password '{config['password']}' \
            --insecure --grpc-web 2>&1"""
        
        login_result = run_command(login_cmd, timeout=15)
        
        if ok(login_result):
            tests.append(create_test_result(
                "argocd_cli_login",
                "ArgoCD CLI login test",
                True,
                f"✓ Successfully logged in",
                "info"
            ))
        else:
            tests.append(create_test_result(
                "argocd_cli_login",
                "ArgoCD CLI login test",
                False,
                f"✗ Login failed: {login_result['stderr'] or login_result['stdout']}",
                "warning"
            ))
    else:
        tests.append(create_test_result(
            "argocd_cli_available",
            "ArgoCD CLI availability in stack-agent",
            False,
            f"✗ ArgoCD CLI not found in stack-agent",
            "warning"
        ))
    
    return tests


def generate_summary(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate overall summary"""
    # Count results by status and severity
    total_tests = len(all_results)
    passed_tests = sum(1 for r in all_results if r.get("status") == True)
    failed_tests = sum(1 for r in all_results if r.get("status") == False)
    critical_issues = sum(1 for r in all_results if r.get("severity") == "critical" and not r.get("status"))
    warnings = sum(1 for r in all_results if r.get("severity") == "warning" and not r.get("status"))
    
    # Count application-specific metrics
    app_sync_tests = [r for r in all_results if "_sync" in r.get("name", "")]
    app_health_tests = [r for r in all_results if "_health" in r.get("name", "") and "server_health" not in r.get("name", "")]
    
    synced_apps = sum(1 for r in app_sync_tests if r.get("status") == True)
    total_apps = len(app_sync_tests)
    healthy_apps = sum(1 for r in app_health_tests if r.get("status") == True)
    
    status = critical_issues == 0
    severity = "critical" if critical_issues > 0 else "warning" if warnings > 0 else "info"
    
    output = (f"Tests: {passed_tests}/{total_tests} passed | "
             f"Apps: {healthy_apps}/{total_apps} healthy, {synced_apps}/{total_apps} synced | "
             f"Critical: {critical_issues} | Warnings: {warnings}")
    
    return create_test_result(
        "overall_summary",
        "Overall ArgoCD test summary",
        status,
        output,
        severity
    )


# ------------------------------------------------------------
# Main runner
# ------------------------------------------------------------

def test_argocd() -> List[Dict[str, Any]]:
    """Main function to test ArgoCD"""
    start_time = time.time()
    results: List[Dict[str, Any]] = []
    
    # 1) ArgoCD deployment
    results.extend(check_argocd_deployment())
    
    # 2) ArgoCD services
    results.extend(check_argocd_services())
    
    # 3) Server health
    results.extend(check_argocd_server_health())
    
    # 4) Applications
    results.extend(check_applications())
    
    # 5) Logs
    results.extend(check_application_logs(time_window_minutes=5))
    
    # 6) CLI access (optional)
    results.extend(check_argocd_cli_access())
    
    # 7) Generate summary
    summary = generate_summary(results)
    results.append(summary)
    
    return results


def print_results(results: List[Dict[str, Any]]):
    """Pretty print test results"""
    print("\n" + "="*80)
    print(" "*30 + "ARGOCD TEST RESULTS")
    print("="*80)
    
    # Group by severity
    by_severity = defaultdict(list)
    for r in results:
        by_severity[r.get("severity", "info")].append(r)
    
    # Print critical issues
    if by_severity["critical"]:
        print("\n❌ CRITICAL ISSUES:")
        for r in by_severity["critical"]:
            if not r.get("status"):
                print(f"  • {r['description']}: {r['output']}")
    
    # Print warnings
    if by_severity["warning"]:
        print("\n⚠️  WARNINGS:")
        for r in by_severity["warning"]:
            if not r.get("status"):
                print(f"  • {r['description']}: {r['output']}")
    
    # Print successes summary
    success_count = sum(1 for r in results if r.get("status"))
    total_count = len(results)
    print(f"\n✅ SUCCESSES: {success_count}/{total_count}")
    
    # Print overall summary
    summary = next((r for r in results if r["name"] == "overall_summary"), None)
    if summary:
        print(f"\n📈 OVERALL SUMMARY:")
        print(f"  {summary['output']}")
    
    print("="*80 + "\n")


if __name__ == "__main__":
    try:
        # Run tests
        results = test_argocd()
        
        # Output JSON (primary output)
        print(json.dumps(results, indent=2))
        
        # Pretty print to stderr for human readability
        if "--pretty" in sys.argv:
            print_results(results)
        
        # Exit with error if critical issues
        critical = sum(1 for r in results if not r.get("status") and r.get("severity") == "critical")
        sys.exit(1 if critical > 0 else 0)
        
    except KeyboardInterrupt:
        print(json.dumps([create_test_result(
            "test_interrupted",
            "Test execution",
            False,
            "Testing interrupted by user",
            "critical"
        )]))
        sys.exit(1)
    except Exception as e:
        import traceback
        print(json.dumps([create_test_result(
            "test_error",
            "Test execution",
            False,
            f"Fatal error: {str(e)}",
            "critical"
        )]))
        if "--debug" in sys.argv:
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)
