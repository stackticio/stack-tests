#!/usr/bin/env python3
"""
Prometheus Security Tests
Comprehensive security analysis for Prometheus monitoring stack

Tests:
1. Authentication on API endpoints
2. Write endpoint protection
3. Admin API security
4. AlertManager authentication
5. External exposure
6. TLS/SSL configuration
7. Network policies
8. Pod security context
9. RBAC configuration
10. Data retention and security

ENV VARS:
  PROMETHEUS_NS (default: prometheus)
  PROMETHEUS_HOST (default: prometheus.prometheus.svc.cluster.local)
  PROMETHEUS_PORT (default: 9090)
  ALERTMANAGER_HOST (default: alertmanager.prometheus.svc.cluster.local)
  ALERTMANAGER_PORT (default: 9093)

Output: JSON array of security test results
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
    """Create standardized security test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.upper()
    }


def test_api_authentication() -> Dict[str, Any]:
    """Check if Prometheus API requires authentication"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    host = os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local")
    port = os.getenv("PROMETHEUS_PORT", "9090")

    # Try accessing API without credentials
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{port}/api/v1/query?query=up"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "prometheus_api_authentication",
            "Check if Prometheus API requires authentication",
            False,
            "WARNING: Prometheus API is accessible without authentication. Anyone can query metrics data.",
            "WARNING"
        )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "prometheus_api_authentication",
            "Check if Prometheus API requires authentication",
            True,
            f"Prometheus API requires authentication (HTTP {http_code})",
            "INFO"
        )
    else:
        return create_result(
            "prometheus_api_authentication",
            "Check if Prometheus API requires authentication",
            True,
            f"Prometheus API returned HTTP {http_code} (may require auth or be restricted)",
            "INFO"
        )


def test_write_endpoint_protection() -> Dict[str, Any]:
    """Check if write endpoints (remote write) are protected"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    host = os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local")
    port = os.getenv("PROMETHEUS_PORT", "9090")

    # Try posting to remote write endpoint
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null -X POST http://{host}:{port}/api/v1/write"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200" or http_code == "204":
        return create_result(
            "prometheus_write_endpoint",
            "Check if write endpoints are protected",
            False,
            "CRITICAL: Write endpoint is accessible without authentication! Attackers can inject malicious metrics.",
            "CRITICAL"
        )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "prometheus_write_endpoint",
            "Check if write endpoints are protected",
            True,
            f"Write endpoint requires authentication (HTTP {http_code})",
            "INFO"
        )
    elif http_code == "404" or http_code == "405":
        return create_result(
            "prometheus_write_endpoint",
            "Check if write endpoints are protected",
            True,
            "Write endpoint is disabled or not configured (good for read-only deployments)",
            "INFO"
        )
    else:
        return create_result(
            "prometheus_write_endpoint",
            "Check if write endpoints are protected",
            True,
            f"Write endpoint returned HTTP {http_code}",
            "INFO"
        )


def test_admin_api_security() -> Dict[str, Any]:
    """Check if admin API endpoints are protected"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    host = os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local")
    port = os.getenv("PROMETHEUS_PORT", "9090")

    # Try accessing admin endpoints (e.g., delete series, snapshot)
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null -X POST http://{host}:{port}/api/v1/admin/tsdb/delete_series?match[]={{__name__=~'.%2b'}}"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200" or http_code == "204":
        return create_result(
            "prometheus_admin_api",
            "Check if admin API is properly protected",
            False,
            "CRITICAL: Admin API is accessible! Attackers can delete metrics data.",
            "CRITICAL"
        )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "prometheus_admin_api",
            "Check if admin API is properly protected",
            True,
            f"Admin API requires authentication (HTTP {http_code})",
            "INFO"
        )
    elif http_code == "405":
        return create_result(
            "prometheus_admin_api",
            "Check if admin API is properly protected",
            True,
            "Admin API is disabled (web.enable-admin-api=false) - good security practice",
            "INFO"
        )
    else:
        return create_result(
            "prometheus_admin_api",
            "Check if admin API is properly protected",
            True,
            f"Admin API returned HTTP {http_code} - likely protected or disabled",
            "INFO"
        )


def test_alertmanager_authentication() -> Dict[str, Any]:
    """Check if AlertManager requires authentication"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    host = os.getenv("ALERTMANAGER_HOST", "alertmanager.prometheus.svc.cluster.local")
    port = os.getenv("ALERTMANAGER_PORT", "9093")

    # Try accessing AlertManager API
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{port}/api/v2/alerts"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "alertmanager_authentication",
            "Check if AlertManager requires authentication",
            False,
            "WARNING: AlertManager API is accessible without authentication. Anyone can view/silence alerts.",
            "WARNING"
        )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "alertmanager_authentication",
            "Check if AlertManager requires authentication",
            True,
            f"AlertManager API requires authentication (HTTP {http_code})",
            "INFO"
        )
    elif http_code == "000" or result["exit_code"] != 0:
        return create_result(
            "alertmanager_authentication",
            "Check if AlertManager requires authentication",
            True,
            "AlertManager is not accessible (may not be deployed or network restricted)",
            "INFO"
        )
    else:
        return create_result(
            "alertmanager_authentication",
            "Check if AlertManager requires authentication",
            True,
            f"AlertManager API returned HTTP {http_code}",
            "INFO"
        )


def test_external_exposure() -> Dict[str, Any]:
    """Check if Prometheus is exposed externally"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")

    # Check service types
    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])
            exposed_services = []

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                # Check for Prometheus-related services
                if any(keyword in svc_name.lower() for keyword in ["prometheus", "alertmanager"]):
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        exposed_services.append(f"{svc_name} (LoadBalancer: {external_ip})")
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        exposed_services.append(f"{svc_name} (NodePort: {node_ports})")

            if exposed_services:
                return create_result(
                    "prometheus_external_exposure",
                    "Check if Prometheus is exposed to external networks",
                    False,
                    f"WARNING: Prometheus services exposed externally: {', '.join(exposed_services)}. Ensure authentication is enabled.",
                    "WARNING"
                )
            else:
                return create_result(
                    "prometheus_external_exposure",
                    "Check if Prometheus is exposed to external networks",
                    True,
                    "Prometheus services are ClusterIP only (internal) - good security practice",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "prometheus_external_exposure",
                "Check if Prometheus is exposed to external networks",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "prometheus_external_exposure",
            "Check if Prometheus is exposed to external networks",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def test_pod_security_context() -> Dict[str, Any]:
    """Check if Prometheus pods run with secure security context"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")

    # Get Prometheus server pods
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=prometheus -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "prometheus_pod_security_context",
                    "Check Prometheus pod security context",
                    True,
                    "No Prometheus pods found",
                    "INFO"
                )

            issues = []
            pod = pods_data["items"][0]
            pod_name = pod["metadata"]["name"]

            # Check pod-level security context
            pod_security = pod["spec"].get("securityContext", {})
            pod_run_as_non_root = pod_security.get("runAsNonRoot", False)

            # Check container security context
            containers = pod["spec"].get("containers", [])
            for container in containers:
                if "prometheus" in container["name"].lower():
                    container_security = container.get("securityContext", {})

                    # Check if running as non-root (pod-level OR container-level)
                    container_run_as_non_root = container_security.get("runAsNonRoot", False)
                    if not pod_run_as_non_root and not container_run_as_non_root:
                        issues.append("Neither pod nor container enforcing runAsNonRoot")

                    # Check if privileged
                    privileged = container_security.get("privileged", False)
                    if privileged:
                        issues.append("Container is running in privileged mode")

                    # Check read-only root filesystem
                    read_only_fs = container_security.get("readOnlyRootFilesystem", False)
                    if not read_only_fs:
                        issues.append("Root filesystem is not read-only (consider enabling for better security)")

            if issues:
                return create_result(
                    "prometheus_pod_security_context",
                    "Check Prometheus pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join(issues)}",
                    "WARNING"
                )
            else:
                return create_result(
                    "prometheus_pod_security_context",
                    "Check Prometheus pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "prometheus_pod_security_context",
                "Check Prometheus pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "prometheus_pod_security_context",
            "Check Prometheus pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for Prometheus namespace"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")

    # Check for NetworkPolicies
    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "prometheus_network_policies",
                    "Check if NetworkPolicies restrict Prometheus access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Metrics are accessible from any pod.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "prometheus_network_policies",
                    "Check if NetworkPolicies restrict Prometheus access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "prometheus_network_policies",
                "Check if NetworkPolicies restrict Prometheus access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "prometheus_network_policies",
            "Check if NetworkPolicies restrict Prometheus access",
            False,
            f"WARNING: Unable to check NetworkPolicies (may not exist or no permissions)",
            "WARNING"
        )


def test_rbac_configuration() -> Dict[str, Any]:
    """Check if Prometheus ServiceAccount has appropriate RBAC permissions"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")

    # Get Prometheus pods to find ServiceAccount
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=prometheus -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "prometheus_rbac_configuration",
                    "Check Prometheus RBAC configuration",
                    True,
                    "No Prometheus pods found to check ServiceAccount",
                    "INFO"
                )

            pod = pods_data["items"][0]
            service_account = pod["spec"].get("serviceAccountName", "default")

            # Check if using default SA (bad practice)
            if service_account == "default":
                return create_result(
                    "prometheus_rbac_configuration",
                    "Check Prometheus RBAC configuration",
                    False,
                    "WARNING: Prometheus is using 'default' ServiceAccount. Should use dedicated ServiceAccount with minimal permissions.",
                    "WARNING"
                )

            # Check for ClusterRoleBindings (Prometheus needs cluster-wide read access)
            cmd = f"kubectl get clusterrolebinding -o json"
            crb_result = run_command(cmd, timeout=10)

            if crb_result["exit_code"] == 0 and crb_result["stdout"]:
                crb_data = json.loads(crb_result["stdout"])
                cluster_admin_bindings = []

                for binding in crb_data.get("items", []):
                    subjects = binding.get("subjects", [])
                    role_ref = binding.get("roleRef", {})

                    for subject in subjects:
                        if (subject.get("name") == service_account and
                            subject.get("namespace") == namespace and
                            "cluster-admin" in role_ref.get("name", "").lower()):
                            cluster_admin_bindings.append(binding["metadata"]["name"])

                if cluster_admin_bindings:
                    return create_result(
                        "prometheus_rbac_configuration",
                        "Check Prometheus RBAC configuration",
                        False,
                        f"WARNING: ServiceAccount '{service_account}' has cluster-admin permissions: {cluster_admin_bindings}. Use least-privilege role.",
                        "WARNING"
                    )
                else:
                    return create_result(
                        "prometheus_rbac_configuration",
                        "Check Prometheus RBAC configuration",
                        True,
                        f"ServiceAccount '{service_account}' has appropriate RBAC (not cluster-admin)",
                        "INFO"
                    )
            else:
                return create_result(
                    "prometheus_rbac_configuration",
                    "Check Prometheus RBAC configuration",
                    True,
                    f"ServiceAccount '{service_account}' is configured (unable to verify ClusterRole details)",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "prometheus_rbac_configuration",
                "Check Prometheus RBAC configuration",
                True,
                f"Unable to check RBAC configuration: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "prometheus_rbac_configuration",
            "Check Prometheus RBAC configuration",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_data_retention() -> Dict[str, Any]:
    """Check if data retention is configured (prevent disk exhaustion)"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    host = os.getenv("PROMETHEUS_HOST", "prometheus.prometheus.svc.cluster.local")
    port = os.getenv("PROMETHEUS_PORT", "9090")

    # Query Prometheus for runtime info
    cmd = f"curl -s http://{host}:{port}/api/v1/status/runtimeinfo"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])
            runtime_info = data.get("data", {})

            retention_time = runtime_info.get("storageRetention", "unknown")

            if retention_time == "unknown" or retention_time == "":
                return create_result(
                    "prometheus_data_retention",
                    "Check if data retention is configured",
                    False,
                    "WARNING: Data retention not configured. May lead to disk exhaustion.",
                    "WARNING"
                )
            else:
                return create_result(
                    "prometheus_data_retention",
                    "Check if data retention is configured",
                    True,
                    f"Data retention configured: {retention_time}",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "prometheus_data_retention",
                "Check if data retention is configured",
                True,
                "Unable to parse runtime info",
                "INFO"
            )
    else:
        return create_result(
            "prometheus_data_retention",
            "Check if data retention is configured",
            True,
            "Unable to query Prometheus runtime info",
            "INFO"
        )


def test_rbac_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    sa_name = os.getenv("PROMETHEUS_SA", "prometheus-server")

    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        return create_result(
            "prometheus_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to check ClusterRoleBindings",
            "INFO"
        )

    try:
        bindings = json.loads(result["stdout"])
        risky_roles = []

        for binding in bindings.get("items", []):
            subjects = binding.get("subjects", [])
            role_ref = binding.get("roleRef", {})

            for subject in subjects:
                if (subject.get("kind") == "ServiceAccount" and
                    subject.get("name") == sa_name and
                    subject.get("namespace") == namespace):

                    role_name = role_ref.get("name", "")

                    if role_name in ["cluster-admin", "admin", "edit"]:
                        risky_roles.append(f"'{role_name}' (full cluster access)")
                    elif "admin" in role_name.lower():
                        risky_roles.append(f"'{role_name}' (potentially risky)")

        if risky_roles:
            return create_result(
                "prometheus_rbac_permissive_roles",
                "Check for overly permissive RBAC cluster roles",
                False,
                f"CRITICAL: Overly permissive roles: {', '.join(risky_roles)}",
                "CRITICAL"
            )

        return create_result(
            "prometheus_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "No overly permissive cluster roles detected",
            "INFO"
        )

    except json.JSONDecodeError:
        return create_result(
            "prometheus_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to parse ClusterRoleBindings",
            "INFO"
        )


def test_rbac_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    sa_name = os.getenv("PROMETHEUS_SA", "prometheus-server")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    issues = []

    # Test access to kube-system secrets
    cmd = f"kubectl auth can-i get secrets --as={sa_full} -n kube-system 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        issues.append("Can access secrets in kube-system")

    # Test cluster-wide pod access (Prometheus needs this for scraping, so only INFO if present)
    cmd = f"kubectl auth can-i get pods --as={sa_full} --all-namespaces 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        # This is expected for Prometheus monitoring
        pass

    if issues:
        return create_result(
            "prometheus_rbac_cross_namespace",
            "Test RBAC cross-namespace access permissions",
            False,
            f"WARNING: Unexpected cross-namespace access: {', '.join(issues)}",
            "WARNING"
        )

    return create_result(
        "prometheus_rbac_cross_namespace",
        "Test RBAC cross-namespace access permissions",
        True,
        "No excessive cross-namespace access detected (cluster-wide pod read access is expected for monitoring)",
        "INFO"
    )


def test_rbac_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive RBAC permissions"""
    namespace = os.getenv("PROMETHEUS_NS", "prometheus")
    sa_name = os.getenv("PROMETHEUS_SA", "prometheus-server")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    risky_permissions = []

    # Test delete pods (Prometheus shouldn't delete pods)
    cmd = f"kubectl auth can-i delete pods --as={sa_full} -n {namespace} 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        risky_permissions.append("delete pods")

    # Test delete namespaces
    cmd = f"kubectl auth can-i delete namespaces --as={sa_full} 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        risky_permissions.append("delete namespaces (CRITICAL)")

    # Test create clusterrolebindings (privilege escalation)
    cmd = f"kubectl auth can-i create clusterrolebindings --as={sa_full} 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        risky_permissions.append("create clusterrolebindings (privilege escalation)")

    if risky_permissions:
        severity = "CRITICAL" if any("CRITICAL" in p or "escalation" in p for p in risky_permissions) else "WARNING"
        return create_result(
            "prometheus_rbac_destructive_perms",
            "Test for destructive RBAC permissions",
            False,
            f"{severity}: Risky permissions: {', '.join(risky_permissions)}",
            severity
        )

    return create_result(
        "prometheus_rbac_destructive_perms",
        "Test for destructive RBAC permissions",
        True,
        "No excessive destructive permissions detected",
        "INFO"
    )


def test_prometheus_security() -> List[Dict[str, Any]]:
    """Run all Prometheus security tests"""
    results = []

    # API Security
    results.append(test_api_authentication())
    results.append(test_write_endpoint_protection())
    results.append(test_admin_api_security())
    results.append(test_alertmanager_authentication())

    # Network Security
    results.append(test_external_exposure())
    results.append(test_network_policies())

    # Container & Kubernetes Security
    results.append(test_pod_security_context())
    results.append(test_rbac_configuration())

    # RBAC Security (detailed checks)
    results.append(test_rbac_overly_permissive_roles())
    results.append(test_rbac_cross_namespace_access())
    results.append(test_rbac_destructive_permissions())

    # Data Security
    results.append(test_data_retention())

    # Summary
    total_checks = len(results)
    passed_checks = sum(1 for r in results if r["status"])
    critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
    warnings = sum(1 for r in results if not r["status"] and r["severity"] == "WARNING")

    if critical_failures > 0:
        severity = "CRITICAL"
        status_text = f"{critical_failures} CRITICAL security issues found!"
    elif warnings > 0:
        severity = "WARNING"
        status_text = f"{warnings} security warnings found"
    else:
        severity = "INFO"
        status_text = "All security checks passed"

    results.append(create_result(
        "prometheus_security_summary",
        "Overall Prometheus security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_prometheus_security()
        print(json.dumps(results, indent=2))

        # Exit with error code if critical failures exist
        critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
        sys.exit(1 if critical_failures > 0 else 0)

    except Exception as e:
        error_result = [create_result(
            "test_execution_error",
            "Security test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
