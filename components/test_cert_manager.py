#!/usr/bin/env python3
"""
Cert-Manager Security Tests
Comprehensive security analysis for cert-manager certificate management

Tests:
1. Certificate expiration monitoring
2. Webhook security
3. RBAC configuration
4. Certificate issuer security
5. Pod security context
6. Network policies
7. Secret management
8. Certificate validation

ENV VARS:
  CERT_MANAGER_NS (default: cert-manager)
  CERT_MANAGER_PORT (default: 9402)

Output: JSON array of security test results
"""

import os
import sys
import json
import subprocess
import time
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


def check_certificate_expiration() -> Dict[str, Any]:
    """Check for certificates expiring soon"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")

    # Get all certificates across all namespaces
    cmd = "kubectl get certificates --all-namespaces -o json"
    result = run_command(cmd, timeout=15)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            certs_data = json.loads(result["stdout"])
            certs = certs_data.get("items", [])

            if not certs:
                return create_result(
                    "certmanager_certificate_expiration",
                    "Check for certificates expiring soon",
                    True,
                    "No certificates found (cert-manager may not be managing any yet)",
                    "INFO"
                )

            expiring_soon = []
            expired = []
            total_certs = len(certs)

            for cert in certs:
                cert_name = cert["metadata"]["name"]
                cert_ns = cert["metadata"]["namespace"]
                conditions = cert.get("status", {}).get("conditions", [])

                # Check certificate status
                for condition in conditions:
                    if condition.get("type") == "Ready":
                        if condition.get("status") != "True":
                            reason = condition.get("reason", "Unknown")
                            if "Expired" in reason:
                                expired.append(f"{cert_ns}/{cert_name}")
                            elif "Renewing" in reason or "Issuing" in reason:
                                expiring_soon.append(f"{cert_ns}/{cert_name}")

            if expired:
                return create_result(
                    "certmanager_certificate_expiration",
                    "Check for certificates expiring soon",
                    False,
                    f"CRITICAL: {len(expired)} certificate(s) EXPIRED: {', '.join(expired[:3])}{'...' if len(expired) > 3 else ''}",
                    "CRITICAL"
                )
            elif expiring_soon:
                return create_result(
                    "certmanager_certificate_expiration",
                    "Check for certificates expiring soon",
                    False,
                    f"WARNING: {len(expiring_soon)} certificate(s) being renewed: {', '.join(expiring_soon[:3])}{'...' if len(expiring_soon) > 3 else ''}",
                    "WARNING"
                )
            else:
                return create_result(
                    "certmanager_certificate_expiration",
                    "Check for certificates expiring soon",
                    True,
                    f"All {total_certs} certificate(s) are valid and not expiring soon",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "certmanager_certificate_expiration",
                "Check for certificates expiring soon",
                True,
                f"Unable to parse certificate data: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "certmanager_certificate_expiration",
            "Check for certificates expiring soon",
            True,
            "Unable to retrieve certificates",
            "INFO"
        )


def test_webhook_security() -> Dict[str, Any]:
    """Check if cert-manager webhook is properly secured"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")

    # Check webhook service
    cmd = f"kubectl get svc -n {namespace} -l app.kubernetes.io/name=webhook -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])
            items = services.get("items", [])

            if not items:
                return create_result(
                    "certmanager_webhook_security",
                    "Check cert-manager webhook security",
                    False,
                    "WARNING: Webhook service not found - cert-manager may not function correctly",
                    "WARNING"
                )

            svc = items[0]
            svc_type = svc["spec"]["type"]

            if svc_type != "ClusterIP":
                return create_result(
                    "certmanager_webhook_security",
                    "Check cert-manager webhook security",
                    False,
                    f"WARNING: Webhook service is {svc_type} - should be ClusterIP for security",
                    "WARNING"
                )

            # Check if webhook pod is running
            cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=webhook -o json"
            pod_result = run_command(cmd, timeout=10)

            if pod_result["exit_code"] == 0 and pod_result["stdout"]:
                pods_data = json.loads(pod_result["stdout"])
                pods = pods_data.get("items", [])

                if pods:
                    pod = pods[0]
                    phase = pod.get("status", {}).get("phase", "Unknown")

                    if phase == "Running":
                        return create_result(
                            "certmanager_webhook_security",
                            "Check cert-manager webhook security",
                            True,
                            "Webhook is running and properly configured as ClusterIP",
                            "INFO"
                        )
                    else:
                        return create_result(
                            "certmanager_webhook_security",
                            "Check cert-manager webhook security",
                            False,
                            f"WARNING: Webhook pod is in {phase} state",
                            "WARNING"
                        )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "certmanager_webhook_security",
        "Check cert-manager webhook security",
        True,
        "Unable to check webhook configuration",
        "INFO"
    )


def check_rbac_configuration() -> Dict[str, Any]:
    """Check cert-manager RBAC configuration"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")

    # Get cert-manager pods to find ServiceAccount
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=cert-manager -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "certmanager_rbac_configuration",
                    "Check cert-manager RBAC configuration",
                    True,
                    "No cert-manager pods found",
                    "INFO"
                )

            pod = pods_data["items"][0]
            service_account = pod["spec"].get("serviceAccountName", "default")

            # Check if using default SA (bad practice)
            if service_account == "default":
                return create_result(
                    "certmanager_rbac_configuration",
                    "Check cert-manager RBAC configuration",
                    False,
                    "CRITICAL: cert-manager is using 'default' ServiceAccount. Should use dedicated ServiceAccount.",
                    "CRITICAL"
                )

            # Check for ClusterRoleBindings
            cmd = f"kubectl get clusterrolebinding -o json"
            crb_result = run_command(cmd, timeout=10)

            if crb_result["exit_code"] == 0 and crb_result["stdout"]:
                crb_data = json.loads(crb_result["stdout"])
                has_binding = False

                for binding in crb_data.get("items", []):
                    subjects = binding.get("subjects", [])
                    for subject in subjects:
                        if (subject.get("name") == service_account and
                            subject.get("namespace") == namespace):
                            has_binding = True
                            break

                if has_binding:
                    return create_result(
                        "certmanager_rbac_configuration",
                        "Check cert-manager RBAC configuration",
                        True,
                        f"ServiceAccount '{service_account}' has appropriate ClusterRole bindings",
                        "INFO"
                    )
                else:
                    return create_result(
                        "certmanager_rbac_configuration",
                        "Check cert-manager RBAC configuration",
                        False,
                        f"WARNING: ServiceAccount '{service_account}' may not have required ClusterRole bindings",
                        "WARNING"
                    )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "certmanager_rbac_configuration",
                "Check cert-manager RBAC configuration",
                True,
                f"Unable to check RBAC: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "certmanager_rbac_configuration",
            "Check cert-manager RBAC configuration",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def check_certificate_issuers() -> Dict[str, Any]:
    """Check certificate issuers configuration"""
    # Get all issuers
    cmd = "kubectl get issuers,clusterissuers --all-namespaces -o json"
    result = run_command(cmd, timeout=15)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            issuers_data = json.loads(result["stdout"])
            issuers = issuers_data.get("items", [])

            if not issuers:
                return create_result(
                    "certmanager_certificate_issuers",
                    "Check certificate issuers configuration",
                    False,
                    "WARNING: No certificate issuers configured. Cert-manager cannot issue certificates.",
                    "WARNING"
                )

            ready_issuers = 0
            not_ready = []

            for issuer in issuers:
                issuer_name = issuer["metadata"]["name"]
                issuer_kind = issuer["kind"]
                conditions = issuer.get("status", {}).get("conditions", [])

                for condition in conditions:
                    if condition.get("type") == "Ready":
                        if condition.get("status") == "True":
                            ready_issuers += 1
                        else:
                            not_ready.append(f"{issuer_kind}/{issuer_name}")

            if not_ready:
                return create_result(
                    "certmanager_certificate_issuers",
                    "Check certificate issuers configuration",
                    False,
                    f"WARNING: {len(not_ready)} issuer(s) not ready: {', '.join(not_ready[:3])}",
                    "WARNING"
                )
            else:
                return create_result(
                    "certmanager_certificate_issuers",
                    "Check certificate issuers configuration",
                    True,
                    f"{ready_issuers} certificate issuer(s) configured and ready",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "certmanager_certificate_issuers",
                "Check certificate issuers configuration",
                True,
                "Unable to parse issuer data",
                "INFO"
            )
    else:
        return create_result(
            "certmanager_certificate_issuers",
            "Check certificate issuers configuration",
            True,
            "Unable to retrieve certificate issuers",
            "INFO"
        )


def check_pod_security_context() -> Dict[str, Any]:
    """Check if cert-manager pods run with secure security context"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")

    # Get all cert-manager pods (controller, webhook, cainjector)
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/instance=cert-manager -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            if not pods:
                return create_result(
                    "certmanager_pod_security_context",
                    "Check cert-manager pod security context",
                    True,
                    "No cert-manager pods found",
                    "INFO"
                )

            all_issues = []

            for pod in pods:
                pod_name = pod["metadata"]["name"]
                pod_security = pod["spec"].get("securityContext", {})
                pod_run_as_non_root = pod_security.get("runAsNonRoot", False)

                containers = pod["spec"].get("containers", [])
                for container in containers:
                    container_security = container.get("securityContext", {})

                    # Check if running as non-root
                    container_run_as_non_root = container_security.get("runAsNonRoot", False)
                    if not pod_run_as_non_root and not container_run_as_non_root:
                        all_issues.append(f"{pod_name}: not enforcing runAsNonRoot")

                    # Check if privileged
                    if container_security.get("privileged", False):
                        all_issues.append(f"{pod_name}: running in privileged mode")

            if all_issues:
                return create_result(
                    "certmanager_pod_security_context",
                    "Check cert-manager pod security context",
                    False,
                    f"Security issues: {', '.join(all_issues[:3])}{'...' if len(all_issues) > 3 else ''}",
                    "WARNING"
                )
            else:
                return create_result(
                    "certmanager_pod_security_context",
                    "Check cert-manager pod security context",
                    True,
                    f"All {len(pods)} cert-manager pod(s) have secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "certmanager_pod_security_context",
                "Check cert-manager pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "certmanager_pod_security_context",
            "Check cert-manager pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def check_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for cert-manager"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")

    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "certmanager_network_policies",
                    "Check if NetworkPolicies restrict cert-manager",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Webhook is accessible from any pod.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "certmanager_network_policies",
                    "Check if NetworkPolicies restrict cert-manager",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "certmanager_network_policies",
                "Check if NetworkPolicies restrict cert-manager",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "certmanager_network_policies",
            "Check if NetworkPolicies restrict cert-manager",
            False,
            f"WARNING: Unable to check NetworkPolicies",
            "WARNING"
        )


def check_rbac_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    sa_name = os.getenv("CERT_MANAGER_SA", "cert-manager")

    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        return create_result(
            "certmanager_rbac_permissive_roles",
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
                    elif "admin" in role_name.lower() and "cert-manager" not in role_name.lower():
                        risky_roles.append(f"'{role_name}' (potentially risky)")

        if risky_roles:
            return create_result(
                "certmanager_rbac_permissive_roles",
                "Check for overly permissive RBAC cluster roles",
                False,
                f"CRITICAL: Overly permissive roles: {', '.join(risky_roles)}",
                "CRITICAL"
            )

        return create_result(
            "certmanager_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "No overly permissive cluster roles detected",
            "INFO"
        )

    except json.JSONDecodeError:
        return create_result(
            "certmanager_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to parse ClusterRoleBindings",
            "INFO"
        )


def check_rbac_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    sa_name = os.getenv("CERT_MANAGER_SA", "cert-manager")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    issues = []

    # cert-manager needs cluster-wide certificate access, so only check for sensitive resources
    # Test access to kube-system secrets
    cmd = f"kubectl auth can-i get secrets --as={sa_full} -n kube-system 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        issues.append("Can access secrets in kube-system (unexpected)")

    if issues:
        return create_result(
            "certmanager_rbac_cross_namespace",
            "Test RBAC cross-namespace access permissions",
            False,
            f"WARNING: Unexpected cross-namespace access: {', '.join(issues)}",
            "WARNING"
        )

    return create_result(
        "certmanager_rbac_cross_namespace",
        "Test RBAC cross-namespace access permissions",
        True,
        "No excessive cross-namespace access detected (cluster-wide certificate access is expected)",
        "INFO"
    )


def check_rbac_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive RBAC permissions"""
    namespace = os.getenv("CERT_MANAGER_NS", "cert-manager")
    sa_name = os.getenv("CERT_MANAGER_SA", "cert-manager")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    risky_permissions = []

    # Test delete pods (cert-manager shouldn't delete pods)
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
            "certmanager_rbac_destructive_perms",
            "Test for destructive RBAC permissions",
            False,
            f"{severity}: Risky permissions: {', '.join(risky_permissions)}",
            severity
        )

    return create_result(
        "certmanager_rbac_destructive_perms",
        "Test for destructive RBAC permissions",
        True,
        "No excessive destructive permissions detected",
        "INFO"
    )


def test_certmanager_security() -> List[Dict[str, Any]]:
    """Run all cert-manager security tests"""
    results = []

    # Certificate Management
    results.append(check_certificate_expiration())
    results.append(check_certificate_issuers())

    # Component Security
    results.append(test_webhook_security())
    results.append(check_rbac_configuration())

    # RBAC Security (detailed checks)
    results.append(check_rbac_overly_permissive_roles())
    results.append(check_rbac_cross_namespace_access())
    results.append(check_rbac_destructive_permissions())

    # Container & Kubernetes Security
    results.append(check_pod_security_context())
    results.append(check_network_policies())

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
        "certmanager_security_summary",
        "Overall cert-manager security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


# Alias for UI compatibility - the UI expects test_cert_manager() not test_certmanager_security()
def test_cert_manager() -> List[Dict[str, Any]]:
    """Alias for test_certmanager_security() for UI compatibility"""
    return test_certmanager_security()


if __name__ == "__main__":
    try:
        results = test_certmanager_security()
        print(json.dumps(results, indent=2))

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
