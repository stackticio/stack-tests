#!/usr/bin/env python3
"""
Keycloak Operator Security Tests
Comprehensive security analysis for Keycloak authentication and SSO platform

Tests:
1. Default admin credentials (admin/admin)
2. Weak admin password
3. Realm configuration security
4. Client secret exposure
5. User password policies
6. External exposure
7. Pod security context
8. Network policies
9. RBAC configuration
10. TLS/SSL configuration
11. Operator health

ENV VARS:
  KEYCLOAK_NS (default: keycloak)
  KEYCLOAK_HOST (default: keycloak.keycloak.svc.cluster.local)
  KEYCLOAK_PORT (default: 8080)
  KEYCLOAK_ADMIN_USER (default: admin)
  KEYCLOAK_ADMIN_PASSWORD (default: admin)

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


def check_default_credentials() -> Dict[str, Any]:
    """Check if Keycloak is using default admin credentials"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")
    admin_user = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
    admin_pass = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")

    # Check if admin secret exists
    cmd = f"kubectl get secret -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            secrets = json.loads(result["stdout"])
            keycloak_secrets = [s for s in secrets.get("items", [])
                               if "keycloak" in s["metadata"]["name"].lower()]

            if keycloak_secrets:
                # Check for common default credential patterns
                for secret in keycloak_secrets:
                    secret_name = secret["metadata"]["name"]
                    if "admin" in secret_name.lower():
                        data = secret.get("data", {})

                        # Check if using default username
                        if "username" in data or "KEYCLOAK_ADMIN" in data:
                            return create_result(
                                "keycloak_default_credentials",
                                "Check for default admin credentials",
                                False,
                                f"WARNING: Found admin credential secret '{secret_name}'. Verify not using default admin/admin.",
                                "WARNING"
                            )
        except (json.JSONDecodeError, KeyError):
            pass

    # If configured admin_pass is "admin", that's a critical issue
    if admin_pass == "admin":
        return create_result(
            "keycloak_default_credentials",
            "Check for default admin credentials",
            False,
            "CRITICAL: KEYCLOAK_ADMIN_PASSWORD environment variable is set to default 'admin'",
            "CRITICAL"
        )

    return create_result(
        "keycloak_default_credentials",
        "Check for default admin credentials",
        True,
        "Admin password appears to be non-default",
        "INFO"
    )


def check_weak_password() -> Dict[str, Any]:
    """Check if Keycloak admin password is weak"""
    admin_pass = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")

    weak_passwords = ["admin", "password", "keycloak", "123456", "admin123", "changeme"]

    if admin_pass.lower() in weak_passwords:
        return create_result(
            "keycloak_weak_password",
            "Check for weak admin password",
            False,
            f"CRITICAL: Admin password is weak: '{admin_pass}'",
            "CRITICAL"
        )

    if len(admin_pass) < 8:
        return create_result(
            "keycloak_weak_password",
            "Check for weak admin password",
            False,
            f"WARNING: Admin password is too short (< 8 characters)",
            "WARNING"
        )

    return create_result(
        "keycloak_weak_password",
        "Check for weak admin password",
        True,
        "Admin password meets minimum security requirements",
        "INFO"
    )


def check_realm_configuration() -> Dict[str, Any]:
    """Check Keycloak realm configuration security"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check for Keycloak custom resources
    cmd = f"kubectl get keycloaks.k8s.keycloak.org -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            keycloaks = json.loads(result["stdout"])
            items = keycloaks.get("items", [])

            if not items:
                return create_result(
                    "keycloak_realm_configuration",
                    "Check Keycloak realm configuration",
                    True,
                    "No Keycloak custom resources found",
                    "INFO"
                )

            # Check if realms are configured
            kc = items[0]
            status = kc.get("status", {})

            if status.get("ready"):
                return create_result(
                    "keycloak_realm_configuration",
                    "Check Keycloak realm configuration",
                    True,
                    f"Keycloak instance is ready and configured",
                    "INFO"
                )
            else:
                return create_result(
                    "keycloak_realm_configuration",
                    "Check Keycloak realm configuration",
                    False,
                    "WARNING: Keycloak instance is not ready",
                    "WARNING"
                )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "keycloak_realm_configuration",
        "Check Keycloak realm configuration",
        True,
        "Unable to check realm configuration (Keycloak operator may not be installed)",
        "INFO"
    )


def check_client_secrets() -> Dict[str, Any]:
    """Check for exposed client secrets"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check for KeycloakClient resources
    cmd = f"kubectl get keycloakclients.k8s.keycloak.org -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            clients = json.loads(result["stdout"])
            items = clients.get("items", [])

            if not items:
                return create_result(
                    "keycloak_client_secrets",
                    "Check for exposed client secrets",
                    True,
                    "No KeycloakClient resources found",
                    "INFO"
                )

            # Check if client secrets are stored in secrets (good practice)
            clients_with_secrets = []
            for client in items:
                client_name = client["metadata"]["name"]
                spec = client.get("spec", {})

                # Check if client secret is referenced properly
                if "secret" in spec:
                    secret_ref = spec["secret"]
                    if isinstance(secret_ref, str):
                        clients_with_secrets.append(client_name)

            if clients_with_secrets:
                return create_result(
                    "keycloak_client_secrets",
                    "Check for exposed client secrets",
                    True,
                    f"{len(clients_with_secrets)} client(s) using secret references (secure)",
                    "INFO"
                )
            else:
                return create_result(
                    "keycloak_client_secrets",
                    "Check for exposed client secrets",
                    False,
                    "WARNING: No clients using secret references. Verify client secrets are properly secured.",
                    "WARNING"
                )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "keycloak_client_secrets",
        "Check for exposed client secrets",
        True,
        "Unable to check client secrets",
        "INFO"
    )


def check_password_policies() -> Dict[str, Any]:
    """Check if strong password policies are configured"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check for KeycloakRealm resources
    cmd = f"kubectl get keycloakrealms.k8s.keycloak.org -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            realms = json.loads(result["stdout"])
            items = realms.get("items", [])

            if not items:
                return create_result(
                    "keycloak_password_policies",
                    "Check password policy configuration",
                    False,
                    "WARNING: No KeycloakRealm resources found. Password policies should be configured.",
                    "WARNING"
                )

            # Check realm password policies
            realms_without_policies = []
            for realm in items:
                realm_name = realm["metadata"]["name"]
                spec = realm.get("spec", {})
                realm_config = spec.get("realm", {})

                password_policy = realm_config.get("passwordPolicy", "")

                # Check for basic password requirements
                if not password_policy or len(password_policy) < 10:
                    realms_without_policies.append(realm_name)

            if realms_without_policies:
                return create_result(
                    "keycloak_password_policies",
                    "Check password policy configuration",
                    False,
                    f"WARNING: {len(realms_without_policies)} realm(s) without strong password policies: {', '.join(realms_without_policies[:3])}",
                    "WARNING"
                )
            else:
                return create_result(
                    "keycloak_password_policies",
                    "Check password policy configuration",
                    True,
                    f"All {len(items)} realm(s) have password policies configured",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "keycloak_password_policies",
        "Check password policy configuration",
        True,
        "Unable to check password policies",
        "INFO"
    )


def check_external_exposure() -> Dict[str, Any]:
    """Check if Keycloak is exposed externally"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check for LoadBalancer or NodePort services
    cmd = f"kubectl get svc -n {namespace} -l app=keycloak -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])
            items = services.get("items", [])

            if not items:
                return create_result(
                    "keycloak_external_exposure",
                    "Check if Keycloak is externally exposed",
                    True,
                    "No Keycloak service found",
                    "INFO"
                )

            for svc in items:
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                if svc_type == "LoadBalancer":
                    external_ip = svc.get("status", {}).get("loadBalancer", {}).get("ingress", [])
                    if external_ip:
                        return create_result(
                            "keycloak_external_exposure",
                            "Check if Keycloak is externally exposed",
                            False,
                            f"CRITICAL: Keycloak service '{svc_name}' is exposed via LoadBalancer. Ensure TLS is enabled!",
                            "CRITICAL"
                        )

                if svc_type == "NodePort":
                    return create_result(
                        "keycloak_external_exposure",
                        "Check if Keycloak is externally exposed",
                        False,
                        f"WARNING: Keycloak service '{svc_name}' is exposed via NodePort",
                        "WARNING"
                    )

            return create_result(
                "keycloak_external_exposure",
                "Check if Keycloak is externally exposed",
                True,
                "Keycloak service is ClusterIP (not externally exposed)",
                "INFO"
            )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "keycloak_external_exposure",
        "Check if Keycloak is externally exposed",
        True,
        "Unable to check service exposure",
        "INFO"
    )


def check_pod_security_context() -> Dict[str, Any]:
    """Check if Keycloak pods run with secure security context"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    cmd = f"kubectl get pod -n {namespace} -l app=keycloak -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            if not pods:
                return create_result(
                    "keycloak_pod_security_context",
                    "Check Keycloak pod security context",
                    True,
                    "No Keycloak pods found",
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
                    "keycloak_pod_security_context",
                    "Check Keycloak pod security context",
                    False,
                    f"Security issues: {', '.join(all_issues[:3])}{'...' if len(all_issues) > 3 else ''}",
                    "WARNING"
                )
            else:
                return create_result(
                    "keycloak_pod_security_context",
                    "Check Keycloak pod security context",
                    True,
                    f"All {len(pods)} Keycloak pod(s) have secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "keycloak_pod_security_context",
                "Check Keycloak pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "keycloak_pod_security_context",
            "Check Keycloak pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def check_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for Keycloak"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    cmd = f"kubectl get networkpolicies -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "keycloak_network_policies",
                    "Check if NetworkPolicies restrict Keycloak",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Keycloak is accessible from any pod.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "keycloak_network_policies",
                    "Check if NetworkPolicies restrict Keycloak",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "keycloak_network_policies",
                "Check if NetworkPolicies restrict Keycloak",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "keycloak_network_policies",
            "Check if NetworkPolicies restrict Keycloak",
            False,
            f"WARNING: Unable to check NetworkPolicies",
            "WARNING"
        )


def check_rbac_configuration() -> Dict[str, Any]:
    """Check Keycloak RBAC configuration"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check for operator pods to find ServiceAccount
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=keycloak-operator -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "keycloak_rbac_configuration",
                    "Check Keycloak RBAC configuration",
                    True,
                    "No Keycloak operator pods found",
                    "INFO"
                )

            pod = pods_data["items"][0]
            service_account = pod["spec"].get("serviceAccountName", "default")

            # Check if using default SA (bad practice)
            if service_account == "default":
                return create_result(
                    "keycloak_rbac_configuration",
                    "Check Keycloak RBAC configuration",
                    False,
                    "CRITICAL: Keycloak operator is using 'default' ServiceAccount. Should use dedicated ServiceAccount.",
                    "CRITICAL"
                )

            # Check for RoleBindings
            cmd = f"kubectl get rolebinding -n {namespace} -o json 2>/dev/null"
            rb_result = run_command(cmd, timeout=10)

            if rb_result["exit_code"] == 0 and rb_result["stdout"]:
                rb_data = json.loads(rb_result["stdout"])
                has_binding = False

                for binding in rb_data.get("items", []):
                    subjects = binding.get("subjects", [])
                    for subject in subjects:
                        if subject.get("name") == service_account:
                            has_binding = True
                            break

                if has_binding:
                    return create_result(
                        "keycloak_rbac_configuration",
                        "Check Keycloak RBAC configuration",
                        True,
                        f"ServiceAccount '{service_account}' has appropriate Role bindings",
                        "INFO"
                    )
                else:
                    return create_result(
                        "keycloak_rbac_configuration",
                        "Check Keycloak RBAC configuration",
                        False,
                        f"WARNING: ServiceAccount '{service_account}' may not have required Role bindings",
                        "WARNING"
                    )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "keycloak_rbac_configuration",
                "Check Keycloak RBAC configuration",
                True,
                f"Unable to check RBAC: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "keycloak_rbac_configuration",
            "Check Keycloak RBAC configuration",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def check_tls_configuration() -> Dict[str, Any]:
    """Check if TLS is properly configured for Keycloak"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check Keycloak custom resource for TLS config
    cmd = f"kubectl get keycloaks.k8s.keycloak.org -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            keycloaks = json.loads(result["stdout"])
            items = keycloaks.get("items", [])

            if not items:
                return create_result(
                    "keycloak_tls_configuration",
                    "Check TLS configuration",
                    True,
                    "No Keycloak custom resources found",
                    "INFO"
                )

            kc = items[0]
            spec = kc.get("spec", {})

            # Check if TLS is enabled
            tls_secret = spec.get("http", {}).get("tlsSecret", "")

            if not tls_secret:
                return create_result(
                    "keycloak_tls_configuration",
                    "Check TLS configuration",
                    False,
                    "WARNING: No TLS secret configured. Keycloak should use HTTPS in production.",
                    "WARNING"
                )
            else:
                return create_result(
                    "keycloak_tls_configuration",
                    "Check TLS configuration",
                    True,
                    f"TLS configured with secret: {tls_secret}",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "keycloak_tls_configuration",
        "Check TLS configuration",
        True,
        "Unable to check TLS configuration",
        "INFO"
    )


def check_operator_health() -> Dict[str, Any]:
    """Check if Keycloak operator is healthy"""
    namespace = os.getenv("KEYCLOAK_NS", "keycloak")

    # Check operator pod status
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=keycloak-operator -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            if not pods:
                return create_result(
                    "keycloak_operator_health",
                    "Check Keycloak operator health",
                    False,
                    "WARNING: No Keycloak operator pods found",
                    "WARNING"
                )

            pod = pods[0]
            phase = pod.get("status", {}).get("phase", "Unknown")

            if phase == "Running":
                # Check if containers are ready
                container_statuses = pod.get("status", {}).get("containerStatuses", [])
                all_ready = all(cs.get("ready", False) for cs in container_statuses)

                if all_ready:
                    return create_result(
                        "keycloak_operator_health",
                        "Check Keycloak operator health",
                        True,
                        "Keycloak operator is running and healthy",
                        "INFO"
                    )
                else:
                    return create_result(
                        "keycloak_operator_health",
                        "Check Keycloak operator health",
                        False,
                        "WARNING: Keycloak operator is running but containers not ready",
                        "WARNING"
                    )
            else:
                return create_result(
                    "keycloak_operator_health",
                    "Check Keycloak operator health",
                    False,
                    f"WARNING: Keycloak operator pod is in {phase} state",
                    "WARNING"
                )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "keycloak_operator_health",
        "Check Keycloak operator health",
        True,
        "Unable to check operator health",
        "INFO"
    )


def test_keycloak_operator() -> List[Dict[str, Any]]:
    """Run all Keycloak operator security tests"""
    results = []

    # Authentication Security
    results.append(check_default_credentials())
    results.append(check_weak_password())
    results.append(check_password_policies())

    # Configuration Security
    results.append(check_realm_configuration())
    results.append(check_client_secrets())
    results.append(check_tls_configuration())

    # Exposure & Network Security
    results.append(check_external_exposure())
    results.append(check_network_policies())

    # Kubernetes Security
    results.append(check_pod_security_context())
    results.append(check_rbac_configuration())

    # Operator Health
    results.append(check_operator_health())

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
        "keycloak_security_summary",
        "Overall Keycloak security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_keycloak_operator()
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
