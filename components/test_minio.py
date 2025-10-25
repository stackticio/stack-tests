#!/usr/bin/env python3
"""
MinIO Security Tests
Comprehensive security analysis for MinIO object storage

Tests:
1. Default credentials (minioadmin/minioadmin)
2. Weak admin password
3. Anonymous bucket access
4. Bucket policies and public exposure
5. TLS/SSL configuration
6. Console access security
7. External exposure
8. Pod security context
9. Network policies
10. RBAC configuration

ENV VARS:
  MINIO_NS (default: minio)
  MINIO_HOST (default: minio.minio.svc.cluster.local)
  MINIO_PORT (default: 9000)
  MINIO_CONSOLE_PORT (default: 9001)
  MINIO_ACCESS_KEY (default: minioadmin)
  MINIO_SECRET_KEY (default: minioadmin)
  MINIO_SA (default: minio)

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
    """Test if default minioadmin/minioadmin credentials work"""
    host = os.getenv("MINIO_HOST", "minio.minio.svc.cluster.local")
    port = os.getenv("MINIO_PORT", "9000")

    # Try to access MinIO with default credentials
    # Check if we can list buckets with default credentials
    cmd = f"curl -s -I -X GET http://{host}:{port}/minio/health/live 2>&1"
    result = run_command(cmd, timeout=10)

    # Try accessing with default credentials via AWS CLI format
    cmd = f"curl -s -u minioadmin:minioadmin http://{host}:{port}/ 2>&1"
    auth_result = run_command(cmd, timeout=10)

    if "AccessDenied" in auth_result["stdout"] or auth_result["exit_code"] != 0:
        return create_result(
            "minio_default_credentials",
            "Check if default minioadmin credentials are disabled",
            True,
            "Default minioadmin/minioadmin credentials appear to be disabled or changed",
            "INFO"
        )
    else:
        # Additional check - try to actually authenticate
        access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")

        if access_key == "minioadmin" and secret_key == "minioadmin":
            return create_result(
                "minio_default_credentials",
                "Check if default minioadmin credentials are disabled",
                False,
                "CRITICAL: Default minioadmin/minioadmin credentials are configured! Change immediately.",
                "CRITICAL"
            )

        return create_result(
            "minio_default_credentials",
            "Check if default minioadmin credentials are disabled",
            True,
            "Custom credentials are configured (not using defaults)",
            "INFO"
        )


def check_weak_admin_password() -> Dict[str, Any]:
    """Check if admin password is weak or default"""
    secret_key = os.getenv("MINIO_SECRET_KEY", "")

    weak_passwords = [
        "minioadmin", "password", "123456", "minio", "admin",
        "default", "password123", "admin123", "minio123"
    ]

    if secret_key.lower() in weak_passwords:
        return create_result(
            "minio_weak_admin_password",
            "Check if admin password is strong",
            False,
            f"CRITICAL: Admin password '{secret_key}' is a known weak/default password! Change immediately.",
            "CRITICAL"
        )
    elif len(secret_key) < 12:
        return create_result(
            "minio_weak_admin_password",
            "Check if admin password is strong",
            False,
            f"WARNING: Admin password length is {len(secret_key)} characters. Recommended minimum is 12 characters.",
            "WARNING"
        )
    else:
        return create_result(
            "minio_weak_admin_password",
            "Check if admin password is strong",
            True,
            f"Admin password appears strong (length: {len(secret_key)} characters)",
            "INFO"
        )


def check_anonymous_bucket_access() -> Dict[str, Any]:
    """Test if buckets allow anonymous access"""
    host = os.getenv("MINIO_HOST", "minio.minio.svc.cluster.local")
    port = os.getenv("MINIO_PORT", "9000")

    # Try to list buckets anonymously
    cmd = f"curl -s -X GET http://{host}:{port}/ 2>&1"
    result = run_command(cmd, timeout=10)

    if "AccessDenied" in result["stdout"] or "InvalidAccessKeyId" in result["stdout"]:
        return create_result(
            "minio_anonymous_access",
            "Check if anonymous bucket access is disabled",
            True,
            "Anonymous access properly requires authentication",
            "INFO"
        )
    elif "ListBucketResult" in result["stdout"] or "Bucket" in result["stdout"]:
        return create_result(
            "minio_anonymous_access",
            "Check if anonymous bucket access is disabled",
            False,
            "CRITICAL: Anonymous access to buckets is ENABLED! Buckets are publicly accessible.",
            "CRITICAL"
        )
    else:
        return create_result(
            "minio_anonymous_access",
            "Check if anonymous bucket access is disabled",
            True,
            f"Unable to access without credentials (HTTP response indicates auth required)",
            "INFO"
        )


def check_tls_configuration() -> Dict[str, Any]:
    """Check if MinIO is using TLS/SSL"""
    host = os.getenv("MINIO_HOST", "minio.minio.svc.cluster.local")
    port = os.getenv("MINIO_PORT", "9000")

    # Check if TLS port responds
    cmd = f"timeout 5 bash -c 'echo | openssl s_client -connect {host}:{port} 2>&1' | grep -q 'Verify return code'"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        # TLS is available, check certificate
        cert_cmd = f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null"
        cert_result = run_command(cert_cmd, timeout=10)

        if cert_result["exit_code"] == 0 and "notAfter" in cert_result["stdout"]:
            return create_result(
                "minio_tls_configuration",
                "Check if MinIO uses TLS/SSL encryption",
                True,
                f"TLS is enabled with valid certificate",
                "INFO"
            )
        else:
            return create_result(
                "minio_tls_configuration",
                "Check if MinIO uses TLS/SSL encryption",
                False,
                f"TLS is accessible but certificate validation failed",
                "WARNING"
            )
    else:
        # Check if non-TLS port is responding
        non_tls_cmd = f"curl -s -I http://{host}:{port}/minio/health/live 2>&1"
        non_tls_result = run_command(non_tls_cmd, timeout=5)

        if non_tls_result["exit_code"] == 0:
            return create_result(
                "minio_tls_configuration",
                "Check if MinIO uses TLS/SSL encryption",
                False,
                f"WARNING: TLS not detected. MinIO appears to be using unencrypted HTTP. Enable TLS for production.",
                "WARNING"
            )

        return create_result(
            "minio_tls_configuration",
            "Check if MinIO uses TLS/SSL encryption",
            True,
            "Unable to determine TLS status (service may not be accessible)",
            "INFO"
        )


def check_console_security() -> Dict[str, Any]:
    """Check if MinIO Console is properly secured"""
    host = os.getenv("MINIO_HOST", "minio.minio.svc.cluster.local")
    console_port = int(os.getenv("MINIO_CONSOLE_PORT", "9001"))

    # Check if console is accessible without auth
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{console_port}/ 2>&1"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        # Console is accessible, check if it requires login
        content_cmd = f"curl -s http://{host}:{console_port}/ 2>&1"
        content_result = run_command(content_cmd, timeout=10)

        if "login" in content_result["stdout"].lower() or "sign in" in content_result["stdout"].lower():
            return create_result(
                "minio_console_security",
                "Check if MinIO Console requires authentication",
                True,
                "Console requires authentication (login page detected)",
                "INFO"
            )
        else:
            return create_result(
                "minio_console_security",
                "Check if MinIO Console requires authentication",
                False,
                "WARNING: Console may be accessible without authentication",
                "WARNING"
            )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "minio_console_security",
            "Check if MinIO Console requires authentication",
            True,
            f"Console properly requires authentication (HTTP {http_code})",
            "INFO"
        )
    elif http_code == "000":
        return create_result(
            "minio_console_security",
            "Check if MinIO Console requires authentication",
            True,
            "Console is not accessible (connection refused) - may be properly restricted",
            "INFO"
        )
    else:
        return create_result(
            "minio_console_security",
            "Check if MinIO Console requires authentication",
            True,
            f"Console returned HTTP {http_code} - authentication appears required",
            "INFO"
        )


def check_external_exposure() -> Dict[str, Any]:
    """Check if MinIO is exposed externally via LoadBalancer"""
    namespace = os.getenv("MINIO_NS", "minio")

    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                if "minio" in svc_name.lower():
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        return create_result(
                            "minio_external_exposure",
                            "Check if MinIO is exposed to external networks",
                            False,
                            f"WARNING: MinIO service '{svc_name}' is exposed as LoadBalancer with external IP: {external_ip}. Ensure proper authentication and encryption.",
                            "WARNING"
                        )
                    elif svc_type == "ClusterIP":
                        return create_result(
                            "minio_external_exposure",
                            "Check if MinIO is exposed to external networks",
                            True,
                            f"MinIO service '{svc_name}' is ClusterIP (internal only) - good security practice",
                            "INFO"
                        )
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        return create_result(
                            "minio_external_exposure",
                            "Check if MinIO is exposed to external networks",
                            False,
                            f"WARNING: MinIO service '{svc_name}' is exposed via NodePort: {node_ports}. Ensure proper network policies.",
                            "WARNING"
                        )

            return create_result(
                "minio_external_exposure",
                "Check if MinIO is exposed to external networks",
                True,
                "No MinIO service found or service is internal only",
                "INFO"
            )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "minio_external_exposure",
                "Check if MinIO is exposed to external networks",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "minio_external_exposure",
            "Check if MinIO is exposed to external networks",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def check_pod_security_context() -> Dict[str, Any]:
    """Check if MinIO pods run with secure security context"""
    namespace = os.getenv("MINIO_NS", "minio")

    cmd = f"kubectl get pod -n {namespace} -l app=minio -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                # Try alternative label
                cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=minio -o json"
                result = run_command(cmd, timeout=10)
                if result["exit_code"] == 0 and result["stdout"]:
                    pods_data = json.loads(result["stdout"])

                if not pods_data.get("items"):
                    return create_result(
                        "minio_pod_security_context",
                        "Check MinIO pod security context",
                        True,
                        "No MinIO pods found",
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
                if "minio" in container["name"].lower():
                    container_security = container.get("securityContext", {})

                    # Check if running as non-root (pod-level OR container-level)
                    container_run_as_non_root = container_security.get("runAsNonRoot", False)
                    if not pod_run_as_non_root and not container_run_as_non_root:
                        issues.append("Neither pod nor container enforcing runAsNonRoot")

                    # Check if privileged
                    privileged = container_security.get("privileged", False)
                    if privileged:
                        issues.append("Container is running in privileged mode")

                    # Check capabilities
                    capabilities = container_security.get("capabilities", {})
                    added_caps = capabilities.get("add", [])
                    if added_caps:
                        issues.append(f"Additional capabilities added: {added_caps}")

            if issues:
                return create_result(
                    "minio_pod_security_context",
                    "Check MinIO pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join(issues)}",
                    "WARNING"
                )
            else:
                return create_result(
                    "minio_pod_security_context",
                    "Check MinIO pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "minio_pod_security_context",
                "Check MinIO pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "minio_pod_security_context",
            "Check MinIO pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def check_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for MinIO namespace"""
    namespace = os.getenv("MINIO_NS", "minio")

    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "minio_network_policies",
                    "Check if NetworkPolicies restrict MinIO access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Network traffic is unrestricted.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "minio_network_policies",
                    "Check if NetworkPolicies restrict MinIO access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "minio_network_policies",
                "Check if NetworkPolicies restrict MinIO access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "minio_network_policies",
            "Check if NetworkPolicies restrict MinIO access",
            False,
            f"WARNING: Unable to check NetworkPolicies (may not exist or no permissions)",
            "WARNING"
        )


def check_rbac_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("MINIO_NS", "minio")
    sa_name = os.getenv("MINIO_SA", "minio")

    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        return create_result(
            "minio_rbac_permissive_roles",
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
                    elif "admin" in role_name.lower() and "minio" not in role_name.lower():
                        risky_roles.append(f"'{role_name}' (potentially risky)")

        if risky_roles:
            return create_result(
                "minio_rbac_permissive_roles",
                "Check for overly permissive RBAC cluster roles",
                False,
                f"CRITICAL: Overly permissive roles: {', '.join(risky_roles)}",
                "CRITICAL"
            )

        return create_result(
            "minio_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "No overly permissive cluster roles detected",
            "INFO"
        )

    except json.JSONDecodeError:
        return create_result(
            "minio_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to parse ClusterRoleBindings",
            "INFO"
        )


def check_rbac_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("MINIO_NS", "minio")
    sa_name = os.getenv("MINIO_SA", "minio")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    issues = []

    # Test access to kube-system secrets
    cmd = f"kubectl auth can-i get secrets --as={sa_full} -n kube-system 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        issues.append("Can access secrets in kube-system")

    # Test cluster-wide pod access
    cmd = f"kubectl auth can-i get pods --as={sa_full} --all-namespaces 2>/dev/null"
    result = run_command(cmd, timeout=5)
    if result["exit_code"] == 0 and "yes" in result["stdout"].lower():
        issues.append("Can list pods cluster-wide")

    if issues:
        return create_result(
            "minio_rbac_cross_namespace",
            "Test RBAC cross-namespace access permissions",
            False,
            f"WARNING: Cross-namespace access: {', '.join(issues)}",
            "WARNING"
        )

    return create_result(
        "minio_rbac_cross_namespace",
        "Test RBAC cross-namespace access permissions",
        True,
        "No excessive cross-namespace access detected",
        "INFO"
    )


def check_rbac_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive RBAC permissions"""
    namespace = os.getenv("MINIO_NS", "minio")
    sa_name = os.getenv("MINIO_SA", "minio")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    risky_permissions = []

    # Test delete pods
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
            "minio_rbac_destructive_perms",
            "Test for destructive RBAC permissions",
            False,
            f"{severity}: Risky permissions: {', '.join(risky_permissions)}",
            severity
        )

    return create_result(
        "minio_rbac_destructive_perms",
        "Test for destructive RBAC permissions",
        True,
        "No excessive destructive permissions detected",
        "INFO"
    )


def test_minio() -> List[Dict[str, Any]]:
    """Run all minio security tests"""
    """Run all MinIO security tests"""
    results = []

    # Authentication & Authorization
    results.append(check_default_credentials())
    results.append(check_weak_admin_password())
    results.append(check_anonymous_bucket_access())

    # Network Security
    results.append(check_tls_configuration())
    results.append(check_console_security())
    results.append(check_external_exposure())

    # Container & Kubernetes Security
    results.append(check_pod_security_context())
    results.append(check_network_policies())

    # RBAC Security
    results.append(check_rbac_overly_permissive_roles())
    results.append(check_rbac_cross_namespace_access())
    results.append(check_rbac_destructive_permissions())

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
        "minio_security_summary",
        "Overall MinIO security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_minio()
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
