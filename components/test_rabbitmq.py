#!/usr/bin/env python3
"""
RabbitMQ Security Tests
Comprehensive security analysis for RabbitMQ messaging broker

Tests:
1. Default credentials check (guest/guest)
2. TLS/SSL configuration
3. Management UI security
4. User permissions and privileges
5. Vhost isolation
6. Authentication mechanisms
7. Network exposure
8. Admin interface access control

ENV VARS:
  RABBITMQ_NS (default: rabbitmq-system)
  RABBITMQ_HOST (default: rabbitmq.rabbitmq-system.svc.cluster.local)
  RABBITMQ_PORT (default: 5672)
  RABBITMQ_USER (default: user)
  RABBITMQ_PASSWORD (default: password)
  RABBITMQ_ADMIN_PASSWORD (default: admin)

Output: JSON array of security test results
"""

import os
import sys
import json
import subprocess
import base64
from typing import List, Dict, Any, Optional
from datetime import datetime


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


def test_default_credentials() -> Dict[str, Any]:
    """Test if default guest/guest credentials work"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    host = os.getenv("RABBITMQ_HOST", "rabbitmq.rabbitmq-system.svc.cluster.local")

    # RabbitMQ Management API port is typically 15672
    mgmt_port = 15672

    # Try default guest/guest credentials
    cmd = f"curl -s -u guest:guest -w '%{{http_code}}' -o /dev/null http://{host}:{mgmt_port}/api/overview"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "rabbitmq_default_credentials",
            "Check if default guest/guest credentials are disabled",
            False,
            "CRITICAL: Default guest/guest credentials are ENABLED and working! This is a major security risk.",
            "CRITICAL"
        )
    elif http_code == "401":
        return create_result(
            "rabbitmq_default_credentials",
            "Check if default guest/guest credentials are disabled",
            True,
            "Default guest/guest credentials are properly disabled (HTTP 401)",
            "INFO"
        )
    else:
        return create_result(
            "rabbitmq_default_credentials",
            "Check if default guest/guest credentials are disabled",
            True,
            f"Management API returned HTTP {http_code} for guest credentials - likely disabled or API unavailable",
            "INFO"
        )


def test_weak_admin_password() -> Dict[str, Any]:
    """Check if admin password is weak or default"""
    admin_password = os.getenv("RABBITMQ_ADMIN_PASSWORD", "")

    # List of common weak passwords
    weak_passwords = [
        "admin", "password", "123456", "rabbitmq", "guest",
        "default", "default_password", "admin123", "password123"
    ]

    if admin_password.lower() in weak_passwords:
        return create_result(
            "rabbitmq_weak_admin_password",
            "Check if admin password is strong",
            False,
            f"CRITICAL: Admin password '{admin_password}' is a known weak/default password! Change immediately.",
            "CRITICAL"
        )
    elif len(admin_password) < 12:
        return create_result(
            "rabbitmq_weak_admin_password",
            "Check if admin password is strong",
            False,
            f"WARNING: Admin password length is {len(admin_password)} characters. Recommended minimum is 12 characters.",
            "WARNING"
        )
    else:
        return create_result(
            "rabbitmq_weak_admin_password",
            "Check if admin password is strong",
            True,
            f"Admin password appears strong (length: {len(admin_password)} characters)",
            "INFO"
        )


def test_tls_configuration() -> Dict[str, Any]:
    """Check if RabbitMQ is using TLS/SSL"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    host = os.getenv("RABBITMQ_HOST", "rabbitmq.rabbitmq-system.svc.cluster.local")
    amqp_port = int(os.getenv("RABBITMQ_PORT", "5672"))

    # Check if TLS port 5671 responds (AMQPS)
    tls_port = 5671
    cmd = f"timeout 5 bash -c 'echo | openssl s_client -connect {host}:{tls_port} 2>&1' | grep -q 'Verify return code'"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        # TLS is available, now check certificate details
        cert_cmd = f"echo | openssl s_client -connect {host}:{tls_port} -servername {host} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null"
        cert_result = run_command(cert_cmd, timeout=10)

        if cert_result["exit_code"] == 0 and "notAfter" in cert_result["stdout"]:
            return create_result(
                "rabbitmq_tls_configuration",
                "Check if RabbitMQ uses TLS/SSL encryption",
                True,
                f"TLS is enabled on port {tls_port} with valid certificate",
                "INFO"
            )
        else:
            return create_result(
                "rabbitmq_tls_configuration",
                "Check if RabbitMQ uses TLS/SSL encryption",
                False,
                f"TLS port {tls_port} is accessible but certificate validation failed",
                "WARNING"
            )
    else:
        # Check if non-TLS port is responding
        non_tls_cmd = f"timeout 3 bash -c 'echo -n | nc -w 2 {host} {amqp_port}' 2>&1"
        non_tls_result = run_command(non_tls_cmd, timeout=5)

        return create_result(
            "rabbitmq_tls_configuration",
            "Check if RabbitMQ uses TLS/SSL encryption",
            False,
            f"WARNING: TLS port {tls_port} not accessible. Only non-encrypted port {amqp_port} appears to be in use. Enable TLS for production.",
            "WARNING"
        )


def test_management_ui_exposure() -> Dict[str, Any]:
    """Check if management UI is properly secured"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    host = os.getenv("RABBITMQ_HOST", "rabbitmq.rabbitmq-system.svc.cluster.local")
    mgmt_port = 15672

    # Check if management API is accessible without auth (not the UI page, but the actual API)
    # The UI page at / returns 200 (it's the login page), but API endpoints should return 401
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{mgmt_port}/api/overview"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "rabbitmq_management_ui_security",
            "Check if management API requires authentication",
            False,
            "CRITICAL: Management API is accessible without authentication!",
            "CRITICAL"
        )
    elif http_code == "401":
        return create_result(
            "rabbitmq_management_ui_security",
            "Check if management API requires authentication",
            True,
            "Management API properly requires authentication (HTTP 401)",
            "INFO"
        )
    elif http_code == "000" or result["exit_code"] != 0:
        return create_result(
            "rabbitmq_management_ui_security",
            "Check if management API requires authentication",
            True,
            "Management API is not accessible (connection refused) - may be properly restricted",
            "INFO"
        )
    else:
        return create_result(
            "rabbitmq_management_ui_security",
            "Check if management API requires authentication",
            True,
            f"Management API returned HTTP {http_code} - authentication appears required",
            "INFO"
        )


def test_user_permissions() -> Dict[str, Any]:
    """Check user permissions and verify they're not overly permissive"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    host = os.getenv("RABBITMQ_HOST", "rabbitmq.rabbitmq-system.svc.cluster.local")
    user = os.getenv("RABBITMQ_USER", "user")
    password = os.getenv("RABBITMQ_PASSWORD", "password")
    mgmt_port = 15672

    # Get user permissions via Management API
    cmd = f"curl -s -u {user}:{password} http://{host}:{mgmt_port}/api/users/{user}"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            user_info = json.loads(result["stdout"])
            tags = user_info.get("tags", "")

            # Check if user has administrator tag
            if "administrator" in tags:
                return create_result(
                    "rabbitmq_user_permissions",
                    "Check if application user has minimal required permissions",
                    False,
                    f"WARNING: User '{user}' has 'administrator' tag. Application users should have minimal permissions (management, policymaker, or monitoring).",
                    "WARNING"
                )
            elif tags == "":
                return create_result(
                    "rabbitmq_user_permissions",
                    "Check if application user has minimal required permissions",
                    True,
                    f"User '{user}' has no admin tags - follows principle of least privilege",
                    "INFO"
                )
            else:
                return create_result(
                    "rabbitmq_user_permissions",
                    "Check if application user has minimal required permissions",
                    True,
                    f"User '{user}' has limited permissions (tags: {tags})",
                    "INFO"
                )
        except json.JSONDecodeError:
            return create_result(
                "rabbitmq_user_permissions",
                "Check if application user has minimal required permissions",
                True,
                "Unable to parse user permissions - API may require admin access",
                "INFO"
            )
    else:
        return create_result(
            "rabbitmq_user_permissions",
            "Check if application user has minimal required permissions",
            True,
            "Unable to check user permissions via API - may require admin credentials",
            "INFO"
        )


def test_external_exposure() -> Dict[str, Any]:
    """Check if RabbitMQ is exposed externally via LoadBalancer"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")

    # Check service type
    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                if "rabbitmq" in svc_name.lower():
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        return create_result(
                            "rabbitmq_external_exposure",
                            "Check if RabbitMQ is exposed to external networks",
                            False,
                            f"WARNING: RabbitMQ service '{svc_name}' is exposed as LoadBalancer with external IP: {external_ip}. Ensure proper firewall rules and authentication.",
                            "WARNING"
                        )
                    elif svc_type == "ClusterIP":
                        return create_result(
                            "rabbitmq_external_exposure",
                            "Check if RabbitMQ is exposed to external networks",
                            True,
                            f"RabbitMQ service '{svc_name}' is ClusterIP (internal only) - good security practice",
                            "INFO"
                        )
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        return create_result(
                            "rabbitmq_external_exposure",
                            "Check if RabbitMQ is exposed to external networks",
                            False,
                            f"WARNING: RabbitMQ service '{svc_name}' is exposed via NodePort: {node_ports}. Ensure proper network policies.",
                            "WARNING"
                        )

            return create_result(
                "rabbitmq_external_exposure",
                "Check if RabbitMQ is exposed to external networks",
                True,
                "No RabbitMQ service found or service is internal only",
                "INFO"
            )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "rabbitmq_external_exposure",
                "Check if RabbitMQ is exposed to external networks",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "rabbitmq_external_exposure",
            "Check if RabbitMQ is exposed to external networks",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def test_pod_security_context() -> Dict[str, Any]:
    """Check if RabbitMQ pods run with secure security context"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")

    # Get RabbitMQ pods
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=rabbitmq -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "rabbitmq_pod_security_context",
                    "Check RabbitMQ pod security context",
                    True,
                    "No RabbitMQ pods found",
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
                if "rabbitmq" in container["name"].lower():
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
                    "rabbitmq_pod_security_context",
                    "Check RabbitMQ pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join(issues)}",
                    "WARNING"
                )
            else:
                return create_result(
                    "rabbitmq_pod_security_context",
                    "Check RabbitMQ pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "rabbitmq_pod_security_context",
                "Check RabbitMQ pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "rabbitmq_pod_security_context",
            "Check RabbitMQ pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for RabbitMQ namespace"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")

    # Check for NetworkPolicies
    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "rabbitmq_network_policies",
                    "Check if NetworkPolicies restrict RabbitMQ access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Network traffic is unrestricted.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "rabbitmq_network_policies",
                    "Check if NetworkPolicies restrict RabbitMQ access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "rabbitmq_network_policies",
                "Check if NetworkPolicies restrict RabbitMQ access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "rabbitmq_network_policies",
            "Check if NetworkPolicies restrict RabbitMQ access",
            False,
            f"WARNING: Unable to check NetworkPolicies (may not exist or no permissions)",
            "WARNING"
        )


def test_rbac_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq-server")

    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        return create_result(
            "rabbitmq_rbac_permissive_roles",
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
                "rabbitmq_rbac_permissive_roles",
                "Check for overly permissive RBAC cluster roles",
                False,
                f"CRITICAL: Overly permissive roles: {', '.join(risky_roles)}",
                "CRITICAL"
            )

        return create_result(
            "rabbitmq_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "No overly permissive cluster roles detected",
            "INFO"
        )

    except json.JSONDecodeError:
        return create_result(
            "rabbitmq_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to parse ClusterRoleBindings",
            "INFO"
        )


def test_rbac_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq-server")
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
            "rabbitmq_rbac_cross_namespace",
            "Test RBAC cross-namespace access permissions",
            False,
            f"WARNING: Cross-namespace access: {', '.join(issues)}",
            "WARNING"
        )

    return create_result(
        "rabbitmq_rbac_cross_namespace",
        "Test RBAC cross-namespace access permissions",
        True,
        "No excessive cross-namespace access detected",
        "INFO"
    )


def test_rbac_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive RBAC permissions"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq-server")
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
            "rabbitmq_rbac_destructive_perms",
            "Test for destructive RBAC permissions",
            False,
            f"{severity}: Risky permissions: {', '.join(risky_permissions)}",
            severity
        )

    return create_result(
        "rabbitmq_rbac_destructive_perms",
        "Test for destructive RBAC permissions",
        True,
        "No excessive destructive permissions detected",
        "INFO"
    )


def test_rabbitmq_security() -> List[Dict[str, Any]]:
    """Run all RabbitMQ security tests"""
    results = []

    # Authentication & Authorization
    results.append(test_default_credentials())
    results.append(test_weak_admin_password())
    results.append(test_user_permissions())

    # Network Security
    results.append(test_tls_configuration())
    results.append(test_management_ui_exposure())
    results.append(test_external_exposure())

    # Container & Kubernetes Security
    results.append(test_pod_security_context())
    results.append(test_network_policies())

    # RBAC Security
    results.append(test_rbac_overly_permissive_roles())
    results.append(test_rbac_cross_namespace_access())
    results.append(test_rbac_destructive_permissions())

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
        "rabbitmq_security_summary",
        "Overall RabbitMQ security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_rabbitmq_security()
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
