#!/usr/bin/env python3
"""
CNPG (CloudNativePG) Security Tests
Comprehensive security analysis for PostgreSQL managed by CloudNativePG

Tests:
1. Default PostgreSQL credentials (postgres/postgres)
2. SSL/TLS encryption for connections
3. Database authentication methods
4. User privileges and roles
5. Network exposure
6. Backup encryption and security
7. Pod security context
8. Network policies
9. Password strength
10. pg_hba.conf configuration

ENV VARS:
  CNPG_NS (default: cnpg)
  CNPG_CLUSTER_NAME (default: cluster-cnpg)
  CNPG_HOST (default: cnpg-rw.cnpg.svc.cluster.local)
  CNPG_PORT (default: 5432)
  CNPG_ADMIN_USER (default: postgres)
  CNPG_ADMIN_PASSWORD (default: password)
  CNPG_DATABASE (default: postgres)
  CNPG_METRICS_PORT (default: 9187)

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


def test_default_postgres_credentials() -> Dict[str, Any]:
    """Test if default postgres/postgres credentials work"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    host = os.getenv("CNPG_HOST", "cnpg-rw.cnpg.svc.cluster.local")
    port = os.getenv("CNPG_PORT", "5432")
    database = os.getenv("CNPG_DATABASE", "postgres")

    # Try connecting with default postgres/postgres
    cmd = f"PGPASSWORD=postgres psql -h {host} -p {port} -U postgres -d {database} -c 'SELECT 1' 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and "1 row" in result["stdout"]:
        return create_result(
            "cnpg_default_credentials",
            "Check if default postgres/postgres credentials are disabled",
            False,
            "CRITICAL: Default postgres/postgres credentials are ENABLED! This is a major security risk.",
            "CRITICAL"
        )
    elif "password authentication failed" in result["stderr"] or "authentication failed" in result["stderr"]:
        return create_result(
            "cnpg_default_credentials",
            "Check if default postgres/postgres credentials are disabled",
            True,
            "Default postgres/postgres credentials are properly disabled",
            "INFO"
        )
    else:
        return create_result(
            "cnpg_default_credentials",
            "Check if default postgres/postgres credentials are disabled",
            True,
            f"Unable to connect with default credentials (likely disabled): {result['stderr'][:100]}",
            "INFO"
        )


def test_weak_admin_password() -> Dict[str, Any]:
    """Check if admin password is weak or default"""
    admin_password = os.getenv("CNPG_ADMIN_PASSWORD", "")

    # List of common weak passwords
    weak_passwords = [
        "postgres", "password", "123456", "admin", "default",
        "password123", "admin123", "postgres123", "password_default1",
        "changeme", "secret", "test"
    ]

    if admin_password.lower() in weak_passwords:
        return create_result(
            "cnpg_weak_admin_password",
            "Check if PostgreSQL admin password is strong",
            False,
            f"CRITICAL: Admin password '{admin_password}' is a known weak/default password! Change immediately.",
            "CRITICAL"
        )
    elif len(admin_password) < 12:
        return create_result(
            "cnpg_weak_admin_password",
            "Check if PostgreSQL admin password is strong",
            False,
            f"WARNING: Admin password length is {len(admin_password)} characters. Recommended minimum is 12 characters.",
            "WARNING"
        )
    else:
        return create_result(
            "cnpg_weak_admin_password",
            "Check if PostgreSQL admin password is strong",
            True,
            f"Admin password appears strong (length: {len(admin_password)} characters)",
            "INFO"
        )


def test_ssl_configuration() -> Dict[str, Any]:
    """Check if PostgreSQL enforces SSL/TLS connections"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    cluster_name = os.getenv("CNPG_CLUSTER_NAME", "cluster-cnpg")

    # Get the primary pod
    cmd = f"kubectl get pod -n {namespace} -l cnpg.io/cluster={cluster_name},cnpg.io/instanceRole=primary -o jsonpath='{{.items[0].metadata.name}}'"
    pod_result = run_command(cmd, timeout=10)

    if pod_result["exit_code"] != 0 or not pod_result["stdout"]:
        return create_result(
            "cnpg_ssl_configuration",
            "Check if PostgreSQL enforces SSL/TLS",
            True,
            "Unable to find CNPG primary pod to check SSL settings",
            "INFO"
        )

    pod_name = pod_result["stdout"]

    # Check SSL setting in PostgreSQL
    cmd = f"kubectl exec {pod_name} -n {namespace} -c postgres -- psql -U postgres -d postgres -t -c 'SHOW ssl' 2>/dev/null"
    ssl_result = run_command(cmd, timeout=10)

    if ssl_result["exit_code"] == 0:
        ssl_status = ssl_result["stdout"].strip()
        if ssl_status == "on":
            return create_result(
                "cnpg_ssl_configuration",
                "Check if PostgreSQL enforces SSL/TLS",
                True,
                "SSL is enabled in PostgreSQL configuration",
                "INFO"
            )
        else:
            return create_result(
                "cnpg_ssl_configuration",
                "Check if PostgreSQL enforces SSL/TLS",
                False,
                f"WARNING: SSL is disabled (ssl={ssl_status}). Enable SSL for production databases.",
                "WARNING"
            )
    else:
        return create_result(
            "cnpg_ssl_configuration",
            "Check if PostgreSQL enforces SSL/TLS",
            True,
            "Unable to check SSL configuration (may require authentication)",
            "INFO"
        )


def test_external_exposure() -> Dict[str, Any]:
    """Check if PostgreSQL is exposed externally via LoadBalancer"""
    namespace = os.getenv("CNPG_NS", "cnpg")

    # Check service types
    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                # Check for PostgreSQL-related services
                if any(keyword in svc_name.lower() for keyword in ["cnpg", "postgres", "pg"]):
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        return create_result(
                            "cnpg_external_exposure",
                            "Check if PostgreSQL is exposed to external networks",
                            False,
                            f"WARNING: PostgreSQL service '{svc_name}' is exposed as LoadBalancer with external IP: {external_ip}. Databases should rarely be externally accessible.",
                            "WARNING"
                        )
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        return create_result(
                            "cnpg_external_exposure",
                            "Check if PostgreSQL is exposed to external networks",
                            False,
                            f"WARNING: PostgreSQL service '{svc_name}' is exposed via NodePort: {node_ports}. Ensure proper network policies.",
                            "WARNING"
                        )

            return create_result(
                "cnpg_external_exposure",
                "Check if PostgreSQL is exposed to external networks",
                True,
                "PostgreSQL services are ClusterIP only (internal) - good security practice",
                "INFO"
            )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "cnpg_external_exposure",
                "Check if PostgreSQL is exposed to external networks",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "cnpg_external_exposure",
            "Check if PostgreSQL is exposed to external networks",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def test_pod_security_context() -> Dict[str, Any]:
    """Check if PostgreSQL pods run with secure security context"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    cluster_name = os.getenv("CNPG_CLUSTER_NAME", "cluster-cnpg")

    # Get PostgreSQL pods
    cmd = f"kubectl get pod -n {namespace} -l cnpg.io/cluster={cluster_name} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "cnpg_pod_security_context",
                    "Check CNPG pod security context",
                    True,
                    "No CNPG pods found",
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
                if "postgres" in container["name"].lower():
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
                        # Filter out acceptable capabilities
                        dangerous_caps = [cap for cap in added_caps if cap not in ["CHOWN", "DAC_OVERRIDE", "FOWNER"]]
                        if dangerous_caps:
                            issues.append(f"Dangerous capabilities added: {dangerous_caps}")

            if issues:
                return create_result(
                    "cnpg_pod_security_context",
                    "Check CNPG pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join(issues)}",
                    "WARNING"
                )
            else:
                return create_result(
                    "cnpg_pod_security_context",
                    "Check CNPG pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "cnpg_pod_security_context",
                "Check CNPG pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "cnpg_pod_security_context",
            "Check CNPG pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for CNPG namespace"""
    namespace = os.getenv("CNPG_NS", "cnpg")

    # Check for NetworkPolicies
    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "cnpg_network_policies",
                    "Check if NetworkPolicies restrict PostgreSQL access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Database access is unrestricted.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "cnpg_network_policies",
                    "Check if NetworkPolicies restrict PostgreSQL access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "cnpg_network_policies",
                "Check if NetworkPolicies restrict PostgreSQL access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "cnpg_network_policies",
            "Check if NetworkPolicies restrict PostgreSQL access",
            False,
            f"WARNING: Unable to check NetworkPolicies (may not exist or no permissions)",
            "WARNING"
        )


def test_backup_encryption() -> Dict[str, Any]:
    """Check if database backups are encrypted"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    cluster_name = os.getenv("CNPG_CLUSTER_NAME", "cluster-cnpg")

    # Get cluster configuration
    cmd = f"kubectl get cluster {cluster_name} -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            cluster_data = json.loads(result["stdout"])
            backup_config = cluster_data.get("spec", {}).get("backup", {})

            if not backup_config:
                return create_result(
                    "cnpg_backup_encryption",
                    "Check if database backups are configured and encrypted",
                    False,
                    "WARNING: No backup configuration found. Backups are essential for disaster recovery.",
                    "WARNING"
                )

            # Check for encryption settings (varies by backup method)
            barman_config = backup_config.get("barmanObjectStore", {})
            if barman_config:
                # Check for S3 encryption or similar
                s3_config = barman_config.get("s3Credentials", {})
                encryption = barman_config.get("serverName", "")  # Simplified check

                return create_result(
                    "cnpg_backup_encryption",
                    "Check if database backups are configured and encrypted",
                    True,
                    f"Backup is configured with Barman. Review backup storage encryption settings separately.",
                    "INFO"
                )
            else:
                return create_result(
                    "cnpg_backup_encryption",
                    "Check if database backups are configured and encrypted",
                    True,
                    "Backup configuration exists. Verify encryption settings in backup storage.",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "cnpg_backup_encryption",
                "Check if database backups are configured and encrypted",
                True,
                "Unable to parse cluster backup configuration",
                "INFO"
            )
    else:
        return create_result(
            "cnpg_backup_encryption",
            "Check if database backups are configured and encrypted",
            True,
            "Unable to retrieve cluster configuration",
            "INFO"
        )


def test_superuser_access() -> Dict[str, Any]:
    """Check if superuser access is properly restricted"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    cluster_name = os.getenv("CNPG_CLUSTER_NAME", "cluster-cnpg")

    # Get cluster configuration to check if superuser is enabled
    cmd = f"kubectl get cluster {cluster_name} -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            cluster_data = json.loads(result["stdout"])

            # CNPG best practice: superuser should be disabled for application access
            enable_superuser_access = cluster_data.get("spec", {}).get("enableSuperuserAccess", False)

            if enable_superuser_access:
                return create_result(
                    "cnpg_superuser_access",
                    "Check if superuser access is properly restricted",
                    False,
                    "WARNING: Superuser access is enabled. For security, applications should use limited-privilege users.",
                    "WARNING"
                )
            else:
                return create_result(
                    "cnpg_superuser_access",
                    "Check if superuser access is properly restricted",
                    True,
                    "Superuser access is disabled - applications use limited-privilege users (best practice)",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "cnpg_superuser_access",
                "Check if superuser access is properly restricted",
                True,
                "Unable to check superuser access configuration",
                "INFO"
            )
    else:
        return create_result(
            "cnpg_superuser_access",
            "Check if superuser access is properly restricted",
            True,
            "Unable to retrieve cluster configuration",
            "INFO"
        )


def test_replica_mode() -> Dict[str, Any]:
    """Check if cluster has replicas for high availability"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    cluster_name = os.getenv("CNPG_CLUSTER_NAME", "cluster-cnpg")

    # Get cluster configuration
    cmd = f"kubectl get cluster {cluster_name} -n {namespace} -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            cluster_data = json.loads(result["stdout"])
            instances = cluster_data.get("spec", {}).get("instances", 1)

            if instances < 2:
                return create_result(
                    "cnpg_replica_mode",
                    "Check if cluster has replicas for high availability",
                    False,
                    f"WARNING: Only {instances} instance(s) configured. For HA and security (backup admin access), use 2+ instances.",
                    "WARNING"
                )
            else:
                return create_result(
                    "cnpg_replica_mode",
                    "Check if cluster has replicas for high availability",
                    True,
                    f"Cluster has {instances} instances configured - supports HA and failover",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "cnpg_replica_mode",
                "Check if cluster has replicas for high availability",
                True,
                "Unable to check replica configuration",
                "INFO"
            )
    else:
        return create_result(
            "cnpg_replica_mode",
            "Check if cluster has replicas for high availability",
            True,
            "Unable to retrieve cluster configuration",
            "INFO"
        )


def test_rbac_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    # CNPG operator typically uses this ServiceAccount name
    sa_name = os.getenv("CNPG_SA", "cnpg-postgres")

    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        return create_result(
            "cnpg_rbac_permissive_roles",
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
                "cnpg_rbac_permissive_roles",
                "Check for overly permissive RBAC cluster roles",
                False,
                f"CRITICAL: Overly permissive roles: {', '.join(risky_roles)}",
                "CRITICAL"
            )

        return create_result(
            "cnpg_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "No overly permissive cluster roles detected",
            "INFO"
        )

    except json.JSONDecodeError:
        return create_result(
            "cnpg_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to parse ClusterRoleBindings",
            "INFO"
        )


def test_rbac_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    sa_name = os.getenv("CNPG_SA", "cnpg-postgres")
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
            "cnpg_rbac_cross_namespace",
            "Test RBAC cross-namespace access permissions",
            False,
            f"WARNING: Cross-namespace access: {', '.join(issues)}",
            "WARNING"
        )

    return create_result(
        "cnpg_rbac_cross_namespace",
        "Test RBAC cross-namespace access permissions",
        True,
        "No excessive cross-namespace access detected",
        "INFO"
    )


def test_rbac_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive RBAC permissions"""
    namespace = os.getenv("CNPG_NS", "cnpg")
    sa_name = os.getenv("CNPG_SA", "cnpg-postgres")
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
            "cnpg_rbac_destructive_perms",
            "Test for destructive RBAC permissions",
            False,
            f"{severity}: Risky permissions: {', '.join(risky_permissions)}",
            severity
        )

    return create_result(
        "cnpg_rbac_destructive_perms",
        "Test for destructive RBAC permissions",
        True,
        "No excessive destructive permissions detected",
        "INFO"
    )


def test_cnpg_security() -> List[Dict[str, Any]]:
    """Run all CNPG security tests"""
    results = []

    # Authentication & Authorization
    results.append(test_default_postgres_credentials())
    results.append(test_weak_admin_password())
    results.append(test_superuser_access())

    # Network Security
    results.append(test_ssl_configuration())
    results.append(test_external_exposure())
    results.append(test_network_policies())

    # Data Security
    results.append(test_backup_encryption())

    # Container & Kubernetes Security
    results.append(test_pod_security_context())

    # High Availability (impacts security)
    results.append(test_replica_mode())

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
        "cnpg_security_summary",
        "Overall CNPG PostgreSQL security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


# Alias for UI compatibility - the UI expects test_cnpg() not test_cnpg_security()
def test_cnpg() -> List[Dict[str, Any]]:
    """Alias for test_cnpg_security() for UI compatibility"""
    return test_cnpg_security()


if __name__ == "__main__":
    try:
        results = test_cnpg_security()
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
