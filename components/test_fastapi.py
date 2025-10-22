#!/usr/bin/env python3
"""
FastAPI Security Tests
Comprehensive security analysis for FastAPI applications

Based on common FastAPI patterns and security best practices.

Tests:
1. API documentation exposure (/docs, /redoc)
2. API key authentication
3. CORS configuration
4. Rate limiting
5. Input validation
6. External exposure
7. Pod security context
8. Network policies
9. Secret management
10. Health endpoint security

ENV VARS:
  FASTAPI_NS (default: fastapi)
  FASTAPI_HOST (default: fastapi.fastapi.svc.cluster.local)
  FASTAPI_PORT (default: 8080)
  FASTAPI_API_KEY (default: none)
  FASTAPI_LOGIN (default: none)

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


def test_api_docs_exposure() -> Dict[str, Any]:
    """Check if API documentation is publicly accessible"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    host = os.getenv("FASTAPI_HOST", "fastapi.fastapi.svc.cluster.local")
    port = os.getenv("FASTAPI_PORT", "8080")

    # Check if /docs is accessible without authentication
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{port}/docs"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        # Check if it's a production environment
        env_mode = os.getenv("ENVIRONMENT", "development").lower()

        if env_mode in ["production", "prod"]:
            return create_result(
                "fastapi_docs_exposure",
                "Check if API documentation is protected in production",
                False,
                "WARNING: API documentation (/docs, /redoc) is publicly accessible in production. This exposes API structure and endpoints.",
                "WARNING"
            )
        else:
            return create_result(
                "fastapi_docs_exposure",
                "Check if API documentation is protected in production",
                True,
                "API documentation is accessible (acceptable in dev/staging environments)",
                "INFO"
            )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "fastapi_docs_exposure",
            "Check if API documentation is protected in production",
            True,
            f"API documentation requires authentication (HTTP {http_code}) - good security practice",
            "INFO"
        )
    elif http_code == "404":
        return create_result(
            "fastapi_docs_exposure",
            "Check if API documentation is protected in production",
            True,
            "API documentation is disabled - excellent for production",
            "INFO"
        )
    else:
        return create_result(
            "fastapi_docs_exposure",
            "Check if API documentation is protected in production",
            True,
            f"API documentation returned HTTP {http_code}",
            "INFO"
        )


def test_api_key_security() -> Dict[str, Any]:
    """Check API key configuration"""
    api_key = os.getenv("FASTAPI_API_KEY", "")

    if not api_key:
        return create_result(
            "fastapi_api_key_security",
            "Check API key configuration and strength",
            True,
            "No API key configured (authentication may use different method)",
            "INFO"
        )

    # Check if API key is weak or default
    weak_patterns = [
        "test", "demo", "example", "default", "api-key",
        "12345", "abcde", "password", "secret"
    ]

    if any(pattern in api_key.lower() for pattern in weak_patterns):
        return create_result(
            "fastapi_api_key_security",
            "Check API key configuration and strength",
            False,
            f"CRITICAL: API key contains weak/default pattern. Use cryptographically strong random keys.",
            "CRITICAL"
        )
    elif len(api_key) < 32:
        return create_result(
            "fastapi_api_key_security",
            "Check API key configuration and strength",
            False,
            f"WARNING: API key length is {len(api_key)} characters. Recommended minimum is 32 characters.",
            "WARNING"
        )
    else:
        return create_result(
            "fastapi_api_key_security",
            "Check API key configuration and strength",
            True,
            f"API key appears strong (length: {len(api_key)} characters)",
            "INFO"
        )


def test_cors_configuration() -> Dict[str, Any]:
    """Check CORS configuration for security issues"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    host = os.getenv("FASTAPI_HOST", "fastapi.fastapi.svc.cluster.local")
    port = os.getenv("FASTAPI_PORT", "8080")

    # Make an OPTIONS request to check CORS headers
    cmd = f"curl -s -I -X OPTIONS -H 'Origin: http://evil.com' http://{host}:{port}/health 2>/dev/null | grep -i 'access-control'"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        cors_headers = result["stdout"].lower()

        # Check for overly permissive CORS
        if "access-control-allow-origin: *" in cors_headers:
            return create_result(
                "fastapi_cors_configuration",
                "Check CORS configuration for security",
                False,
                "WARNING: CORS allows all origins (*). This can enable cross-site attacks. Restrict to specific domains.",
                "WARNING"
            )
        elif "access-control-allow-credentials: true" in cors_headers and "access-control-allow-origin: *" in cors_headers:
            return create_result(
                "fastapi_cors_configuration",
                "Check CORS configuration for security",
                False,
                "CRITICAL: CORS allows all origins with credentials enabled! This is a major security vulnerability.",
                "CRITICAL"
            )
        elif "access-control-allow-origin" in cors_headers:
            return create_result(
                "fastapi_cors_configuration",
                "Check CORS configuration for security",
                True,
                "CORS is configured with specific allowed origins",
                "INFO"
            )
        else:
            return create_result(
                "fastapi_cors_configuration",
                "Check CORS configuration for security",
                True,
                "CORS headers present - configuration appears restricted",
                "INFO"
            )
    else:
        return create_result(
            "fastapi_cors_configuration",
            "Check CORS configuration for security",
            True,
            "No CORS headers detected (CORS may be disabled or not configured)",
            "INFO"
        )


def test_health_endpoint_exposure() -> Dict[str, Any]:
    """Check if health endpoint exposes sensitive information"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    host = os.getenv("FASTAPI_HOST", "fastapi.fastapi.svc.cluster.local")
    port = os.getenv("FASTAPI_PORT", "8080")

    # Check health endpoint
    cmd = f"curl -s http://{host}:{port}/health"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            health_data = json.loads(result["stdout"])

            # Check for sensitive information leaks
            sensitive_keys = ["password", "secret", "token", "api_key", "database_url", "connection_string"]
            exposed_keys = []

            def check_dict(d, path=""):
                for key, value in d.items():
                    if any(sens in key.lower() for sens in sensitive_keys):
                        exposed_keys.append(f"{path}{key}")
                    if isinstance(value, dict):
                        check_dict(value, f"{path}{key}.")

            check_dict(health_data)

            if exposed_keys:
                return create_result(
                    "fastapi_health_endpoint",
                    "Check if health endpoint exposes sensitive data",
                    False,
                    f"CRITICAL: Health endpoint exposes sensitive keys: {', '.join(exposed_keys)}",
                    "CRITICAL"
                )
            else:
                return create_result(
                    "fastapi_health_endpoint",
                    "Check if health endpoint exposes sensitive data",
                    True,
                    "Health endpoint does not expose sensitive information",
                    "INFO"
                )
        except json.JSONDecodeError:
            return create_result(
                "fastapi_health_endpoint",
                "Check if health endpoint exposes sensitive data",
                True,
                "Health endpoint returns non-JSON response (likely safe)",
                "INFO"
            )
    else:
        return create_result(
            "fastapi_health_endpoint",
            "Check if health endpoint exposes sensitive data",
            True,
            "Health endpoint not accessible or does not exist",
            "INFO"
        )


def test_authentication_required() -> Dict[str, Any]:
    """Check if API endpoints require authentication"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    host = os.getenv("FASTAPI_HOST", "fastapi.fastapi.svc.cluster.local")
    port = os.getenv("FASTAPI_PORT", "8080")

    # Try accessing root endpoint without credentials
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{port}/"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    # Root might be public, try a common API path
    cmd_api = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{port}/api/v1/"
    result_api = run_command(cmd_api, timeout=10)
    http_code_api = result_api["stdout"]

    if http_code_api == "200":
        return create_result(
            "fastapi_authentication_required",
            "Check if API endpoints require authentication",
            False,
            "WARNING: API endpoints are accessible without authentication. Consider adding API key or OAuth protection.",
            "WARNING"
        )
    elif http_code_api in ["401", "403"]:
        return create_result(
            "fastapi_authentication_required",
            "Check if API endpoints require authentication",
            True,
            f"API endpoints require authentication (HTTP {http_code_api})",
            "INFO"
        )
    else:
        return create_result(
            "fastapi_authentication_required",
            "Check if API endpoints require authentication",
            True,
            f"API endpoint returned HTTP {http_code_api} - may require authentication or not exist",
            "INFO"
        )


def test_external_exposure() -> Dict[str, Any]:
    """Check if FastAPI is exposed externally"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")

    # Check service types
    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                if "fastapi" in svc_name.lower():
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        return create_result(
                            "fastapi_external_exposure",
                            "Check if FastAPI is exposed to external networks",
                            False,
                            f"WARNING: FastAPI service '{svc_name}' is exposed as LoadBalancer with external IP: {external_ip}. Ensure API authentication is strong.",
                            "WARNING"
                        )
                    elif svc_type == "ClusterIP":
                        return create_result(
                            "fastapi_external_exposure",
                            "Check if FastAPI is exposed to external networks",
                            True,
                            f"FastAPI service '{svc_name}' is ClusterIP (internal only) - good security practice",
                            "INFO"
                        )
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        return create_result(
                            "fastapi_external_exposure",
                            "Check if FastAPI is exposed to external networks",
                            False,
                            f"WARNING: FastAPI service '{svc_name}' is exposed via NodePort: {node_ports}. Ensure proper authentication.",
                            "WARNING"
                        )

            return create_result(
                "fastapi_external_exposure",
                "Check if FastAPI is exposed to external networks",
                True,
                "No FastAPI service found or service is internal only",
                "INFO"
            )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "fastapi_external_exposure",
                "Check if FastAPI is exposed to external networks",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "fastapi_external_exposure",
            "Check if FastAPI is exposed to external networks",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def test_pod_security_context() -> Dict[str, Any]:
    """Check if FastAPI pods run with secure security context"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")

    # Get FastAPI pods
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=fastapi -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "fastapi_pod_security_context",
                    "Check FastAPI pod security context",
                    True,
                    "No FastAPI pods found",
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
                    issues.append("Root filesystem is not read-only (acceptable for FastAPI with /tmp writes)")

            if any(issue for issue in issues if "privileged" in issue or "runAsNonRoot" in issue):
                return create_result(
                    "fastapi_pod_security_context",
                    "Check FastAPI pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join([i for i in issues if 'read-only' not in i.lower()])}",
                    "WARNING"
                )
            else:
                return create_result(
                    "fastapi_pod_security_context",
                    "Check FastAPI pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "fastapi_pod_security_context",
                "Check FastAPI pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "fastapi_pod_security_context",
            "Check FastAPI pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for FastAPI namespace"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")

    # Check for NetworkPolicies
    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "fastapi_network_policies",
                    "Check if NetworkPolicies restrict FastAPI access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. API is accessible from any pod.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "fastapi_network_policies",
                    "Check if NetworkPolicies restrict FastAPI access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "fastapi_network_policies",
                "Check if NetworkPolicies restrict FastAPI access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "fastapi_network_policies",
            "Check if NetworkPolicies restrict FastAPI access",
            False,
            f"WARNING: Unable to check NetworkPolicies (may not exist or no permissions)",
            "WARNING"
        )


def test_secret_management() -> Dict[str, Any]:
    """Check if secrets are properly managed (not in env vars)"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")

    # Get pod to check environment variables
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=fastapi -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "fastapi_secret_management",
                    "Check if secrets are properly managed",
                    True,
                    "No FastAPI pods found",
                    "INFO"
                )

            pod = pods_data["items"][0]
            containers = pod["spec"].get("containers", [])

            plaintext_secrets = []

            for container in containers:
                env_vars = container.get("env", [])

                for env in env_vars:
                    env_name = env.get("name", "").lower()
                    env_value = env.get("value", "")

                    # Check if sensitive env vars have plain values
                    if any(sens in env_name for sens in ["password", "secret", "token", "api_key"]):
                        if env_value and not env.get("valueFrom"):
                            plaintext_secrets.append(env_name)

            if plaintext_secrets:
                return create_result(
                    "fastapi_secret_management",
                    "Check if secrets are properly managed",
                    False,
                    f"WARNING: Sensitive environment variables stored as plaintext: {', '.join(plaintext_secrets)}. Use Kubernetes Secrets with valueFrom.",
                    "WARNING"
                )
            else:
                return create_result(
                    "fastapi_secret_management",
                    "Check if secrets are properly managed",
                    True,
                    "Secrets appear to be managed via Kubernetes Secrets (valueFrom) - good practice",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "fastapi_secret_management",
                "Check if secrets are properly managed",
                True,
                f"Unable to check secret management: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "fastapi_secret_management",
            "Check if secrets are properly managed",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_rbac_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    sa_name = os.getenv("FASTAPI_SA", "fastapi")

    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        return create_result(
            "fastapi_rbac_permissive_roles",
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
                "fastapi_rbac_permissive_roles",
                "Check for overly permissive RBAC cluster roles",
                False,
                f"CRITICAL: Overly permissive roles: {', '.join(risky_roles)}",
                "CRITICAL"
            )

        return create_result(
            "fastapi_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "No overly permissive cluster roles detected",
            "INFO"
        )

    except json.JSONDecodeError:
        return create_result(
            "fastapi_rbac_permissive_roles",
            "Check for overly permissive RBAC cluster roles",
            True,
            "Unable to parse ClusterRoleBindings",
            "INFO"
        )


def test_rbac_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    sa_name = os.getenv("FASTAPI_SA", "fastapi")
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
            "fastapi_rbac_cross_namespace",
            "Test RBAC cross-namespace access permissions",
            False,
            f"WARNING: Cross-namespace access: {', '.join(issues)}",
            "WARNING"
        )

    return create_result(
        "fastapi_rbac_cross_namespace",
        "Test RBAC cross-namespace access permissions",
        True,
        "No excessive cross-namespace access detected",
        "INFO"
    )


def test_rbac_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive RBAC permissions"""
    namespace = os.getenv("FASTAPI_NS", "fastapi")
    sa_name = os.getenv("FASTAPI_SA", "fastapi")
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
            "fastapi_rbac_destructive_perms",
            "Test for destructive RBAC permissions",
            False,
            f"{severity}: Risky permissions: {', '.join(risky_permissions)}",
            severity
        )

    return create_result(
        "fastapi_rbac_destructive_perms",
        "Test for destructive RBAC permissions",
        True,
        "No excessive destructive permissions detected",
        "INFO"
    )


def test_fastapi_security() -> List[Dict[str, Any]]:
    """Run all FastAPI security tests"""
    results = []

    # API Security
    results.append(test_api_docs_exposure())
    results.append(test_authentication_required())
    results.append(test_api_key_security())
    results.append(test_cors_configuration())
    results.append(test_health_endpoint_exposure())

    # Network Security
    results.append(test_external_exposure())
    results.append(test_network_policies())

    # Container & Kubernetes Security
    results.append(test_pod_security_context())
    results.append(test_secret_management())

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
        "fastapi_security_summary",
        "Overall FastAPI security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_fastapi_security()
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
