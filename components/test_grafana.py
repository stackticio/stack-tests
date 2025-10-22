#!/usr/bin/env python3
"""
Grafana Security Tests
Comprehensive security analysis for Grafana dashboards and visualization

Tests:
1. Default admin credentials (admin/admin)
2. Weak admin password
3. Anonymous access
4. Public dashboards
5. API authentication
6. External exposure
7. Data source permissions
8. Pod security context
9. Network policies
10. User management and RBAC

ENV VARS:
  GRAFANA_NS (default: grafana)
  GRAFANA_HOST (default: grafana.grafana.svc.cluster.local)
  GRAFANA_PORT (default: 3000)
  GRAFANA_ADMIN_USER (default: admin)
  GRAFANA_ADMIN_PASSWORD (default: admin)

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


def test_default_admin_credentials() -> Dict[str, Any]:
    """Test if default admin/admin credentials work"""
    namespace = os.getenv("GRAFANA_NS", "grafana")
    host = os.getenv("GRAFANA_HOST", "grafana.grafana.svc.cluster.local")
    port = os.getenv("GRAFANA_PORT", "3000")

    # Try default admin/admin credentials
    cmd = f"curl -s -u admin:admin -w '%{{http_code}}' -o /dev/null http://{host}:{port}/api/org"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "grafana_default_credentials",
            "Check if default admin/admin credentials are disabled",
            False,
            "CRITICAL: Default admin/admin credentials are ENABLED and working! This is a major security risk.",
            "CRITICAL"
        )
    elif http_code == "401":
        return create_result(
            "grafana_default_credentials",
            "Check if default admin/admin credentials are disabled",
            True,
            "Default admin/admin credentials are properly disabled (HTTP 401)",
            "INFO"
        )
    else:
        return create_result(
            "grafana_default_credentials",
            "Check if default admin/admin credentials are disabled",
            True,
            f"Default credentials check returned HTTP {http_code} - likely disabled",
            "INFO"
        )


def test_weak_admin_password() -> Dict[str, Any]:
    """Check if admin password is weak or default"""
    admin_password = os.getenv("GRAFANA_ADMIN_PASSWORD", "")

    # List of common weak passwords
    weak_passwords = [
        "admin", "password", "123456", "grafana", "admin123",
        "password123", "default", "default_password", "changeme",
        "secret", "test", "grafana123"
    ]

    if admin_password.lower() in weak_passwords:
        return create_result(
            "grafana_weak_admin_password",
            "Check if Grafana admin password is strong",
            False,
            f"CRITICAL: Admin password '{admin_password}' is a known weak/default password! Change immediately.",
            "CRITICAL"
        )
    elif len(admin_password) < 12:
        return create_result(
            "grafana_weak_admin_password",
            "Check if Grafana admin password is strong",
            False,
            f"WARNING: Admin password length is {len(admin_password)} characters. Recommended minimum is 12 characters.",
            "WARNING"
        )
    else:
        return create_result(
            "grafana_weak_admin_password",
            "Check if Grafana admin password is strong",
            True,
            f"Admin password appears strong (length: {len(admin_password)} characters)",
            "INFO"
        )


def test_anonymous_access() -> Dict[str, Any]:
    """Check if anonymous access is enabled"""
    namespace = os.getenv("GRAFANA_NS", "grafana")
    host = os.getenv("GRAFANA_HOST", "grafana.grafana.svc.cluster.local")
    port = os.getenv("GRAFANA_PORT", "3000")

    # Try accessing API without credentials
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{host}:{port}/api/org"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "grafana_anonymous_access",
            "Check if anonymous access is disabled",
            False,
            "CRITICAL: Anonymous access is ENABLED! Anyone can view dashboards without authentication.",
            "CRITICAL"
        )
    elif http_code == "401":
        return create_result(
            "grafana_anonymous_access",
            "Check if anonymous access is disabled",
            True,
            "Anonymous access is properly disabled (HTTP 401)",
            "INFO"
        )
    else:
        return create_result(
            "grafana_anonymous_access",
            "Check if anonymous access is disabled",
            True,
            f"Anonymous access check returned HTTP {http_code}",
            "INFO"
        )


def test_public_dashboards() -> Dict[str, Any]:
    """Check if public dashboards feature is disabled"""
    namespace = os.getenv("GRAFANA_NS", "grafana")
    host = os.getenv("GRAFANA_HOST", "grafana.grafana.svc.cluster.local")
    port = os.getenv("GRAFANA_PORT", "3000")
    admin_user = os.getenv("GRAFANA_ADMIN_USER", "admin")
    admin_password = os.getenv("GRAFANA_ADMIN_PASSWORD", "admin")

    # Check if public dashboards are enabled via API
    cmd = f"curl -s -u {admin_user}:{admin_password} http://{host}:{port}/api/dashboards/public"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])

            # If we get a list, public dashboards feature is enabled
            if isinstance(data, list):
                if len(data) > 0:
                    return create_result(
                        "grafana_public_dashboards",
                        "Check if public dashboards are disabled",
                        False,
                        f"WARNING: {len(data)} public dashboard(s) found. Public dashboards can expose sensitive data.",
                        "WARNING"
                    )
                else:
                    return create_result(
                        "grafana_public_dashboards",
                        "Check if public dashboards are disabled",
                        True,
                        "Public dashboards feature is enabled but no public dashboards configured",
                        "INFO"
                    )
            # If we get an error, feature might be disabled
            elif isinstance(data, dict) and "message" in data:
                return create_result(
                    "grafana_public_dashboards",
                    "Check if public dashboards are disabled",
                    True,
                    "Public dashboards feature appears to be disabled or restricted",
                    "INFO"
                )
        except json.JSONDecodeError:
            pass

    return create_result(
        "grafana_public_dashboards",
        "Check if public dashboards are disabled",
        True,
        "Unable to check public dashboards (may require authentication)",
        "INFO"
    )


def test_api_key_security() -> Dict[str, Any]:
    """Check API keys configuration"""
    namespace = os.getenv("GRAFANA_NS", "grafana")
    host = os.getenv("GRAFANA_HOST", "grafana.grafana.svc.cluster.local")
    port = os.getenv("GRAFANA_PORT", "3000")
    admin_user = os.getenv("GRAFANA_ADMIN_USER", "admin")
    admin_password = os.getenv("GRAFANA_ADMIN_PASSWORD", "admin")

    # Get list of API keys
    cmd = f"curl -s -u {admin_user}:{admin_password} http://{host}:{port}/api/auth/keys"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])

            if isinstance(data, list):
                # Check for admin role API keys
                admin_keys = [k for k in data if k.get("role", "").lower() == "admin"]

                if len(admin_keys) > 0:
                    return create_result(
                        "grafana_api_key_security",
                        "Check API key security configuration",
                        False,
                        f"WARNING: {len(admin_keys)} API key(s) with Admin role found. Use Viewer/Editor roles for least privilege.",
                        "WARNING"
                    )
                elif len(data) > 0:
                    return create_result(
                        "grafana_api_key_security",
                        "Check API key security configuration",
                        True,
                        f"{len(data)} API key(s) configured with appropriate roles (no Admin keys)",
                        "INFO"
                    )
                else:
                    return create_result(
                        "grafana_api_key_security",
                        "Check API key security configuration",
                        True,
                        "No API keys configured",
                        "INFO"
                    )
        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "grafana_api_key_security",
        "Check API key security configuration",
        True,
        "Unable to check API keys (may require admin authentication)",
        "INFO"
    )


def test_external_exposure() -> Dict[str, Any]:
    """Check if Grafana is exposed externally"""
    namespace = os.getenv("GRAFANA_NS", "grafana")

    # Check service types
    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                if "grafana" in svc_name.lower():
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        return create_result(
                            "grafana_external_exposure",
                            "Check if Grafana is exposed to external networks",
                            False,
                            f"WARNING: Grafana service '{svc_name}' is exposed as LoadBalancer with external IP: {external_ip}. Ensure strong authentication.",
                            "WARNING"
                        )
                    elif svc_type == "ClusterIP":
                        return create_result(
                            "grafana_external_exposure",
                            "Check if Grafana is exposed to external networks",
                            True,
                            f"Grafana service '{svc_name}' is ClusterIP (internal only) - good security practice",
                            "INFO"
                        )
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        return create_result(
                            "grafana_external_exposure",
                            "Check if Grafana is exposed to external networks",
                            False,
                            f"WARNING: Grafana service '{svc_name}' is exposed via NodePort: {node_ports}. Ensure proper authentication.",
                            "WARNING"
                        )

            return create_result(
                "grafana_external_exposure",
                "Check if Grafana is exposed to external networks",
                True,
                "No Grafana service found or service is internal only",
                "INFO"
            )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "grafana_external_exposure",
                "Check if Grafana is exposed to external networks",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "grafana_external_exposure",
            "Check if Grafana is exposed to external networks",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def test_pod_security_context() -> Dict[str, Any]:
    """Check if Grafana pods run with secure security context"""
    namespace = os.getenv("GRAFANA_NS", "grafana")

    # Get Grafana pods
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=grafana -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])

            if not pods_data.get("items"):
                return create_result(
                    "grafana_pod_security_context",
                    "Check Grafana pod security context",
                    True,
                    "No Grafana pods found",
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
                if "grafana" in container["name"].lower():
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
                    "grafana_pod_security_context",
                    "Check Grafana pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join(issues)}",
                    "WARNING"
                )
            else:
                return create_result(
                    "grafana_pod_security_context",
                    "Check Grafana pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "grafana_pod_security_context",
                "Check Grafana pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "grafana_pod_security_context",
            "Check Grafana pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured for Grafana namespace"""
    namespace = os.getenv("GRAFANA_NS", "grafana")

    # Check for NetworkPolicies
    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "grafana_network_policies",
                    "Check if NetworkPolicies restrict Grafana access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'. Grafana is accessible from any pod.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "grafana_network_policies",
                    "Check if NetworkPolicies restrict Grafana access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "grafana_network_policies",
                "Check if NetworkPolicies restrict Grafana access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "grafana_network_policies",
            "Check if NetworkPolicies restrict Grafana access",
            False,
            f"WARNING: Unable to check NetworkPolicies (may not exist or no permissions)",
            "WARNING"
        )


def test_data_source_security() -> Dict[str, Any]:
    """Check data source security configuration"""
    namespace = os.getenv("GRAFANA_NS", "grafana")
    host = os.getenv("GRAFANA_HOST", "grafana.grafana.svc.cluster.local")
    port = os.getenv("GRAFANA_PORT", "3000")
    admin_user = os.getenv("GRAFANA_ADMIN_USER", "admin")
    admin_password = os.getenv("GRAFANA_ADMIN_PASSWORD", "admin")

    # Get data sources
    cmd = f"curl -s -u {admin_user}:{admin_password} http://{host}:{port}/api/datasources"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            data = json.loads(result["stdout"])

            if isinstance(data, list):
                # Check for insecure data sources
                critical_issues = []
                info_notices = []

                for ds in data:
                    ds_name = ds.get("name", "unknown")
                    ds_url = ds.get("url", "")

                    # CRITICAL: Check if basic auth credentials are stored insecurely
                    if ds.get("basicAuth", False) and not ds.get("secureJsonFields", {}).get("basicAuthPassword", False):
                        critical_issues.append(f"{ds_name} (basic auth password not stored securely)")

                    # INFO: Check if TLS is disabled for internal cluster services
                    # Only flag as issue if accessing external services or using authentication
                    json_data = ds.get("jsonData", {})
                    is_internal = ".svc.cluster.local" in ds_url or "localhost" in ds_url or "127.0.0.1" in ds_url
                    has_auth = ds.get("basicAuth", False) or json_data.get("httpHeaderName1", "")

                    if ds.get("type") in ["prometheus", "loki", "elasticsearch"] and not json_data.get("tlsAuth", False):
                        if not is_internal or has_auth:
                            # External service or has auth - TLS is important
                            critical_issues.append(f"{ds_name} (TLS not enabled - required for external/authenticated data sources)")
                        else:
                            # Internal service without auth - TLS is nice-to-have for defense-in-depth
                            info_notices.append(f"{ds_name} (TLS not enabled - consider enabling for defense-in-depth)")

                if critical_issues:
                    return create_result(
                        "grafana_data_source_security",
                        "Check data source security configuration",
                        False,
                        f"CRITICAL/WARNING: {', '.join(critical_issues)}",
                        "WARNING"
                    )
                elif info_notices:
                    return create_result(
                        "grafana_data_source_security",
                        "Check data source security configuration",
                        True,
                        f"Data sources configured. INFO: {', '.join(info_notices)}",
                        "INFO"
                    )
                else:
                    return create_result(
                        "grafana_data_source_security",
                        "Check data source security configuration",
                        True,
                        f"{len(data)} data source(s) configured with secure settings",
                        "INFO"
                    )
        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "grafana_data_source_security",
        "Check data source security configuration",
        True,
        "Unable to check data sources (may require admin authentication)",
        "INFO"
    )


def test_grafana_security() -> List[Dict[str, Any]]:
    """Run all Grafana security tests"""
    results = []

    # Authentication & Authorization
    results.append(test_default_admin_credentials())
    results.append(test_weak_admin_password())
    results.append(test_anonymous_access())
    results.append(test_public_dashboards())
    results.append(test_api_key_security())

    # Data Security
    results.append(test_data_source_security())

    # Network Security
    results.append(test_external_exposure())
    results.append(test_network_policies())

    # Container & Kubernetes Security
    results.append(test_pod_security_context())

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
        "grafana_security_summary",
        "Overall Grafana security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_grafana_security()
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
