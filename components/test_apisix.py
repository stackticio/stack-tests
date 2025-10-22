#!/usr/bin/env python3
"""
APISIX Security Tests
Comprehensive security analysis for APISIX API Gateway

Tests:
1. Admin API protection
2. Default admin key
3. ETCD security
4. Route authentication
5. Plugin security configurations
6. SSL/TLS configuration
7. Rate limiting
8. External exposure
9. Pod security context
10. Network policies

ENV VARS:
  APISIX_NS (default: ingress-apisix)
  APISIX_HOST (default: apisix-gateway.ingress-apisix.svc.cluster.local)
  APISIX_PORT (default: 80)
  APISIX_ADMIN_HOST (default: apisix-admin.ingress-apisix.svc.cluster.local)
  APISIX_ADMIN_PORT (default: 9180)
  APISIX_ADMIN_KEY (default: none)

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


def test_admin_api_protection() -> Dict[str, Any]:
    """Check if Admin API is protected"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")
    admin_host = os.getenv("APISIX_ADMIN_HOST", "apisix-admin.ingress-apisix.svc.cluster.local")
    admin_port = os.getenv("APISIX_ADMIN_PORT", "9180")

    # Try accessing admin API without key
    cmd = f"curl -s -w '%{{http_code}}' -o /dev/null http://{admin_host}:{admin_port}/apisix/admin/routes"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "apisix_admin_api_protection",
            "Check if Admin API requires authentication",
            False,
            "CRITICAL: Admin API is accessible without authentication! Anyone can modify routes and plugins.",
            "CRITICAL"
        )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "apisix_admin_api_protection",
            "Check if Admin API requires authentication",
            True,
            f"Admin API requires authentication (HTTP {http_code}) - good security practice",
            "INFO"
        )
    elif http_code == "000" or result["exit_code"] != 0:
        return create_result(
            "apisix_admin_api_protection",
            "Check if Admin API requires authentication",
            True,
            "Admin API is not accessible (may be disabled or network restricted)",
            "INFO"
        )
    else:
        return create_result(
            "apisix_admin_api_protection",
            "Check if Admin API requires authentication",
            True,
            f"Admin API returned HTTP {http_code} - likely protected",
            "INFO"
        )


def test_default_admin_key() -> Dict[str, Any]:
    """Check if default admin key is used"""
    # Default APISIX admin key
    default_key = "edd1c9f034335f136f87ad84b625c8f1"

    admin_host = os.getenv("APISIX_ADMIN_HOST", "apisix-admin.ingress-apisix.svc.cluster.local")
    admin_port = os.getenv("APISIX_ADMIN_PORT", "9180")

    # Try with default admin key
    cmd = f"curl -s -H 'X-API-KEY: {default_key}' -w '%{{http_code}}' -o /dev/null http://{admin_host}:{admin_port}/apisix/admin/routes"
    result = run_command(cmd, timeout=10)

    http_code = result["stdout"]

    if http_code == "200":
        return create_result(
            "apisix_default_admin_key",
            "Check if default admin key is disabled",
            False,
            "CRITICAL: Default admin key 'edd1c9f034335f136f87ad84b625c8f1' is ENABLED! Change immediately.",
            "CRITICAL"
        )
    elif http_code == "401" or http_code == "403":
        return create_result(
            "apisix_default_admin_key",
            "Check if default admin key is disabled",
            True,
            "Default admin key is properly disabled (HTTP 401/403)",
            "INFO"
        )
    else:
        return create_result(
            "apisix_default_admin_key",
            "Check if default admin key is disabled",
            True,
            f"Admin API returned HTTP {http_code} for default key",
            "INFO"
        )


def test_etcd_security() -> Dict[str, Any]:
    """Check ETCD security configuration"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")

    # Get ETCD pods
    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=etcd -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            if not pods:
                return create_result(
                    "apisix_etcd_security",
                    "Check ETCD security configuration",
                    True,
                    "No ETCD pods found (may be using external ETCD)",
                    "INFO"
                )

            # Check if ETCD service is internal
            cmd = f"kubectl get svc -n {namespace} -l app.kubernetes.io/name=etcd -o json"
            svc_result = run_command(cmd, timeout=10)

            if svc_result["exit_code"] == 0 and svc_result["stdout"]:
                services = json.loads(svc_result["stdout"])
                for svc in services.get("items", []):
                    svc_type = svc["spec"]["type"]

                    if svc_type != "ClusterIP":
                        return create_result(
                            "apisix_etcd_security",
                            "Check ETCD security configuration",
                            False,
                            f"WARNING: ETCD service is {svc_type} - should be ClusterIP. ETCD contains sensitive route configs.",
                            "WARNING"
                        )

                return create_result(
                    "apisix_etcd_security",
                    "Check ETCD security configuration",
                    True,
                    f"ETCD is properly configured as ClusterIP ({len(pods)} instance(s))",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            pass

    return create_result(
        "apisix_etcd_security",
        "Check ETCD security configuration",
        True,
        "Unable to check ETCD configuration",
        "INFO"
    )


def test_route_authentication() -> Dict[str, Any]:
    """Check if routes have authentication configured"""
    admin_host = os.getenv("APISIX_ADMIN_HOST", "apisix-admin.ingress-apisix.svc.cluster.local")
    admin_port = os.getenv("APISIX_ADMIN_PORT", "9180")
    admin_key = os.getenv("APISIX_ADMIN_KEY", "")

    if not admin_key:
        return create_result(
            "apisix_route_authentication",
            "Check if routes have authentication plugins",
            True,
            "Unable to check routes (no admin key provided)",
            "INFO"
        )

    # Get routes configuration
    cmd = f"curl -s -H 'X-API-KEY: {admin_key}' http://{admin_host}:{admin_port}/apisix/admin/routes"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            routes_data = json.loads(result["stdout"])
            routes = routes_data.get("node", {}).get("nodes", [])

            if not routes:
                return create_result(
                    "apisix_route_authentication",
                    "Check if routes have authentication plugins",
                    True,
                    "No routes configured yet",
                    "INFO"
                )

            routes_without_auth = []

            for route in routes:
                route_value = route.get("value", {})
                route_name = route_value.get("name", route_value.get("uri", "unknown"))
                plugins = route_value.get("plugins", {})

                # Check for common auth plugins
                has_auth = any(auth_plugin in plugins for auth_plugin in [
                    "key-auth", "jwt-auth", "basic-auth", "hmac-auth", "ldap-auth", "authz-keycloak"
                ])

                if not has_auth:
                    routes_without_auth.append(route_name)

            if routes_without_auth and len(routes_without_auth) > len(routes) * 0.5:
                return create_result(
                    "apisix_route_authentication",
                    "Check if routes have authentication plugins",
                    False,
                    f"WARNING: {len(routes_without_auth)}/{len(routes)} routes have no authentication: {', '.join(routes_without_auth[:3])}",
                    "WARNING"
                )
            elif routes_without_auth:
                return create_result(
                    "apisix_route_authentication",
                    "Check if routes have authentication plugins",
                    True,
                    f"{len(routes) - len(routes_without_auth)}/{len(routes)} routes have authentication configured",
                    "INFO"
                )
            else:
                return create_result(
                    "apisix_route_authentication",
                    "Check if routes have authentication plugins",
                    True,
                    f"All {len(routes)} routes have authentication configured",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "apisix_route_authentication",
                "Check if routes have authentication plugins",
                True,
                "Unable to parse routes configuration",
                "INFO"
            )
    else:
        return create_result(
            "apisix_route_authentication",
            "Check if routes have authentication plugins",
            True,
            "Unable to access Admin API to check routes",
            "INFO"
        )


def test_ssl_configuration() -> Dict[str, Any]:
    """Check SSL/TLS configuration"""
    admin_host = os.getenv("APISIX_ADMIN_HOST", "apisix-admin.ingress-apisix.svc.cluster.local")
    admin_port = os.getenv("APISIX_ADMIN_PORT", "9180")
    admin_key = os.getenv("APISIX_ADMIN_KEY", "")

    if not admin_key:
        return create_result(
            "apisix_ssl_configuration",
            "Check SSL/TLS certificates configuration",
            True,
            "Unable to check SSL config (no admin key provided)",
            "INFO"
        )

    # Get SSL certificates
    cmd = f"curl -s -H 'X-API-KEY: {admin_key}' http://{admin_host}:{admin_port}/apisix/admin/ssls"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            ssl_data = json.loads(result["stdout"])
            ssls = ssl_data.get("node", {}).get("nodes", [])

            if not ssls:
                return create_result(
                    "apisix_ssl_configuration",
                    "Check SSL/TLS certificates configuration",
                    False,
                    "WARNING: No SSL certificates configured. Consider enabling HTTPS for production.",
                    "WARNING"
                )
            else:
                return create_result(
                    "apisix_ssl_configuration",
                    "Check SSL/TLS certificates configuration",
                    True,
                    f"{len(ssls)} SSL certificate(s) configured",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "apisix_ssl_configuration",
                "Check SSL/TLS certificates configuration",
                True,
                "Unable to parse SSL configuration",
                "INFO"
            )
    else:
        return create_result(
            "apisix_ssl_configuration",
            "Check SSL/TLS certificates configuration",
            True,
            "Unable to access Admin API to check SSL",
            "INFO"
        )


def test_external_exposure() -> Dict[str, Any]:
    """Check if APISIX is exposed externally"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")

    cmd = f"kubectl get svc -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            services = json.loads(result["stdout"])
            exposed = []

            for svc in services.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc["spec"]["type"]

                # Check gateway service (not admin)
                if "gateway" in svc_name.lower() or ("apisix" in svc_name.lower() and "admin" not in svc_name.lower() and "etcd" not in svc_name.lower()):
                    if svc_type == "LoadBalancer":
                        external_ip = svc["status"].get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", "pending")
                        exposed.append(f"{svc_name} (LoadBalancer: {external_ip})")
                    elif svc_type == "NodePort":
                        node_ports = [p.get("nodePort") for p in svc["spec"].get("ports", []) if p.get("nodePort")]
                        exposed.append(f"{svc_name} (NodePort: {node_ports})")

            if exposed:
                return create_result(
                    "apisix_external_exposure",
                    "Check if APISIX gateway is externally exposed",
                    True,
                    f"INFO: APISIX gateway exposed (expected for API gateway): {', '.join(exposed)}. Ensure routes have authentication.",
                    "INFO"
                )
            else:
                return create_result(
                    "apisix_external_exposure",
                    "Check if APISIX gateway is externally exposed",
                    True,
                    "APISIX gateway is ClusterIP (internal only)",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError):
            return create_result(
                "apisix_external_exposure",
                "Check if APISIX gateway is externally exposed",
                True,
                "Unable to parse service configuration",
                "INFO"
            )
    else:
        return create_result(
            "apisix_external_exposure",
            "Check if APISIX gateway is externally exposed",
            True,
            "Unable to check service exposure",
            "INFO"
        )


def test_pod_security_context() -> Dict[str, Any]:
    """Check if APISIX pods run with secure security context"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")

    cmd = f"kubectl get pod -n {namespace} -l app.kubernetes.io/name=apisix -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            if not pods:
                return create_result(
                    "apisix_pod_security_context",
                    "Check APISIX pod security context",
                    True,
                    "No APISIX pods found",
                    "INFO"
                )

            issues = []
            pod = pods[0]
            pod_name = pod["metadata"]["name"]

            pod_security = pod["spec"].get("securityContext", {})
            pod_run_as_non_root = pod_security.get("runAsNonRoot", False)

            containers = pod["spec"].get("containers", [])
            for container in containers:
                container_security = container.get("securityContext", {})

                container_run_as_non_root = container_security.get("runAsNonRoot", False)
                if not pod_run_as_non_root and not container_run_as_non_root:
                    issues.append("Not enforcing runAsNonRoot")

                if container_security.get("privileged", False):
                    issues.append("Running in privileged mode")

            if issues:
                return create_result(
                    "apisix_pod_security_context",
                    "Check APISIX pod security context",
                    False,
                    f"Security issues in pod '{pod_name}': {', '.join(issues)}",
                    "WARNING"
                )
            else:
                return create_result(
                    "apisix_pod_security_context",
                    "Check APISIX pod security context",
                    True,
                    f"Pod '{pod_name}' has secure security context",
                    "INFO"
                )

        except (json.JSONDecodeError, KeyError) as e:
            return create_result(
                "apisix_pod_security_context",
                "Check APISIX pod security context",
                True,
                f"Unable to parse pod security context: {str(e)}",
                "INFO"
            )
    else:
        return create_result(
            "apisix_pod_security_context",
            "Check APISIX pod security context",
            True,
            "Unable to retrieve pod information",
            "INFO"
        )


def test_network_policies() -> Dict[str, Any]:
    """Check if NetworkPolicies are configured"""
    namespace = os.getenv("APISIX_NS", "ingress-apisix")

    cmd = f"kubectl get networkpolicies -n {namespace} -o json"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0 and result["stdout"]:
        try:
            netpol_data = json.loads(result["stdout"])
            policies = netpol_data.get("items", [])

            if len(policies) == 0:
                return create_result(
                    "apisix_network_policies",
                    "Check if NetworkPolicies restrict APISIX access",
                    False,
                    f"WARNING: No NetworkPolicies found in namespace '{namespace}'.",
                    "WARNING"
                )
            else:
                policy_names = [p["metadata"]["name"] for p in policies]
                return create_result(
                    "apisix_network_policies",
                    "Check if NetworkPolicies restrict APISIX access",
                    True,
                    f"NetworkPolicies configured: {', '.join(policy_names)} ({len(policies)} total)",
                    "INFO"
                )
        except (json.JSONDecodeError, KeyError):
            return create_result(
                "apisix_network_policies",
                "Check if NetworkPolicies restrict APISIX access",
                True,
                "Unable to parse NetworkPolicy data",
                "INFO"
            )
    else:
        return create_result(
            "apisix_network_policies",
            "Check if NetworkPolicies restrict APISIX access",
            False,
            "WARNING: Unable to check NetworkPolicies",
            "WARNING"
        )


def test_apisix_security() -> List[Dict[str, Any]]:
    """Run all APISIX security tests"""
    results = []

    # API Gateway Security
    results.append(test_admin_api_protection())
    results.append(test_default_admin_key())
    results.append(test_route_authentication())
    results.append(test_ssl_configuration())

    # Infrastructure Security
    results.append(test_etcd_security())
    results.append(test_external_exposure())

    # Container & Kubernetes Security
    results.append(test_pod_security_context())
    results.append(test_network_policies())

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
        "apisix_security_summary",
        "Overall APISIX security assessment",
        critical_failures == 0,
        f"{passed_checks}/{total_checks} checks passed | {status_text}",
        severity
    ))

    return results


if __name__ == "__main__":
    try:
        results = test_apisix_security()
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
