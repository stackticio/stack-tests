#!/usr/bin/env python3
"""
RabbitMQ RBAC Security Test

Tests RabbitMQ ServiceAccount permissions to ensure proper least privilege configuration.

Environment Variables:
- RABBITMQ_NS: RabbitMQ namespace (default: rabbitmq-system)
- RABBITMQ_SA: RabbitMQ ServiceAccount name (default: rabbitmq)
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, List


def run_command(cmd: str) -> tuple:
    """Execute shell command and return output"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def test_serviceaccount_exists() -> Dict[str, Any]:
    """Check if RabbitMQ ServiceAccount exists"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq")

    cmd = f"kubectl get serviceaccount {sa_name} -n {namespace} -o json 2>/dev/null"
    code, stdout, stderr = run_command(cmd)

    if code != 0:
        return {
            "name": "rabbitmq_rbac_serviceaccount",
            "description": "Check if RabbitMQ ServiceAccount exists",
            "status": False,
            "output": f"CRITICAL: ServiceAccount '{sa_name}' not found in namespace '{namespace}'",
            "severity": "CRITICAL"
        }

    return {
        "name": "rabbitmq_rbac_serviceaccount",
        "description": "Check if RabbitMQ ServiceAccount exists",
        "status": True,
        "output": f"ServiceAccount '{sa_name}' exists in namespace '{namespace}'",
        "severity": "INFO"
    }


def test_overly_permissive_roles() -> Dict[str, Any]:
    """Check if ServiceAccount has overly permissive cluster roles"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq")

    # Check ClusterRoleBindings
    cmd = f"kubectl get clusterrolebindings -o json 2>/dev/null"
    code, stdout, stderr = run_command(cmd)

    if code != 0:
        return {
            "name": "rabbitmq_rbac_permissive_roles",
            "description": "Check for overly permissive cluster roles",
            "status": True,
            "output": "Unable to check ClusterRoleBindings",
            "severity": "INFO"
        }

    try:
        bindings = json.loads(stdout)
        risky_roles = []

        for binding in bindings.get("items", []):
            subjects = binding.get("subjects", [])
            role_ref = binding.get("roleRef", {})

            # Check if this binding applies to our ServiceAccount
            for subject in subjects:
                if (subject.get("kind") == "ServiceAccount" and
                    subject.get("name") == sa_name and
                    subject.get("namespace") == namespace):

                    role_name = role_ref.get("name", "")

                    # Check for risky roles
                    if role_name in ["cluster-admin", "admin", "edit"]:
                        risky_roles.append(f"ClusterRole '{role_name}' (VERY RISKY - full cluster access)")
                    elif "admin" in role_name.lower():
                        risky_roles.append(f"ClusterRole '{role_name}' (potentially risky)")

        if risky_roles:
            return {
                "name": "rabbitmq_rbac_permissive_roles",
                "description": "Check for overly permissive cluster roles",
                "status": False,
                "output": f"CRITICAL: Overly permissive roles found: {', '.join(risky_roles)}",
                "severity": "CRITICAL"
            }

        return {
            "name": "rabbitmq_rbac_permissive_roles",
            "description": "Check for overly permissive cluster roles",
            "status": True,
            "output": "No overly permissive cluster roles detected",
            "severity": "INFO"
        }

    except json.JSONDecodeError:
        return {
            "name": "rabbitmq_rbac_permissive_roles",
            "description": "Check for overly permissive cluster roles",
            "status": True,
            "output": "Unable to parse ClusterRoleBindings",
            "severity": "INFO"
        }


def test_cross_namespace_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access resources in other namespaces"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    # Test access to kube-system secrets (should be NO)
    cmd = f"kubectl auth can-i get secrets --as={sa_full} -n kube-system 2>/dev/null"
    code, stdout, stderr = run_command(cmd)

    issues = []

    if code == 0 and "yes" in stdout.lower():
        issues.append("Can access secrets in kube-system (RISKY)")

    # Test access to default namespace secrets
    cmd = f"kubectl auth can-i get secrets --as={sa_full} -n default 2>/dev/null"
    code, stdout, stderr = run_command(cmd)

    if code == 0 and "yes" in stdout.lower():
        issues.append("Can access secrets in default namespace (RISKY)")

    # Test cluster-wide pod access
    cmd = f"kubectl auth can-i get pods --as={sa_full} --all-namespaces 2>/dev/null"
    code, stdout, stderr = run_command(cmd)

    if code == 0 and "yes" in stdout.lower():
        issues.append("Can list pods cluster-wide (may be excessive)")

    if issues:
        return {
            "name": "rabbitmq_rbac_cross_namespace",
            "description": "Test cross-namespace access permissions",
            "status": False,
            "output": f"WARNING: Cross-namespace access detected: {', '.join(issues)}",
            "severity": "WARNING"
        }

    return {
        "name": "rabbitmq_rbac_cross_namespace",
        "description": "Test cross-namespace access permissions",
        "status": True,
        "output": "No excessive cross-namespace access detected",
        "severity": "INFO"
    }


def test_destructive_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has destructive permissions it shouldn't have"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    risky_permissions = []

    # Test delete pods (RabbitMQ shouldn't delete pods)
    cmd = f"kubectl auth can-i delete pods --as={sa_full} -n {namespace} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        risky_permissions.append("delete pods")

    # Test delete deployments
    cmd = f"kubectl auth can-i delete deployments --as={sa_full} -n {namespace} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        risky_permissions.append("delete deployments")

    # Test delete services
    cmd = f"kubectl auth can-i delete services --as={sa_full} -n {namespace} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        risky_permissions.append("delete services")

    # Test delete namespaces
    cmd = f"kubectl auth can-i delete namespaces --as={sa_full} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        risky_permissions.append("delete namespaces (CRITICAL)")

    # Test create clusterrolebindings
    cmd = f"kubectl auth can-i create clusterrolebindings --as={sa_full} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        risky_permissions.append("create clusterrolebindings (CRITICAL - privilege escalation)")

    if risky_permissions:
        severity = "CRITICAL" if any("CRITICAL" in p for p in risky_permissions) else "WARNING"
        return {
            "name": "rabbitmq_rbac_destructive_perms",
            "description": "Test for destructive permissions",
            "status": False,
            "output": f"{severity}: ServiceAccount has risky permissions: {', '.join(risky_permissions)}",
            "severity": severity
        }

    return {
        "name": "rabbitmq_rbac_destructive_perms",
        "description": "Test for destructive permissions",
        "status": True,
        "output": "No excessive destructive permissions detected",
        "severity": "INFO"
    }


def test_necessary_permissions() -> Dict[str, Any]:
    """Test if ServiceAccount has necessary permissions for RabbitMQ operation"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    missing_permissions = []

    # RabbitMQ typically needs to:
    # 1. Get/list endpoints (for cluster discovery)
    cmd = f"kubectl auth can-i get endpoints --as={sa_full} -n {namespace} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code != 0 or "yes" not in stdout.lower():
        missing_permissions.append("get endpoints (needed for cluster discovery)")

    # 2. Get/list pods (for cluster membership)
    cmd = f"kubectl auth can-i get pods --as={sa_full} -n {namespace} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code != 0 or "yes" not in stdout.lower():
        missing_permissions.append("get pods (needed for cluster membership)")

    # 3. Get configmaps (for configuration)
    cmd = f"kubectl auth can-i get configmaps --as={sa_full} -n {namespace} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code != 0 or "yes" not in stdout.lower():
        missing_permissions.append("get configmaps (may be needed for configuration)")

    if missing_permissions:
        return {
            "name": "rabbitmq_rbac_necessary_perms",
            "description": "Test for necessary RabbitMQ permissions",
            "status": False,
            "output": f"WARNING: Missing potentially necessary permissions: {', '.join(missing_permissions)}",
            "severity": "WARNING"
        }

    return {
        "name": "rabbitmq_rbac_necessary_perms",
        "description": "Test for necessary RabbitMQ permissions",
        "status": True,
        "output": "ServiceAccount has necessary permissions for RabbitMQ operation",
        "severity": "INFO"
    }


def test_node_access() -> Dict[str, Any]:
    """Test if ServiceAccount can access node resources"""
    namespace = os.getenv("RABBITMQ_NS", "rabbitmq-system")
    sa_name = os.getenv("RABBITMQ_SA", "rabbitmq")
    sa_full = f"system:serviceaccount:{namespace}:{sa_name}"

    issues = []

    # Test node access (usually not needed for apps)
    cmd = f"kubectl auth can-i get nodes --as={sa_full} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        issues.append("Can get nodes")

    # Test persistent volumes
    cmd = f"kubectl auth can-i get persistentvolumes --as={sa_full} 2>/dev/null"
    code, stdout, stderr = run_command(cmd)
    if code == 0 and "yes" in stdout.lower():
        issues.append("Can get persistentvolumes")

    if issues:
        return {
            "name": "rabbitmq_rbac_node_access",
            "description": "Test access to cluster-level resources",
            "status": False,
            "output": f"WARNING: Has access to cluster resources: {', '.join(issues)} (usually not needed)",
            "severity": "WARNING"
        }

    return {
        "name": "rabbitmq_rbac_node_access",
        "description": "Test access to cluster-level resources",
        "status": True,
        "output": "No excessive cluster-level access detected",
        "severity": "INFO"
    }


def main():
    """Run all RBAC tests"""
    tests = [
        test_serviceaccount_exists,
        test_overly_permissive_roles,
        test_cross_namespace_access,
        test_destructive_permissions,
        test_necessary_permissions,
        test_node_access,
    ]

    results = []
    passed = 0
    failed = 0
    critical_count = 0
    warning_count = 0

    for test in tests:
        result = test()
        results.append(result)

        if result["name"] != "rabbitmq_rbac_summary":
            if result["status"]:
                passed += 1
            else:
                failed += 1
                if result["severity"] == "CRITICAL":
                    critical_count += 1
                elif result["severity"] == "WARNING":
                    warning_count += 1

    # Summary
    total = passed + failed
    if critical_count > 0:
        summary_status = False
        summary_output = f"{passed}/{total} checks passed | {critical_count} CRITICAL RBAC issues found!"
        summary_severity = "CRITICAL"
    elif warning_count > 0:
        summary_status = False
        summary_output = f"{passed}/{total} checks passed | {warning_count} RBAC warnings found"
        summary_severity = "WARNING"
    else:
        summary_status = True
        summary_output = f"{passed}/{total} checks passed | RBAC properly configured"
        summary_severity = "INFO"

    results.append({
        "name": "rabbitmq_rbac_summary",
        "description": "Overall RabbitMQ RBAC security assessment",
        "status": summary_status,
        "output": summary_output,
        "severity": summary_severity
    })

    print(json.dumps(results, indent=2))

    # Exit with error if critical issues found
    if critical_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
