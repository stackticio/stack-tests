#!/usr/bin/env python3
"""
OPA Gatekeeper Policy Test Script
- Tests Gatekeeper connectivity, policies enforcement, constraint templates, and violations
- Designed for OPA Gatekeeper in Kubernetes clusters

ENV VARS
  OPA_HOST (default: opa.opa.svc.cluster.local)
  OPA_NS (default: opa)
  OPA_PORT (default: 8181)
  POLICY_LABEL_DENY (true/false)
  POLICY_PROBES (true/false)
  POLICY_RESOURCE (true/false)
  POLICY_SECURITY_CONTEXT (true/false)
  POLICY_POD_LEVEL_SECURITY (true/false)
  POLICY_IMAGE (true/false)

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import time
import subprocess
import sys
import re
import yaml
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import tempfile
import uuid

# ------------------------------------------------------------
# Utilities & configuration
# ------------------------------------------------------------

def run_command(command: str, env: Optional[Dict[str, str]] = None, timeout: int = 30) -> Dict[str, Any]:
    """Run a shell command and capture stdout/stderr/exit code."""
    try:
        # Combine stderr and stdout for better error capture
        completed = subprocess.run(
            command,
            shell=True,
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # If stderr contains useful info, combine it with stdout
        output = completed.stdout or ''
        if completed.stderr:
            output = f"{output}\nSTDERR: {completed.stderr}".strip()
            
        return {
            "stdout": output,
            "stderr": completed.stderr or '',
            "combined": output,
            "exit_code": completed.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "combined": "Timeout", "exit_code": 124}

def ok(proc: Dict[str, Any]) -> bool:
    return proc.get("exit_code", 1) == 0

# ------------------------------------------------------------
# Configuration from environment
# ------------------------------------------------------------

OPA_HOST = os.getenv('OPA_HOST', 'opa.opa.svc.cluster.local')
OPA_NS = os.getenv('OPA_NS', 'opa')
OPA_PORT = os.getenv('OPA_PORT', '8181')

# Auto-detect where Gatekeeper is actually running
def detect_gatekeeper_namespace():
    """Detect the Gatekeeper namespace - could be same as OPA_NS or different"""
    # First check if it's in OPA_NS
    cmd = f"kubectl get pods -n {OPA_NS} --no-headers 2>/dev/null | grep -E 'gatekeeper-audit|gatekeeper-controller'"
    r = run_command(cmd, timeout=5)
    if ok(r) and r['stdout']:
        return OPA_NS
    
    # Otherwise check other common namespaces
    possible_namespaces = ['gatekeeper-system', 'gatekeeper']
    for ns in possible_namespaces:
        cmd = f"kubectl get pods -n {ns} --no-headers 2>/dev/null | grep -E 'gatekeeper-audit|gatekeeper-controller'"
        r = run_command(cmd, timeout=5)
        if ok(r) and r['stdout']:
            return ns
    
    # Default to OPA_NS if nothing found
    return OPA_NS

GATEKEEPER_NS = os.getenv('GATEKEEPER_NS', detect_gatekeeper_namespace())

# Policy flags from environment
POLICIES = {
    'label_deny': os.getenv('POLICY_LABEL_DENY', 'false').lower() == 'true',
    'probes': os.getenv('POLICY_PROBES', 'false').lower() == 'true',
    'resource': os.getenv('POLICY_RESOURCE', 'false').lower() == 'true',
    'security_context': os.getenv('POLICY_SECURITY_CONTEXT', 'false').lower() == 'true',
    'pod_level_security': os.getenv('POLICY_POD_LEVEL_SECURITY', 'false').lower() == 'true',
    'image': os.getenv('POLICY_IMAGE', 'false').lower() == 'true',
}

# ------------------------------------------------------------
# Result helper
# ------------------------------------------------------------

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create a test result with clear, actionable output messages"""
    
    # Enhance output messages for common scenarios
    enhanced_output = output
    
    # Policy deployment issues
    if "enabled in ENV but" in output:
        policy_name = name.replace('_policy_deployment', '')
        enhanced_output = f"Policy '{policy_name}' is configured in environment but not applied to cluster. Run: kubectl apply -f <{policy_name}_policy.yaml>"
    
    # Test failures
    elif "was not rejected as expected" in output:
        enhanced_output = f"ENFORCEMENT FAILURE: Non-compliant resource was allowed through. Check if policy is in 'deny' mode and webhook is working"
    elif "Failed to create" in output and "compliant pod" in output:
        if "denied the request" in output:
            enhanced_output = f"UNEXPECTED REJECTION: Compliant resource was blocked. Review policy constraints and labels"
        else:
            enhanced_output = f"INFRASTRUCTURE ISSUE: Could not create test resource. Check cluster permissions and quotas"
    
    # Webhook issues  
    elif "failurePolicy: Ignore" in output:
        enhanced_output = "SECURITY RISK: Webhook set to 'Ignore' - violations will be allowed if Gatekeeper fails. Run: kubectl patch validatingwebhookconfigurations gatekeeper-validating-webhook-configuration --type='json' -p='[{\"op\": \"replace\", \"path\": \"/webhooks/0/failurePolicy\", \"value\": \"Fail\"}]'"
    
    # Violations
    elif "violation(s)" in output and "Found" in output:
        enhanced_output = f"{output}. These resources violate current policies but existed before enforcement. Consider cleaning them up"
    
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": enhanced_output,
        "severity": severity.lower(),
    }

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def check_gatekeeper_connectivity() -> List[Dict[str, Any]]:
    """Check basic Gatekeeper connectivity and health"""
    tests = []
    
    # First, determine the actual namespace where Gatekeeper is running
    global GATEKEEPER_NS
    
    # Check if Gatekeeper pods are running in the detected namespace
    cmd = f"kubectl get pods -n {GATEKEEPER_NS} --no-headers 2>/dev/null | grep -E 'gatekeeper-audit'"
    r = run_command(cmd, timeout=15)
    
    if ok(r) and 'Running' in r['stdout']:
        tests.append(create_test_result(
            "gatekeeper_audit_pod", 
            "Check Gatekeeper audit pod status",
            True,
            f"Gatekeeper audit pod is running in namespace {GATEKEEPER_NS}",
            "INFO"
        ))
    else:
        # Maybe Gatekeeper is not installed at all
        tests.append(create_test_result(
            "gatekeeper_audit_pod",
            "Check Gatekeeper audit pod status", 
            False,
            f"Gatekeeper audit pod not found or not running in {GATEKEEPER_NS}",
            "CRITICAL"
        ))
        return tests  # Early exit if core component not running
    
    # Check controller manager pods
    cmd = f"kubectl get pods -n {GATEKEEPER_NS} --no-headers | grep -E 'gatekeeper-controller' | grep Running | wc -l"
    r = run_command(cmd, timeout=15)
    
    if ok(r) and r['stdout']:
        running_count = int(r['stdout'].strip()) if r['stdout'].strip().isdigit() else 0
        tests.append(create_test_result(
            "gatekeeper_controller_pods",
            "Check Gatekeeper controller manager pods",
            running_count > 0,
            f"Found {running_count} controller manager pod(s) running",
            "INFO" if running_count > 0 else "WARNING"
        ))
    
    # Check webhook configuration
    cmd = "kubectl get validatingwebhookconfigurations gatekeeper-validating-webhook-configuration -o jsonpath='{.webhooks[0].name}' 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and 'validation.gatekeeper.sh' in r['stdout']:
        tests.append(create_test_result(
            "gatekeeper_webhook",
            "Check Gatekeeper validating webhook",
            True,
            "Validating webhook configured correctly",
            "INFO"
        ))
    else:
        tests.append(create_test_result(
            "gatekeeper_webhook",
            "Check Gatekeeper validating webhook",
            False,
            f"Webhook not configured properly",
            "WARNING"
        ))
    
    # Check webhook failure policy
    cmd = "kubectl get validatingwebhookconfigurations gatekeeper-validating-webhook-configuration -o jsonpath='{.webhooks[0].failurePolicy}' 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        failure_policy = r['stdout'].strip() or 'unknown'
        is_fail_closed = failure_policy.lower() == 'fail'
        tests.append(create_test_result(
            "gatekeeper_webhook_failure_policy",
            "Check webhook failure policy",
            is_fail_closed,
            f"Webhook failure policy: {failure_policy} ({'secure' if is_fail_closed else 'may allow violations if webhook fails'})",
            "INFO" if is_fail_closed else "WARNING"
        ))
    
    # Check if Gatekeeper is excluding the default namespace
    cmd = "kubectl get validatingwebhookconfigurations gatekeeper-validating-webhook-configuration -o jsonpath='{.webhooks[0].namespaceSelector}' 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    if ok(r) and r['stdout']:
        tests.append(create_test_result(
            "gatekeeper_namespace_selector",
            "Check webhook namespace selector",
            True,
            f"Namespace selector configured: {r['stdout'][:100]}",
            "INFO"
        ))
    
    return tests

def check_constraint_templates() -> List[Dict[str, Any]]:
    """Check deployed constraint templates and verify enabled policies are actually deployed"""
    tests = []
    
    # Map template names to policy types
    template_policy_map = {
        'k8sallowedimagerequirements': 'image',
        'podlevelsecuritypolicy': 'pod_level_security',
        'probespolicy': 'probes',
        'blocknamespacedeployments': 'label_deny',
        'resourcepolicy': 'resource',
        'securitycontextpolicy': 'security_context',
    }
    
    # First check for enabled but not deployed policies
    enabled_policies = [k for k, v in POLICIES.items() if v]
    
    if not enabled_policies:
        tests.append(create_test_result(
            "policy_configuration",
            "Check policy configuration",
            True,
            "No policies enabled in environment variables",
            "INFO"
        ))
        return tests
    
    tests.append(create_test_result(
        "policy_configuration",
        "Check policy configuration",
        True,
        f"Enabled policies from ENV: {', '.join(enabled_policies)}",
        "INFO"
    ))
    
    # Get deployed constraint templates
    cmd = "kubectl get constrainttemplates.templates.gatekeeper.sh -o json"
    r = run_command(cmd, timeout=15)
    
    deployed_templates = []
    if ok(r) and r['stdout']:
        try:
            templates = json.loads(r['stdout'])
            deployed_templates = [t['metadata']['name'].lower() for t in templates.get('items', [])]
        except:
            pass
    
    if not deployed_templates:
        tests.append(create_test_result(
            "constraint_templates_deployed",
            "Check deployed constraint templates",
            False,
            "No constraint templates found in cluster. Policies enabled but not deployed!",
            "WARNING"
        ))
        
        # Check each enabled policy
        for policy_type in enabled_policies:
            tests.append(create_test_result(
                f"{policy_type}_policy_deployment",
                f"Check {policy_type} policy deployment",
                False,
                f"Policy '{policy_type}' is enabled in ENV but no corresponding template deployed",
                "WARNING"
            ))
        return tests
    
    tests.append(create_test_result(
        "constraint_templates_deployed",
        "List deployed constraint templates",
        True,
        f"Found {len(deployed_templates)} deployed template(s)",
        "INFO"
    ))
    
    # Check each enabled policy to see if it's actually deployed
    for policy_type in enabled_policies:
        # Find the template name for this policy type
        template_name = None
        for tpl_name, pol_type in template_policy_map.items():
            if pol_type == policy_type:
                template_name = tpl_name
                break
        
        if template_name and template_name in deployed_templates:
            # Policy is enabled AND deployed - run tests
            tests.append(create_test_result(
                f"{policy_type}_policy_deployment",
                f"Check {policy_type} policy deployment",
                True,
                f"Policy '{policy_type}' is enabled and template '{template_name}' is deployed",
                "INFO"
            ))
            tests.extend(test_policy(template_name, policy_type))
        else:
            # Policy is enabled but NOT deployed
            tests.append(create_test_result(
                f"{policy_type}_policy_deployment",
                f"Check {policy_type} policy deployment",
                False,
                f"Policy '{policy_type}' is enabled in ENV but template not found in cluster. Skipping tests.",
                "WARNING"
            ))
    
    return tests

def test_policy(template_name: str, policy_type: str) -> List[Dict[str, Any]]:
    """Test a specific policy with positive and negative cases"""
    tests = []
    
    # Get constraints for this template
    cmd = f"kubectl get {template_name.lower()} -o json 2>/dev/null"
    r = run_command(cmd, timeout=10)
    
    constraints = []
    if ok(r) and r['stdout']:
        try:
            constraint_data = json.loads(r['stdout'])
            constraints = constraint_data.get('items', [])
        except:
            pass
    
    if not constraints:
        tests.append(create_test_result(
            f"{policy_type}_constraints",
            f"Check constraints for {template_name}",
            False,
            f"No constraints found for template {template_name}",
            "WARNING"
        ))
        return tests
    
    # Analyze constraint configuration
    constraint_configs = []
    for c in constraints:
        name = c.get('metadata', {}).get('name', 'unknown')
        enforcement = c.get('spec', {}).get('enforcementAction', 'deny')
        match = c.get('spec', {}).get('match', {})
        
        # Extract matching criteria
        label_selector = match.get('labelSelector', {}).get('matchLabels', {})
        namespaces = match.get('namespaces', [])
        
        config = {
            'name': name,
            'enforcement': enforcement,
            'labels': label_selector,
            'namespaces': namespaces if namespaces else ['default']  # Use default if no namespace specified
        }
        constraint_configs.append(config)
        
        info = f"{name} (enforcement={enforcement}, labels={label_selector}, namespaces={namespaces[:2] if namespaces else 'all'})"
        
    tests.append(create_test_result(
        f"{policy_type}_constraints",
        f"Check constraints for {template_name}",
        True,
        f"Found {len(constraints)} constraint(s): {constraint_configs[0]['name']} and others",
        "INFO"
    ))
    
    # Run tests for each constraint configuration
    for config in constraint_configs:
        if policy_type == 'probes':
            tests.extend(test_probes_policy_with_config(config))
        elif policy_type == 'resource':
            tests.extend(test_resource_policy_with_config(config))
        elif policy_type == 'security_context':
            tests.extend(test_security_context_policy_with_config(config))
        elif policy_type == 'pod_level_security':
            tests.extend(test_pod_level_security_policy_with_config(config))
        elif policy_type == 'image':
            tests.extend(test_image_policy_with_config(config))
        elif policy_type == 'label_deny':
            tests.extend(test_label_deny_policy_with_config(config))
        
        # Only test first constraint to avoid too many tests
        break
    
    return tests

def test_probes_policy_with_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Test probes policy enforcement with specific constraint configuration"""
    tests = []
    test_name = f"test-probes-{uuid.uuid4().hex[:8]}"
    test_ns = config['namespaces'][0] if config['namespaces'] else 'default'
    labels = config['labels']
    
    # Create namespace if needed
    if test_ns not in ['default', 'kube-system', 'kube-public']:
        run_command(f"kubectl create namespace {test_ns} --dry-run=client -o yaml | kubectl apply -f -", timeout=5)
    
    # Build label string for YAML
    label_lines = []
    for key, value in labels.items():
        label_lines.append(f"    {key}: {value}")
    labels_yaml = '\n'.join(label_lines) if label_lines else "    test: pod"
    
    # Positive test - Pod WITH required labels AND fully compliant with ALL policies
    positive_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-valid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(positive_yaml)
        positive_file = f.name
    
    cmd = f"kubectl apply -f {positive_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        tests.append(create_test_result(
            f"probes_positive_{config['name'][:20]}",
            f"Probes policy - positive test (fully compliant, labels: {labels})",
            True,
            f"Fully compliant pod created successfully in {test_ns}",
            "INFO"
        ))
        # Cleanup
        run_command(f"kubectl delete pod {test_name}-valid -n {test_ns} --ignore-not-found=true", timeout=10)
    else:
        error_msg = r.get('combined', '') or f"Exit code: {r.get('exit_code', 'unknown')}"
        tests.append(create_test_result(
            f"probes_positive_{config['name'][:20]}",
            f"Probes policy - positive test (fully compliant, labels: {labels})",
            False,
            f"Failed to create fully compliant pod: {error_msg[:200]}",
            "WARNING"
        ))
    
    os.unlink(positive_file)
    
    # Negative test - Pod WITH required labels but WITHOUT probes (should fail)
    negative_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-invalid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(negative_yaml)
        negative_file = f.name
    
    cmd = f"kubectl apply -f {negative_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) and ('denied the request' in r.get('combined', '')):
        tests.append(create_test_result(
            f"probes_negative_{config['name'][:20]}",
            f"Probes policy - negative test (no probes, labels: {labels})",
            True,
            f"Pod without probes correctly rejected in {test_ns}",
            "INFO"
        ))
    else:
        if ok(r):
            tests.append(create_test_result(
                f"probes_negative_{config['name'][:20]}",
                f"Probes policy - negative test (no probes, labels: {labels})",
                False,
                f"Pod without probes was created when it should have been rejected (constraint: {config['name']})",
                "WARNING"
            ))
            # Cleanup
            run_command(f"kubectl delete pod {test_name}-invalid -n {test_ns} --ignore-not-found=true", timeout=10)
        else:
            error_msg = r.get('combined', '') or f"Exit code: {r.get('exit_code', 'unknown')}"
            tests.append(create_test_result(
                f"probes_negative_{config['name'][:20]}",
                f"Probes policy - negative test (no probes, labels: {labels})",
                False,
                f"Pod creation failed but not due to probes policy: {error_msg[:200]}",
                "WARNING"
            ))
    
    os.unlink(negative_file)
    
    return tests

def test_resource_policy_with_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Test resource policy enforcement with specific constraint configuration"""
    tests = []
    test_name = f"test-resources-{uuid.uuid4().hex[:8]}"
    test_ns = config['namespaces'][0] if config['namespaces'] else 'default'
    labels = config['labels']
    
    # Create namespace if needed
    if test_ns not in ['default', 'kube-system', 'kube-public']:
        run_command(f"kubectl create namespace {test_ns} --dry-run=client -o yaml | kubectl apply -f -", timeout=5)
    
    # Build label string for YAML
    label_lines = []
    for key, value in labels.items():
        label_lines.append(f"    {key}: {value}")
    labels_yaml = '\n'.join(label_lines) if label_lines else "    test: pod"
    
    # Positive test - Fully compliant pod with all requirements
    positive_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-valid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(positive_yaml)
        positive_file = f.name
    
    cmd = f"kubectl apply -f {positive_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        tests.append(create_test_result(
            f"resource_positive_{config['name'][:20]}",
            f"Resource policy - positive test (fully compliant, labels: {labels})",
            True,
            f"Fully compliant pod created successfully in {test_ns}",
            "INFO"
        ))
        run_command(f"kubectl delete pod {test_name}-valid -n {test_ns} --ignore-not-found=true", timeout=10)
    else:
        error_msg = r.get('combined', '') or f"Exit code: {r.get('exit_code', 'unknown')}"
        tests.append(create_test_result(
            f"resource_positive_{config['name'][:20]}",
            f"Resource policy - positive test (fully compliant, labels: {labels})",
            False,
            f"Failed: {error_msg[:200]}",
            "WARNING"
        ))
    
    os.unlink(positive_file)
    
    # Negative test - WITH labels but WITHOUT resources (missing only resources to isolate test)
    negative_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-invalid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(negative_yaml)
        negative_file = f.name
    
    cmd = f"kubectl apply -f {negative_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) and ('denied the request' in r.get('combined', '')):
        tests.append(create_test_result(
            f"resource_negative_{config['name'][:20]}",
            f"Resource policy - negative test (no resources, labels: {labels})",
            True,
            f"Pod without resources correctly rejected",
            "INFO"
        ))
    else:
        if ok(r):
            tests.append(create_test_result(
                f"resource_negative_{config['name'][:20]}",
                f"Resource policy - negative test (no resources, labels: {labels})",
                False,
                f"Pod without resources was created when it should have been rejected",
                "WARNING"
            ))
            run_command(f"kubectl delete pod {test_name}-invalid -n {test_ns} --ignore-not-found=true", timeout=10)
        else:
            error_msg = r.get('combined', '') or f"Exit code: {r.get('exit_code', 'unknown')}"
            tests.append(create_test_result(
                f"resource_negative_{config['name'][:20]}",
                f"Resource policy - negative test",
                False,
                f"Failed but not due to resource policy: {error_msg[:200]}",
                "WARNING"
            ))
    
    os.unlink(negative_file)
    
    return tests

def test_security_context_policy_with_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Test security context policy with specific constraint configuration"""
    tests = []
    test_name = f"test-secctx-{uuid.uuid4().hex[:8]}"
    test_ns = config['namespaces'][0] if config['namespaces'] else 'default'
    labels = config['labels']
    
    # Create namespace if needed
    if test_ns not in ['default', 'kube-system', 'kube-public']:
        run_command(f"kubectl create namespace {test_ns} --dry-run=client -o yaml | kubectl apply -f -", timeout=5)
    
    # Build label string
    label_lines = []
    for key, value in labels.items():
        label_lines.append(f"    {key}: {value}")
    labels_yaml = '\n'.join(label_lines) if label_lines else "    test: pod"
    
    # Positive test - Fully compliant pod
    positive_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-valid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(positive_yaml)
        positive_file = f.name
    
    cmd = f"kubectl apply -f {positive_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        tests.append(create_test_result(
            f"security_context_positive_{config['name'][:20]}",
            f"Security context - positive test (fully compliant, labels: {labels})",
            True,
            f"Fully compliant pod created successfully",
            "INFO"
        ))
        run_command(f"kubectl delete pod {test_name}-valid -n {test_ns} --ignore-not-found=true", timeout=10)
    else:
        error_msg = r.get('combined', '') or f"Exit code: {r.get('exit_code', 'unknown')}"
        tests.append(create_test_result(
            f"security_context_positive_{config['name'][:20]}",
            f"Security context - positive test",
            False,
            f"Failed: {error_msg[:200]}",
            "WARNING"
        ))
    
    os.unlink(positive_file)
    
    # Negative test - Missing only security context to isolate test
    negative_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-invalid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(negative_yaml)
        negative_file = f.name
    
    cmd = f"kubectl apply -f {negative_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) and ('denied the request' in r.get('combined', '')):
        tests.append(create_test_result(
            f"security_context_negative_{config['name'][:20]}",
            f"Security context - negative test (no security context)",
            True,
            f"Pod without security context correctly rejected",
            "INFO"
        ))
    else:
        if ok(r):
            tests.append(create_test_result(
                f"security_context_negative_{config['name'][:20]}",
                f"Security context - negative test",
                False,
                f"Pod without security context was created when it should have been rejected",
                "WARNING"
            ))
            run_command(f"kubectl delete pod {test_name}-invalid -n {test_ns} --ignore-not-found=true", timeout=10)
        else:
            tests.append(create_test_result(
                f"security_context_negative_{config['name'][:20]}",
                f"Security context - negative test",
                False,
                f"Failed but not due to security context policy: {r.get('combined', '')[:200]}",
                "WARNING"
            ))
    
    os.unlink(negative_file)
    
    return tests

def test_pod_level_security_policy_with_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Test pod level security policy with specific constraint configuration"""
    tests = []
    test_name = f"test-podsec-{uuid.uuid4().hex[:8]}"
    test_ns = config['namespaces'][0] if config['namespaces'] else 'default'
    labels = config['labels']
    
    # Create namespace if needed
    if test_ns not in ['default', 'kube-system', 'kube-public']:
        run_command(f"kubectl create namespace {test_ns} --dry-run=client -o yaml | kubectl apply -f -", timeout=5)
    
    # Build label string
    label_lines = []
    for key, value in labels.items():
        label_lines.append(f"    {key}: {value}")
    labels_yaml = '\n'.join(label_lines) if label_lines else "    test: pod"
    
    # Positive test - Fully compliant pod
    positive_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-valid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(positive_yaml)
        positive_file = f.name
    
    cmd = f"kubectl apply -f {positive_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        tests.append(create_test_result(
            f"pod_security_positive_{config['name'][:20]}",
            f"Pod security - positive test (fully compliant, labels: {labels})",
            True,
            f"Fully compliant pod created successfully",
            "INFO"
        ))
        run_command(f"kubectl delete pod {test_name}-valid -n {test_ns} --ignore-not-found=true", timeout=10)
    else:
        error_msg = r.get('combined', '') or f"Exit code: {r.get('exit_code', 'unknown')}"
        tests.append(create_test_result(
            f"pod_security_positive_{config['name'][:20]}",
            f"Pod security - positive test",
            False,
            f"Failed: {error_msg[:200]}",
            "WARNING"
        ))
    
    os.unlink(positive_file)
    
    # Negative test - Violates ONLY pod-level security (hostNetwork=true)
    negative_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-invalid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  hostNetwork: true
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
    livenessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(negative_yaml)
        negative_file = f.name
    
    cmd = f"kubectl apply -f {negative_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) and ('denied the request' in r.get('combined', '')):
        tests.append(create_test_result(
            f"pod_security_negative_{config['name'][:20]}",
            f"Pod security - negative test (hostNetwork=true)",
            True,
            f"Pod with hostNetwork correctly rejected",
            "INFO"
        ))
    else:
        if ok(r):
            tests.append(create_test_result(
                f"pod_security_negative_{config['name'][:20]}",
                f"Pod security - negative test (hostNetwork)",
                False,
                f"Pod with hostNetwork was created when it should have been rejected",
                "WARNING"
            ))
            run_command(f"kubectl delete pod {test_name}-invalid -n {test_ns} --ignore-not-found=true", timeout=10)
        else:
            tests.append(create_test_result(
                f"pod_security_negative_{config['name'][:20]}",
                f"Pod security - negative test",
                False,
                f"Failed but not due to pod security policy: {r.get('combined', '')[:200]}",
                "WARNING"
            ))
    
    os.unlink(negative_file)
    
    return tests

def test_image_policy_with_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Test image policy with specific constraint configuration"""
    tests = []
    test_name = f"test-image-{uuid.uuid4().hex[:8]}"
    test_ns = config['namespaces'][0] if config['namespaces'] else 'default'
    labels = config['labels']
    
    # Create namespace if needed
    if test_ns not in ['default', 'kube-system', 'kube-public']:
        run_command(f"kubectl create namespace {test_ns} --dry-run=client -o yaml | kubectl apply -f -", timeout=5)
    
    # Build label string
    label_lines = []
    for key, value in labels.items():
        label_lines.append(f"    {key}: {value}")
    labels_yaml = '\n'.join(label_lines) if label_lines else "    test: pod"
    
    # Positive test - allowed image
    positive_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-valid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  containers:
  - name: test-container
    image: bitnami/postgresql:15.2.0
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(positive_yaml)
        positive_file = f.name
    
    cmd = f"kubectl apply -f {positive_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        tests.append(create_test_result(
            f"image_positive_{config['name'][:20]}",
            f"Image policy - positive test (allowed registry)",
            True,
            f"Pod with allowed image created successfully",
            "INFO"
        ))
        run_command(f"kubectl delete pod {test_name}-valid -n {test_ns} --ignore-not-found=true", timeout=10)
    else:
        tests.append(create_test_result(
            f"image_positive_{config['name'][:20]}",
            f"Image policy - positive test",
            False,
            f"Failed: {r.get('combined', '')[:200]}",
            "WARNING"
        ))
    
    os.unlink(positive_file)
    
    # Negative test - disallowed image
    negative_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {test_name}-invalid
  namespace: {test_ns}
  labels:
{labels_yaml}
spec:
  containers:
  - name: test-container
    image: nginx:latest
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(negative_yaml)
        negative_file = f.name
    
    cmd = f"kubectl apply -f {negative_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) and ('denied the request' in r.get('combined', '')):
        tests.append(create_test_result(
            f"image_negative_{config['name'][:20]}",
            f"Image policy - negative test (latest tag)",
            True,
            f"Pod with 'latest' tag correctly rejected",
            "INFO"
        ))
    else:
        if ok(r):
            tests.append(create_test_result(
                f"image_negative_{config['name'][:20]}",
                f"Image policy - negative test",
                False,
                f"Pod with 'latest' tag was created when it should have been rejected",
                "WARNING"
            ))
            run_command(f"kubectl delete pod {test_name}-invalid -n {test_ns} --ignore-not-found=true", timeout=10)
        else:
            tests.append(create_test_result(
                f"image_negative_{config['name'][:20]}",
                f"Image policy - negative test",
                False,
                f"Failed but not due to policy: {r.get('combined', '')[:200]}",
                "WARNING"
            ))
    
    os.unlink(negative_file)
    
    return tests

def test_label_deny_policy_with_config(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Test label deny policy with specific constraint configuration"""
    tests = []
    test_name = f"test-label-{uuid.uuid4().hex[:8]}"
    test_ns = config['namespaces'][0] if config['namespaces'] else 'production'
    
    # Create namespace if needed
    if test_ns not in ['default', 'kube-system', 'kube-public']:
        run_command(f"kubectl create namespace {test_ns} --dry-run=client -o yaml | kubectl apply -f -", timeout=5)
    
    # For label deny, the labels are REQUIRED, not selectors
    # This policy typically requires specific labels to be present
    
    # Positive test - WITH required labels
    positive_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {test_name}-valid
  namespace: {test_ns}
  labels:
    production: env
    label: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(positive_yaml)
        positive_file = f.name
    
    cmd = f"kubectl apply -f {positive_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if ok(r):
        tests.append(create_test_result(
            f"label_deny_positive_{config['name'][:20]}",
            f"Label deny - positive test (with required labels)",
            True,
            f"Deployment with required labels created in {test_ns}",
            "INFO"
        ))
        run_command(f"kubectl delete deployment {test_name}-valid -n {test_ns} --ignore-not-found=true", timeout=10)
    else:
        tests.append(create_test_result(
            f"label_deny_positive_{config['name'][:20]}",
            f"Label deny - positive test",
            False,
            f"Failed: {r.get('combined', '')[:200]}",
            "WARNING"
        ))
    
    os.unlink(positive_file)
    
    # Negative test - WITHOUT required labels
    negative_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {test_name}-invalid
  namespace: {test_ns}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(negative_yaml)
        negative_file = f.name
    
    cmd = f"kubectl apply -f {negative_file} 2>&1"
    r = run_command(cmd, timeout=10)
    
    if not ok(r) and ('denied the request' in r.get('combined', '')):
        tests.append(create_test_result(
            f"label_deny_negative_{config['name'][:20]}",
            f"Label deny - negative test (without labels)",
            True,
            f"Deployment without labels correctly rejected in {test_ns}",
            "INFO"
        ))
    else:
        if ok(r):
            tests.append(create_test_result(
                f"label_deny_negative_{config['name'][:20]}",
                f"Label deny - negative test",
                False,
                f"Deployment without labels was created when it should have been rejected",
                "WARNING"
            ))
            run_command(f"kubectl delete deployment {test_name}-invalid -n {test_ns} --ignore-not-found=true", timeout=10)
        else:
            tests.append(create_test_result(
                f"label_deny_negative_{config['name'][:20]}",
                f"Label deny - negative test",
                False,
                f"Failed but not due to policy: {r.get('combined', '')[:200]}",
                "WARNING"
            ))
    
    os.unlink(negative_file)
    
    return tests

def check_gatekeeper_logs(time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Check Gatekeeper pod logs for errors and violations"""
    tests = []
    
    # Check audit logs for violations
    cmd = f"kubectl logs -n {GATEKEEPER_NS} -l gatekeeper.sh/operation=audit --since={time_window_minutes}m --tail=100 2>&1"
    r = run_command(cmd, timeout=20)
    
    if ok(r) and r['stdout']:
        violation_count = r['stdout'].count('violations')
        error_count = r['stdout'].count('error')
        
        if error_count > 10:  # Threshold for concerning number of errors
            tests.append(create_test_result(
                "gatekeeper_audit_logs",
                f"Check Gatekeeper audit logs (last {time_window_minutes}m)",
                False,
                f"Found {error_count} errors in audit logs",
                "WARNING"
            ))
        else:
            tests.append(create_test_result(
                "gatekeeper_audit_logs",
                f"Check Gatekeeper audit logs (last {time_window_minutes}m)",
                True,
                f"Audit running normally, {violation_count} violation entries logged",
                "INFO"
            ))
    
    # Check controller logs
    cmd = f"kubectl logs -n {GATEKEEPER_NS} -l control-plane=controller-manager --since={time_window_minutes}m --tail=100 2>&1 | head -200"
    r = run_command(cmd, timeout=20)
    
    if ok(r) and r['stdout']:
        if 'panic' in r['stdout'].lower() or 'fatal' in r['stdout'].lower():
            tests.append(create_test_result(
                "gatekeeper_controller_logs",
                f"Check Gatekeeper controller logs (last {time_window_minutes}m)",
                False,
                "Found panic or fatal errors in controller logs",
                "CRITICAL"
            ))
        else:
            tests.append(create_test_result(
                "gatekeeper_controller_logs",
                f"Check Gatekeeper controller logs (last {time_window_minutes}m)",
                True,
                "Controller logs healthy",
                "INFO"
            ))
    
    return tests

def check_constraint_violations() -> List[Dict[str, Any]]:
    """Check for any existing constraint violations"""
    tests = []
    
    # Get all constraint types
    cmd = "kubectl get constraints -A -o json 2>/dev/null"
    r = run_command(cmd, timeout=15)
    
    total_violations = 0
    violation_details = []
    
    if ok(r) and r['stdout']:
        try:
            data = json.loads(r['stdout'])
            for item in data.get('items', []):
                violations = item.get('status', {}).get('totalViolations', 0)
                if violations > 0:
                    total_violations += violations
                    name = item.get('metadata', {}).get('name', 'unknown')
                    kind = item.get('kind', 'unknown')
                    violation_details.append(f"{kind}/{name}: {violations}")
        except:
            pass
    
    if total_violations > 0:
        tests.append(create_test_result(
            "constraint_violations",
            "Check for existing constraint violations",
            False,
            f"Found {total_violations} total violation(s): {', '.join(violation_details[:3])}{'...' if len(violation_details) > 3 else ''}",
            "WARNING"
        ))
    else:
        tests.append(create_test_result(
            "constraint_violations",
            "Check for existing constraint violations",
            True,
            "No constraint violations found",
            "INFO"
        ))
    
    return tests

# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------

def test_opa_gatekeeper() -> List[Dict[str, Any]]:
    """Main test runner for OPA Gatekeeper policies"""
    results: List[Dict[str, Any]] = []
    
    # 1) Gatekeeper connectivity (gate)
    gatekeeper_tests = check_gatekeeper_connectivity()
    results.extend(gatekeeper_tests)
    
    if not gatekeeper_tests[0]['status']:
        # Early exit if Gatekeeper not running
        return results
    
    # 2) Check constraint templates and run policy tests
    results.extend(check_constraint_templates())
    
    # 3) Check for existing violations
    results.extend(check_constraint_violations())
    
    # 4) Check Gatekeeper logs
    results.extend(check_gatekeeper_logs(time_window_minutes=5))
    
    return results

def main():
    """Main entry point"""
    try:
        # Print enabled policies for debugging
        enabled_policies = [k for k, v in POLICIES.items() if v]
        if enabled_policies:
            print(f"# Enabled policies: {', '.join(enabled_policies)}", file=sys.stderr)
        else:
            print("# No policies enabled via environment variables", file=sys.stderr)
        
        # Run tests
        results = test_opa_gatekeeper()
        
        # Output JSON results
        print(json.dumps(results, indent=2))
        
        # Exit with appropriate code
        critical_failures = [r for r in results if r['severity'] == 'critical' and not r['status']]
        sys.exit(1 if critical_failures else 0)
        
    except Exception as e:
        # Emergency fallback
        error_result = [{
            "name": "script_error",
            "description": "Script execution error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()
