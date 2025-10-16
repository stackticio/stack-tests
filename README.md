# Testing Script Development Guide

## Overview

This guide explains how to write test scripts that integrate with our testing API. All test scripts must follow a standardized JSON output format.

## Basic Structure Requirements

### 1. JSON Output Format

Each test result must be a JSON object with these exact fields:

```json
{
  "name": "unique_test_identifier",
  "description": "Human-readable test description",
  "status": true,
  "output": "Detailed test results or error message",
  "severity": "INFO"
}
```

#### Field Requirements

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier (lowercase with underscores) |
| `description` | string | No | Human-readable test description |
| `status` | boolean | Yes | `true` for pass, `false` for fail |
| `output` | string | Yes | Detailed test results or error message |
| `severity` | string | Yes | One of: `INFO`, `WARNING`, `CRITICAL` |

### 2. Script Output

Your script must output a **JSON array** to stdout:

```python
if __name__ == "__main__":
    results = []
    
    # Run your tests
    results.append(test_connectivity())
    results.append(test_health())
    
    # Output JSON array to stdout
    print(json.dumps(results, indent=2))
```

### 3. Environment Variables

Use environment variables for configuration:

```python
# Namespace/location
NAMESPACE = os.getenv('COMPONENT_NS', 'default-namespace')

# Connection details
HOST = os.getenv('COMPONENT_HOST', 'service.namespace.svc.cluster.local')
PORT = os.getenv('COMPONENT_PORT', '8080')

# Credentials (if needed)
USERNAME = os.getenv('COMPONENT_USER', 'admin')
PASSWORD = os.getenv('COMPONENT_PASSWORD', 'password')
```

### 4. Helper Function Pattern

Use this standard helper for running commands:

```python
def run_command(command: str, env: Dict = None, timeout: int = 30) -> Dict:
    """Run shell command and return result"""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            env=env or os.environ.copy(),
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
```

### 5. Test Function Pattern

Each test should return a properly formatted result:

```python
def test_service_health() -> Dict:
    """Test service health endpoint"""
    cmd = f"curl -s http://{HOST}:{PORT}/health"
    result = run_command(cmd, timeout=10)
    
    passed = result["exit_code"] == 0
    
    return {
        "name": "service_health_check",
        "description": "Check if service is responding",
        "status": passed,
        "output": result["stdout"] if passed else f"Failed: {result['stderr']}",
        "severity": "CRITICAL" if not passed else "INFO"
    }
```

### 6. Severity Guidelines

- **`INFO`**: Test passed or informational result
- **`WARNING`**: Non-critical failure, service degraded but functional
- **`CRITICAL`**: Critical failure, service is down or unusable

### 7. Exit Codes (Optional but Recommended)

```python
def main():
    results = test_all()
    print(json.dumps(results, indent=2))
    
    # Exit with appropriate code
    critical_failures = [r for r in results 
                        if not r['status'] and r['severity'] == 'CRITICAL']
    return 1 if critical_failures else 0

if __name__ == "__main__":
    sys.exit(main())
```

## Quick Start Template

```python
#!/usr/bin/env python3
import os
import json
import subprocess
from typing import List, Dict

def run_command(command: str, timeout: int = 30) -> Dict:
    """Run shell command and return result"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        return {
            "exit_code": result.returncode, 
            "stdout": result.stdout.strip(), 
            "stderr": result.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "Timeout"}

def test_my_service() -> Dict:
    """Example test function"""
    result = run_command("your-test-command")
    
    return {
        "name": "my_service_test",
        "description": "Test my service functionality",
        "status": result["exit_code"] == 0,
        "output": result["stdout"] or result["stderr"],
        "severity": "CRITICAL" if result["exit_code"] != 0 else "INFO"
    }

def main():
    """Main entry point"""
    results = []
    
    # Add your tests here
    results.append(test_my_service())
    
    # Output JSON to stdout
    print(json.dumps(results, indent=2))
    
    # Return exit code based on critical failures
    critical_failures = [r for r in results 
                        if not r['status'] and r['severity'] == 'CRITICAL']
    return 1 if critical_failures else 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
```

## Examples

See the following reference implementations:

- `test_apisix.py` - APISIX gateway testing
- `test_kafka.py` - Kafka broker testing  
- `test_minio.py` - MinIO object storage testing

## API Integration

Once your script follows this format, it can be integrated with the testing API:

**POST** `/tests/run`

```json
{
  "system_id": "my-system",
  "component": "my-service",
  "host_url": "http://production-host.example.com",
  "stack_url": "http://stack1.example.com:8000",
  "git_url": "https://github.com/myorg/myrepo.git",
  "git_branch": "main",
  "git_folder_hierarchy": "tests",
  "git_token": "ghp_xxxxxxxxxxxxx",
  "custom_tests": ["test_my_service"]
}
```

## Best Practices

1. **Always validate inputs** - Check environment variables and fail gracefully
2. **Use descriptive names** - Test names should clearly indicate what's being tested
3. **Provide detailed output** - Include relevant information in the output field
4. **Set appropriate severity** - Use CRITICAL for service-down scenarios
5. **Handle timeouts** - Set reasonable timeouts for all operations
6. **Clean up resources** - Remove temporary files/resources created during tests
7. **Test independently** - Each test should be runnable on its own
8. **Document environment variables** - List all required env vars at the top of your script

## Common Patterns

### Testing Kubernetes Resources

```python
def test_pod_health() -> Dict:
    namespace = os.getenv('K8S_NAMESPACE', 'default')
    cmd = f"kubectl get pods -n {namespace} -l app=myapp --no-headers"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        pods = result["stdout"].split("\n")
        running = [p for p in pods if "Running" in p]
        status = len(running) == len(pods)
        output = f"Pods: {len(running)}/{len(pods)} running"
    else:
        status = False
        output = f"Failed to get pods: {result['stderr']}"
    
    return {
        "name": "k8s_pod_health",
        "status": status,
        "output": output,
        "severity": "CRITICAL" if not status else "INFO"
    }
```

### Testing HTTP Endpoints

```python
def test_http_endpoint() -> Dict:
    url = os.getenv('SERVICE_URL', 'http://localhost:8080')
    cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}/health"
    result = run_command(cmd, timeout=5)
    
    http_code = result["stdout"]
    status = http_code in ["200", "204"]
    
    return {
        "name": "http_health_check",
        "status": status,
        "output": f"HTTP {http_code}" if result["exit_code"] == 0 else "Connection failed",
        "severity": "CRITICAL" if not status else "INFO"
    }
```

### Testing with Authentication

```python
def test_authenticated_endpoint() -> Dict:
    url = os.getenv('API_URL')
    token = os.getenv('API_TOKEN')
    
    cmd = f"curl -s -H 'Authorization: Bearer {token}' {url}/api/status"
    result = run_command(cmd, timeout=10)
    
    try:
        data = json.loads(result["stdout"])
        status = data.get("status") == "healthy"
        output = f"Service status: {data.get('status')}"
    except:
        status = False
        output = "Failed to parse response"
    
    return {
        "name": "api_auth_check",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }
```

## Troubleshooting

### Common Issues

1. **Script doesn't produce JSON output**
   - Ensure you're using `print(json.dumps(results))` 
   - Check for print statements that output non-JSON data

2. **Tests timeout**
   - Increase timeout values in `run_command()`
   - Check for blocking operations

3. **Environment variables not found**
   - Provide sensible defaults with `os.getenv('VAR', 'default')`
   - Document all required variables

4. **Inconsistent test results**
   - Ensure tests clean up after themselves
   - Avoid dependencies between tests

---

**That's it!** Follow this structure and your script will integrate seamlessly with the testing API.
