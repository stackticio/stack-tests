# Stack Testing Framework

> **Automated, metadata-driven testing for Kubernetes infrastructure components**

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture: Stacktic → Stack Agent → Tests](#architecture-stacktic--stack-agent--tests)
3. [How It Works](#how-it-works)
4. [Multi-Resource ENV Format](#multi-resource-env-format)
5. [Test Development Guide](#test-development-guide)
6. [Examples](#examples)

---

## Overview

This testing framework **automatically discovers and tests infrastructure components** deployed via Stacktic templates. The key innovation is that **tests are automatically customized** based on actual deployed resources - no manual configuration needed.

**Key Features:**
- 🔍 **Auto-Discovery**: Finds components from environment variables
- 📦 **Multi-Resource Testing**: Tests all databases, queues, buckets per component
- 🎯 **Dynamic Generation**: Tests adapt to deployed resources
- 🏗️ **Metadata-Driven**: Leverages Stacktic component information
- 🌐 **Cross-Stack Ready**: Can test components across multiple stacks

**The Problem We Solve:**

Traditional testing requires manually writing tests for each deployed component:
```python
# ❌ Manual approach - breaks when configuration changes
test_mongodb_db1()
test_mongodb_db2()
test_kafka_topic1()
test_kafka_topic2()
```

Our approach auto-generates tests from metadata:
```python
# ✅ Automated approach - adapts to configuration
for db in parse_databases_from_env():
    test_mongodb_connection(db)
for topic in parse_topics_from_env():
    test_kafka_topic(topic)
```

---

## Architecture: Stacktic → Stack Agent → Tests

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    STACKTIC TESTING ARCHITECTURE                              │
└──────────────────────────────────────────────────────────────────────────────┘

Step 1: Template Generation (Stacktic)
┌─────────────────────────────────────┐
│  Stacktic Templates                 │
│  (/Users/.../dev/templates/)        │
│                                     │
│  ├─ mongodb/                        │
│  │  └─ Generates cloud.env:         │
│  │     MONGODB_HOST=...             │
│  │     MONGODB_DATABASES=           │
│  │       "db1:user1:pass1:...;      │
│  │        db2:user2:pass2:..."      │
│  │                                  │
│  ├─ kafka/                          │
│  │  └─ Generates cloud.env:         │
│  │     KAFKA_HOST=...               │
│  │     KAFKA_TOPICS="topic1,..."    │
│  │                                  │
│  └─ stack_agent/                    │
│     └─ Embeds test files from       │
│        this repository              │
└─────────────────────────────────────┘
            │
            ▼
Step 2: Stack Agent Deployment
┌─────────────────────────────────────┐
│  Stack Agent Pod (Kubernetes)       │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  Component Discovery          │ │
│  │  (from ENV variables)         │ │
│  │                               │ │
│  │  Scans for: *_HOST            │ │
│  │  Finds: MONGODB_HOST,         │ │
│  │         KAFKA_HOST,           │ │
│  │         RABBITMQ_HOST         │ │
│  └────────────┬──────────────────┘ │
│               │                     │
│               ▼                     │
│  ┌───────────────────────────────┐ │
│  │  Test Definition Loader       │ │
│  │                               │ │
│  │  Loads: test_mongodb.py       │ │
│  │         test_kafka.py         │ │
│  │         test_rabbitmq.py      │ │
│  └────────────┬──────────────────┘ │
│               │                     │
│               ▼                     │
│  ┌───────────────────────────────┐ │
│  │  Dynamic Test Generator       │ │
│  │                               │ │
│  │  Parses multi-resource ENVs:  │ │
│  │  MONGODB_DATABASES split by ; │ │
│  │  → [db1, db2, db3]            │ │
│  │                               │ │
│  │  Generates test per resource  │ │
│  └────────────┬──────────────────┘ │
└───────────────┼────────────────────┘
                │
                ▼
Step 3: Test Execution
┌─────────────────────────────────────┐
│  Test Scripts (This Repository)    │
│  (/Users/.../dev/stack-tests/)     │
│                                     │
│  components/test_mongodb.py         │
│    ├─ Parses MONGODB_DATABASES     │
│    ├─ Generates connectivity test  │
│    │  for EACH database            │
│    ├─ Generates collection test    │
│    │  for EACH collection          │
│    └─ Returns JSON results          │
│                                     │
│  components/test_kafka.py           │
│    ├─ Parses KAFKA_TOPICS          │
│    ├─ Tests EACH topic             │
│    └─ Returns JSON results          │
└─────────────────────────────────────┘
                │
                ▼
Step 4: Results
┌─────────────────────────────────────┐
│  JSON Test Results                  │
│                                     │
│  [                                  │
│    {                                │
│      "name": "mongodb_db1_connect", │
│      "status": true,                │
│      "severity": "INFO"             │
│    },                               │
│    {                                │
│      "name": "kafka_topic1_check",  │
│      "status": true,                │
│      "severity": "INFO"             │
│    }                                │
│  ]                                  │
└─────────────────────────────────────┘
```

---

## How It Works

### 1. Stacktic Generates Component Metadata

When templates are rendered, Stacktic generates **structured environment variables** encoding component information:

**MongoDB Template** (`templates/mongodb/`):
```jinja2
{# Collect all database sub-components #}
{% set __database = [] %}
{% for sub_comp in cookiecutter.sub_components.values() %}
  {% if sub_comp.type == "database" %}
    {{ __database.append(sub_comp) }}
  {% endif %}
{% endfor %}

{# Generate ENV with multiple databases #}
MONGODB_DATABASES="
{%- for db in __database -%}
  {%- if not loop.first %};{% endif -%}
  {{ db.name }}:{{ db.attributes.username }}:{{ db.attributes.password }}:{{ db.attributes.auth_database }}:{{ db.attributes.collection }}
{%- endfor -%}"
```

**Generated ENV (`cloud.env`):**
```bash
MONGODB_HOST=mongodb-mongos.mongodb.svc.cluster.local
MONGODB_PORT=27017
MONGODB_CLUSTER_ADMIN_PASSWORD=abc123
MONGODB_DATABASES="orders:orders_user:pass1:admin:transactions;users:users_user:pass2:admin:profiles;logs:logs_user:pass3:admin:events"
```

### 2. Stack Agent Discovers Components

Stack Agent scans environment variables to find components:

```python
# From stack_agent template: stack_test_definitions.py
def discover_components_from_env() -> List[str]:
    """Discovers components from _HOST environment variables"""
    components = set()

    for key in os.environ:
        if '_HOST' in key:
            # MONGODB_HOST → mongodb
            # KAFKA_HOST → kafka
            # RABBITMQ_RABBITMQ_HOST → rabbitmq
            component = key.replace('_HOST', '').lower().split('_')[0]
            components.add(component)

    return sorted(list(components))

# Result: ['mongodb', 'kafka', 'rabbitmq']
```

### 3. Tests Parse Multi-Resource ENVs

Each test file parses the structured ENV to extract resources:

```python
# From components/test_mongodb.py
def parse_databases() -> List[Dict[str, str]]:
    """
    Parse MONGODB_DATABASES environment variable
    Format: db1:user1:pass1:authdb1:collection1;db2:user2:pass2:authdb2:collection2
    """
    databases = []
    databases_env = os.getenv('MONGODB_DATABASES', '')

    for db_config in databases_env.split(';'):
        if db_config.strip():
            parts = db_config.strip().split(':')
            if len(parts) >= 5:
                databases.append({
                    'database': parts[0],
                    'username': parts[1],
                    'password': parts[2],
                    'auth_database': parts[3],
                    'collection': parts[4]
                })

    return databases

# Result: [
#   {'database': 'orders', 'username': 'orders_user', 'password': 'pass1', ...},
#   {'database': 'users', 'username': 'users_user', 'password': 'pass2', ...},
#   {'database': 'logs', 'username': 'logs_user', 'password': 'pass3', ...}
# ]
```

### 4. Tests Generated Per Resource

For **each database**, generate specific tests:

```python
def check_database_auth() -> List[Dict[str, Any]]:
    """Test authentication for each configured database"""
    tests = []

    for db in DATABASES:
        # Connectivity test for THIS database
        tests.append({
            'name': f'mongodb_{db["database"]}_connectivity',
            'description': f'Test {db["database"]} connectivity',
            'command': 'mongosh',
            'args': [
                f'--host={MONGO_HOST}:{MONGO_PORT}',
                f'--username={db["username"]}',
                f'--password={db["password"]}',
                f'--authenticationDatabase={db["auth_database"]}',
                '--eval', f'db.getSiblingDB("{db["database"]}").runCommand({{ ping: 1 }})'
            ],
            'timeout': 30,
            'severity': 'CRITICAL'
        })

        # Collection test for THIS database
        tests.append({
            'name': f'mongodb_{db["database"]}_collection_{db["collection"]}',
            'description': f'Check {db["collection"]} exists in {db["database"]}',
            'command': 'mongosh',
            'args': [...],  # Check collection
            'timeout': 30,
            'severity': 'WARNING'
        })

    return tests

# Result: 6 tests total (2 tests × 3 databases)
```

---

## Multi-Resource ENV Format

### Supported Component Types

| Component | ENV Variable | Format |
|-----------|-------------|--------|
| **MongoDB** | `MONGODB_DATABASES` | `db:user:pass:authdb:collection;...` |
| **PostgreSQL/CNPG** | `POSTGRES_DATABASES` | `name:user:pass:database;...` |
| **RabbitMQ** | `RABBITMQ_QUEUES` | `queue1,queue2,...` |
| | `RABBITMQ_EXCHANGES` | `exchange1,exchange2,...` |
| **MinIO** | `MINIO_BUCKETS` | `name:bucket:accesskey:secretkey;...` |
| **Kafka** | `KAFKA_TOPICS` | `topic1,topic2,...` |

### Format Examples

**MongoDB:**
```bash
MONGODB_DATABASES="orders:ord_user:pass1:admin:txns;users:usr_user:pass2:admin:profiles"
```

**PostgreSQL:**
```bash
POSTGRES_DATABASES="app1:app1_user:pass1:app1_db;app2:app2_user:pass2:app2_db"
```

**RabbitMQ:**
```bash
RABBITMQ_QUEUES="orders.new,orders.processed,users.created"
RABBITMQ_EXCHANGES="orders,users,notifications"
```

**MinIO:**
```bash
MINIO_BUCKETS="models:ml-models:minio-access-key:minio-secret-key;logs:app-logs:log-access:log-secret"
```

### Why This Format?

1. **Single ENV Variable**: All resources in one place
2. **Parseable**: Simple split operations (`;` for records, `:` for fields)
3. **Complete Information**: Includes credentials, namespaces, collections
4. **Generated Automatically**: Templates create this from sub-components
5. **No Manual Updates**: Adding/removing resources updates tests automatically

---

## Test Development Guide

This guide explains how to write test scripts that integrate with the testing framework. All test scripts must follow a standardized JSON output format.

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

## Cross-Stack Testing (Future Enhancement)

### Current State: Single Stack

Currently, Stack Agent tests components within a single stack using ENV-based discovery.

### Future: Multi-Stack Testing with `is_referenced`

Stack Agent templates **could leverage** Stacktic's global component registry (similar to Grafana multi-stack dashboards) to enable cross-stack testing:

```python
# Potential enhancement in stack_agent template

# Access global component registry
{% for comp_name, comp in cookiecutter.components.items() %}
  {% if comp.is_referenced %}
    # This is a remote component from another stack
    # Generate connectivity/health tests (read-only)

    # Example: Remote MongoDB from stack-2
    STACK_2_MONGODB_HOST={{ comp.attributes.host }}
    STACK_2_MONGODB_PORT={{ comp.attributes.port }}
    STACK_2_MONGODB_REMOTE=true  # Flag for limited testing
  {% endif %}
{% endfor %}
```

### Use Case: Centralized Testing from SRE Stack

```
SRE Stack (Testing Hub)
      │
      ├─ Stack Agent Pod
      │    │
      │    ├─ Local Components:
      │    │   - prometheus-master (full tests)
      │    │   - grafana (full tests)
      │    │
      │    ├─ Remote Components (is_referenced: true):
      │    │   - stack-2-prometheus (connectivity tests)
      │    │   - stack-2-mongodb (health checks)
      │    │   - stack-3-kafka (topic verification)
      │    │
      │    └─ Generated Tests:
      │        ├─ Local: Full access tests
      │        └─ Remote: Connectivity + health tests
      │
      └─ Single dashboard showing all stack health
```

### Benefits

- **Centralized Testing**: One Stack Agent tests multiple stacks
- **Auto-Discovery**: No manual configuration for remote components
- **Dynamic Updates**: Adding/removing stacks automatically updates tests
- **Cross-Stack Validation**: Verify cross-stack connections (remote_write, federation)

---

## Related Documentation

- **Stacktic Templates** (`/Users/.../dev/templates/`):
  - See `AI-README.md` - Multi-stack architecture overview
  - See `TEMPLATING-GUIDE.md` - Global component registry (`is_referenced`)
  - See `grafana/README.md` - Multi-stack dashboard example
  - See `stack_agent/AI-README.md` - Stack Agent architecture

- **Multi-Stack Concepts**:
  - `cookiecutter.components` - Global registry across all stacks
  - `is_referenced: true` - Marks components from other stacks
  - `links_from` / `links_to` - Cross-stack relationships

---

**That's it!** Follow this structure and your script will integrate seamlessly with the testing framework.

**Key Takeaways:**
- ✅ Tests auto-discover components from ENV variables
- ✅ Tests auto-customize based on deployed resources
- ✅ Templates generate the ENV format automatically
- ✅ Stack Agent orchestrates discovery and execution
- ✅ Cross-stack testing possible via global component registry
