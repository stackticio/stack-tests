# Test Script API Documentation

## Overview

This document describes the standardized structure for creating test scripts that integrate with our infrastructure testing API. All test scripts follow a consistent pattern to ensure compatibility and maintainability.

## Core Structure

### 1. Basic Function Pattern

Every test function must follow this exact pattern:

```python
def test_component_name() -> List[Dict]:
    """Brief description of what this test does"""
    # Test implementation
    return [{
        "name": "unique_test_identifier",
        "description": "Full description of what this test validates",
        "passed": True/False,  # Boolean result
        "output": "Human-readable detailed output string",
        "severity": "LOW/WARNING/CRITICAL"  # Impact level
    }]
```

### 2. Helper Function

All scripts must include this exact helper function:

```python
def run_command(command: str, env: Dict = None, timeout: int = 10) -> Dict:
    """Helper to run a shell command and capture stdout/stderr/exit code"""
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

## Return Dictionary Structure

### Required Fields

Each test function MUST return a list containing one or more dictionaries with these exact fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `name` | `str` | Unique identifier for the test | `"postgresql_connectivity"` |
| `description` | `str` | Full description of what the test validates | `"Test PostgreSQL server connectivity"` |
| `passed` | `bool` | Whether the test passed or failed | `True` or `False` |
| `output` | `str` | Detailed human-readable result message | `"Connected to PostgreSQL 14.5 at host:5432"` |
| `severity` | `str` | Impact level if test fails | `"LOW"`, `"WARNING"`, or `"CRITICAL"` |

### Severity Levels

- **`CRITICAL`**: Service is completely down or core functionality is broken
- **`WARNING`**: Service is degraded or non-essential features are failing  
- **`LOW`**: Informational or minor issues that don't impact functionality

## Naming Conventions

### Function Names

Test functions must follow this pattern:
- Main tests: `test_<component>_<aspect>()`
- Sub-tests: `<component>_<specific>_<test>()`

Examples:
```python
# Main test functions (return List[Dict])
def test_postgresql_connectivity() -> List[Dict]:
def test_postgresql_list_databases() -> List[Dict]:

# Sub-test functions (return Dict) - called by test_databases()
def postgresql_db_connectivity(db_info: Dict) -> Dict:
def postgresql_db_write(db_info: Dict) -> Dict:
```

### Test Name Field

The `name` field should follow: `<component>_<specific>_<aspect>`

Examples:
- `postgresql_connectivity`
- `postgresql_myapp_write`
- `grafana_datasource_connectivity`

## Environment Variables

Scripts should read configuration from environment variables with sensible defaults:

```python
host = os.getenv("POSTGRESQL_HOST", "default-host.cluster.local")
port = os.getenv("POSTGRESQL_PORT", "5432")
namespace = os.getenv("COMPONENT_NAMESPACE", "default")
```

## Output Field Guidelines

The `output` field should provide actionable information:

### Good Output Examples
```python
# Specific details about success
"Connected to PostgreSQL 14.5 at db.example.com:5432, response time: 0.5s"

# Clear failure reason with details
"Authentication failed for user 'appuser' on database 'myapp'"

# Aggregate information
"Total databases: 5 (System: 2, User: 3 - app_db, test_db, prod_db)"

# Multiple data points
"All 3 pods healthy | prometheus-server: 1, alertmanager: 1, node-exporter: 1"
```

### Poor Output Examples
```python
# Too generic
"Test passed"
"Connection failed"

# Not actionable
"Error"
"Something went wrong"
```

## Pattern for Testing Multiple Items

When testing multiple databases/users/routes, use this pattern:

```python
def _get_databases() -> List[Dict]:
    """Parse databases from environment variable"""
    databases = []
    databases_env = os.getenv("POSTGRES_DATABASES", "")
    for db_config in databases_env.split(";"):
        if db_config.strip():
            parts = db_config.strip().split(":")
            if len(parts) >= 4:
                databases.append({
                    "name": parts[0],
                    "user": parts[1],
                    "password": parts[2],
                    "database": parts[3]
                })
    return databases

def test_databases() -> List[Dict]:
    """Test all configured databases"""
    databases = _get_databases()
    results = []
    
    for database in databases:
        results.append(postgresql_db_connectivity(database))
        results.append(postgresql_db_write(database))
        results.append(postgresql_db_tables(database))
    
    return results
```

## Complete Example - PostgreSQL Test

```python
#!/usr/bin/env python3
import os
from typing import List, Dict
import subprocess

def run_command(command: str, env: Dict = None, timeout: int = 10) -> Dict:
    """Helper to run a shell command and capture stdout/stderr/exit code"""
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

def test_postgresql_connectivity() -> List[Dict]:
    """Test PostgreSQL server connectivity"""
    host = os.getenv("POSTGRESQL_HOST", "localhost")
    port = os.getenv("POSTGRESQL_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    result = run_command(f'psql "{conn_str}" -c "SELECT version();"')

    if result["exit_code"] == 0 and "PostgreSQL" in result["stdout"]:
        # Extract version for detailed output
        version = "unknown"
        for line in result["stdout"].split('\n'):
            if "PostgreSQL" in line:
                version = line.strip()
                break
        
        return [{
            "name": "postgresql_connectivity",
            "description": "Test PostgreSQL server connectivity",
            "passed": True,
            "output": f"Connected to {version} at {host}:{port}",
            "severity": "LOW"
        }]
    
    return [{
        "name": "postgresql_connectivity",
        "description": "Test PostgreSQL server connectivity", 
        "passed": False,
        "output": f"Connection failed to {host}:{port}: {result.get('stderr', 'Unknown error')}",
        "severity": "CRITICAL"
    }]
```

## Usage in Your API

Your API can call these functions and aggregate results:

```python
# Collect all test results
results = []
results.extend(test_postgresql_connectivity())
results.extend(test_postgresql_list_databases())
results.extend(test_databases())

# Process results
for result in results:
    # API can access standardized fields
    test_name = result['name']
    test_passed = result['passed']
    test_output = result['output']
    test_severity = result['severity']
    test_description = result['description']
    
    # Store, display, or process as needed
```

## Best Practices

1. **Always return the exact dictionary structure** - Missing fields will break the API
2. **Make output actionable** - Include specific values, counts, and identifiers
3. **Use appropriate severity** - Don't mark everything as CRITICAL
4. **Handle errors gracefully** - Return a proper failure dict rather than raising exceptions
5. **Keep functions focused** - One test per function, return multiple dicts if testing multiple items
6. **Use environment variables** - Never hardcode credentials or endpoints
7. **Provide context in output** - Include hostnames, ports, versions, counts, etc.

## Testing Your Script

Before integration, verify your script follows the structure:

```python
# Test that all functions return correct structure
import your_test_script

results = your_test_script.test_your_component()

for result in results:
    assert 'name' in result
    assert 'description' in result
    assert 'passed' in result
    assert 'output' in result
    assert 'severity' in result
    assert isinstance(result['passed'], bool)
    assert result['severity'] in ['LOW', 'WARNING', 'CRITICAL']
    print(f"✓ {result['name']} structure valid")
```

## Summary

Following this structure ensures:
- Consistent API integration
- Clear test results
- Actionable output messages
- Proper error handling
- Easy maintenance and debugging

All test scripts in the system follow this exact pattern, making them predictable and reliable for automated infrastructure testing.
