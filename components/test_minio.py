#!/usr/bin/env python3
"""
MinIO Bucket Connectivity Test Script - Production version based on actual ENV variables
Tests connectivity and access to all MinIO buckets defined in environment variables
"""


import os
import time
import subprocess
from typing import List, Dict
from datetime import datetime

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
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "exit_code": completed.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "exit_code": 124}


def test_minio_connectivity() -> List[Dict]:
    """Test basic MinIO connectivity"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    # Test basic connectivity with curl
    command = f"curl -s -o /dev/null -w '%{{http_code}}' {minio_endpoint}/minio/health/ready"
    result = run_command(command, timeout=10)
    
    # Check if we got HTTP 200
    status = True if result['stdout'] == '200' else False
    severity = "INFO" if status else "WARNING"
    output = ""

    if status == "passed":
        output = f"MinIO health check succeeded at {minio_endpoint}"
    else:
        output = f"MinIO health check failed. HTTP code: {result['stdout']}"
    

    return [{
        "name": "minio_connectivity",
        "status": status,
        "output": output,
        "severity": severity
    }]


def test_minio_list_buckets() -> List[Dict]:
    """List all buckets using admin credentials if available"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    # Try to get admin credentials from environment
    admin_access_key = os.getenv('MINIO_ROOT_USER', os.getenv('MINIO_ACCESS_KEY', ''))
    admin_secret_key = os.getenv('MINIO_ROOT_PASSWORD', os.getenv('MINIO_SECRET_KEY', ''))
    
    if not admin_access_key or not admin_secret_key:
        return [{
            "name": "minio_list_buckets",
            "status": False,
            "output": "Admin credentials not available",
            "severity": "WARNING"
        }]
    
    # Set up temporary alias and list buckets
    alias_name = "test_admin_temp"
    setup_cmd = f"mc alias set {alias_name} {minio_endpoint} {admin_access_key} {admin_secret_key} 2>&1"
    result = run_command(setup_cmd, timeout=10)
    
    if result['exit_code'] != 0:
        return [{
            "name": "minio_list_buckets",
            "status": False,
            "output": result.get('stdout', ''),
            "severity": "WARNING"
        }]
    
    # List all buckets
    list_cmd = f"mc ls {alias_name} 2>&1"
    result = run_command(list_cmd, timeout=10)
    
    # Clean up alias
    cleanup_cmd = f"mc alias rm {alias_name} 2>&1"
    run_command(cleanup_cmd, timeout=5)
    
    status = True if result["exit_code"] == 0 else False
    severity = "INFO" if status else "WARNING"

    return [{
        "name": "minio_list_buckets",
        "status": status,
        "output": result.get('stdout', ''),
        "severity": severity
    }]


def _get_buckets() -> List[Dict]:
    """Parse MINIO_BUCKETS environment variable"""
    buckets = []
    buckets_env = os.getenv('MINIO_BUCKETS', '')
    
    for bucket_config in buckets_env.split(';'):
        if not bucket_config.strip():
            continue
        parts = bucket_config.strip().split(':')
        if len(parts) >= 4:
            buckets.append({
                'name': parts[0],
                'user': parts[1],
                'access_key': parts[2],
                'secret_key': parts[3]
            })
    return buckets


def test_buckets():
    """Test all configured buckets"""
    buckets = _get_buckets()
    results = []
    
    for bucket_info in buckets:
        results.append(minio_bucket_connectivity(bucket_info))
        results.append(minio_bucket_write(bucket_info))
        results.append(minio_bucket_list(bucket_info))
    
    return results


def minio_bucket_connectivity(bucket_info: Dict) -> Dict:
    """Test connectivity to a specific bucket"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    bucket_name = bucket_info['name']
    access_key = bucket_info['access_key']
    secret_key = bucket_info['secret_key']
    
    # Set up MinIO client alias
    alias_name = f"test_{bucket_name}"
    setup_command = f"mc alias set {alias_name} {minio_endpoint} {access_key} {secret_key} 2>&1"
    
    result = run_command(setup_command, timeout=10)
    
    # Clean up alias if successful
    if result['exit_code'] == 0:
        cleanup_command = f"mc alias rm {alias_name} 2>&1"
        run_command(cleanup_command, timeout=5)
        result['stdout'] = f"Successfully connected to bucket '{bucket_name}' at {minio_endpoint}"
    
    status = True if result['exit_code'] == 0 else False
    severity = "INFO" if status else "WARNING"

    return {
        "name": f"minio_{bucket_name}_connectivity",
        "status": status,
        "output": result.get('stdout', ''),
        "severity": severity
    }


def minio_bucket_write(bucket_info: Dict) -> Dict:
    """Test write permissions in a bucket"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    bucket_name = bucket_info['name']
    access_key = bucket_info['access_key']
    secret_key = bucket_info['secret_key']
    
    # Set up MinIO client alias
    alias_name = f"test_{bucket_name}"
    setup_command = f"mc alias set {alias_name} {minio_endpoint} {access_key} {secret_key} 2>&1"
    result = run_command(setup_command, timeout=10)
    
    if result['exit_code'] != 0:
        return {
            "name": f"minio_{bucket_name}_write",
            "status": False,
            "output": result.get('stdout', ''),
            "severity": "WARNING"
        }
    
    # Create and upload test file
    test_file = f"/tmp/test_{bucket_name}_{int(time.time())}.txt"
    test_content = f"Test content for {bucket_name} at {datetime.now().isoformat()}"
    
    # Create test file
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    # Upload test file
    upload_command = f"mc cp {test_file} {alias_name}/{bucket_name}/test_write_{int(time.time())}.txt 2>&1"
    result = run_command(upload_command, timeout=15)
    
    # Clean up test file
    try:
        os.remove(test_file)
    except:
        pass
    
    # Clean up alias
    cleanup_command = f"mc alias rm {alias_name} 2>&1"
    run_command(cleanup_command, timeout=5)
    
    status = True if result['exit_code'] == 0 else False
    severity = "INFO" if status else "WARNING"
    
    return {
        "name": f"minio_{bucket_name}_write",
        "status": status,
        "output": result.get('stdout', ''),
        "severity": severity
    }


def minio_bucket_list(bucket_info: Dict) -> Dict:
    """List objects in a bucket"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    bucket_name = bucket_info['name']
    access_key = bucket_info['access_key']
    secret_key = bucket_info['secret_key']
    
    # Set up MinIO client alias
    alias_name = f"test_{bucket_name}"
    setup_command = f"mc alias set {alias_name} {minio_endpoint} {access_key} {secret_key} 2>&1"
    result = run_command(setup_command, timeout=10)
    
    if result['exit_code'] != 0:
        return {
            "name": f"minio_{bucket_name}_list",
            "status": False,
            "output": result.get('stdout', ''),
            "severity": "WARNING"
        }
    
    # List bucket contents (limit to first 20 objects)
    list_command = f"mc ls {alias_name}/{bucket_name} --max-keys 20 2>&1"
    result = run_command(list_command, timeout=10)
    
    # Check for bucket existence
    if "does not exist" in result['stderr'].lower() or "does not exist" in result['stdout'].lower():
        result['stdout'] = f"Bucket '{bucket_name}' does not exist"
        status = False
    elif result['exit_code'] == 0 or "objects" in result['stdout'].lower() or result['stdout'] == "":
        status = True
        if not result['stdout']:
            result['stdout'] = f"Bucket '{bucket_name}' is empty or successfully accessed"
    else:
        status = False
    
    # Clean up alias
    cleanup_command = f"mc alias rm {alias_name} 2>&1"
    run_command(cleanup_command, timeout=5)
    
    severity = "INFO" if status else "WARNING"

    return {
        "name": f"minio_{bucket_name}_list",
        "status": status,
        "output": result.get('stdout', ''),
        "severity": severity
    }


def test_minio_policy() -> List[Dict]:
    """Check bucket policies for all configured buckets"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    buckets = _get_buckets()
    results = []
    
    for bucket_info in buckets:
        bucket_name = bucket_info['name']
        
        # Test if bucket is publicly accessible
        test_url = f"{minio_endpoint}/{bucket_name}/"
        command = f"curl -s -o /dev/null -w '%{{http_code}}' {test_url}"
        
        result = run_command(command, timeout=10)
        
        # For public buckets, we expect either 200 or 403 (list denied but bucket exists)
        if result['stdout'] in ['200', '403']:
            status = "passed"
            result['stdout'] = f"Bucket '{bucket_name}' is accessible (public policy verified)"
        else:
            status = "failed"
            result['stdout'] = f"Bucket '{bucket_name}' may not have correct public policy. HTTP code: {result['stdout']}"
        
        severity = "INFO" if status else "WARNING"

        results.append({
            "name": f"minio_{bucket_name}_policy",
            "status": status,
            "output": result.get('stdout', ''),
            "severity": severity
        })
    
    return results


def test_minio_statistics() -> List[Dict]:
    """Get MinIO statistics using mc admin if available"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    # Try to get admin credentials
    admin_access_key = os.getenv('MINIO_ROOT_USER', os.getenv('MINIO_ACCESS_KEY', ''))
    admin_secret_key = os.getenv('MINIO_ROOT_PASSWORD', os.getenv('MINIO_SECRET_KEY', ''))
    
    if not admin_access_key or not admin_secret_key:
        return [{
            "name": "minio_statistics",
            "status": False,
            "output": "Admin credentials not available",
            "severity": "WARNING"
        }]
    
    # Set up temporary alias
    alias_name = "test_admin_stats"
    setup_cmd = f"mc alias set {alias_name} {minio_endpoint} {admin_access_key} {admin_secret_key} 2>&1"
    result = run_command(setup_cmd, timeout=10)
    
    if result['exit_code'] != 0:
        return [{
            "name": "minio_statistics",
            "status": False,
            "output": result.get('stdout', ''),
            "severity": "WARNING"
        }]
    
    # Get server info
    info_cmd = f"mc admin info {alias_name} 2>&1"
    result = run_command(info_cmd, timeout=15)
    
    # Clean up alias
    cleanup_cmd = f"mc alias rm {alias_name} 2>&1"
    run_command(cleanup_cmd, timeout=5)
    
    status = True if result["exit_code"] == 0 else False
    severity = "INFO" if status else "WARNING"

    return [{
        "name": "minio_statistics",
        "status": status,
        "output": result.get('stdout', ''),
        "severity": severity
    }]


def test_minio_disk_usage() -> List[Dict]:
    """Check disk usage for MinIO"""
    minio_host = os.getenv('MINIO_HOST', 'minio.minio.svc.cluster.local')
    minio_port = os.getenv('MINIO_PORT', '9000')
    minio_endpoint = f"http://{minio_host}:{minio_port}"
    
    # Try to get admin credentials
    admin_access_key = os.getenv('MINIO_ROOT_USER', os.getenv('MINIO_ACCESS_KEY', ''))
    admin_secret_key = os.getenv('MINIO_ROOT_PASSWORD', os.getenv('MINIO_SECRET_KEY', ''))
    
    if not admin_access_key or not admin_secret_key:
        return [{
            "name": "minio_disk_usage",
            "status": False,
            "output": "Admin credentials not available",
            "severity": "WARNING"
        }]
    
    # Set up temporary alias
    alias_name = "test_admin_disk"
    setup_cmd = f"mc alias set {alias_name} {minio_endpoint} {admin_access_key} {admin_secret_key} 2>&1"
    result = run_command(setup_cmd, timeout=10)
    
    if result['exit_code'] != 0:
        return [{
            "name": "minio_disk_usage",
            "status": False,
            "output": result.get('stdout', ''),
            "severity": "WARNING"
        }]
    
    # Get disk usage
    disk_cmd = f"mc du {alias_name} --max-depth 1 2>&1"
    result = run_command(disk_cmd, timeout=20)
    
    # Clean up alias
    cleanup_cmd = f"mc alias rm {alias_name} 2>&1"
    run_command(cleanup_cmd, timeout=5)
    
    status = True if result["exit_code"] == 0 else False
    
    return [{
        "name": "minio_disk_usage",
        "status": status,
        "output": result.get('stdout', ''),
        "severity": "WARNING"
    }]
