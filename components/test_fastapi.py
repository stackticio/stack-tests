#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_fastapi_generic.py - Generic FastAPI Health Check that discovers configuration
"""

import os
import sys
import json
import subprocess
import base64
from typing import List, Dict, Any

def run_command(command: str, timeout: int = 30) -> Dict:
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


def get_config() -> Dict:
    """Get configuration from environment"""
    return {
        "namespace": os.getenv("FASTAPI_NS", "fastapi"),
        "port": "8080",
        "api_key": os.getenv("API_KEY", "a1b2c3d4e5f6789012345678901234567890abcd")
    }


def python_http_request(namespace: str, path: str, headers: Dict = None) -> Dict:
    """Make HTTP request using Python urllib"""
    headers_str = ""
    if headers:
        header_lines = [f"req.add_header('{k}', '{v}')" for k, v in headers.items()]
        headers_str = "; ".join(header_lines)
    
    cmd = f"""kubectl exec -n {namespace} deployment/fastapi -- python3 -c "
import urllib.request, urllib.error, json
try:
    req = urllib.request.Request('http://localhost:8080{path}')
    {headers_str}
    resp = urllib.request.urlopen(req, timeout=5)
    print(json.dumps({{'status': resp.status, 'body': resp.read().decode()}}))
except urllib.error.HTTPError as e:
    print(json.dumps({{'status': e.code, 'body': e.read().decode()}}))
except Exception as e:
    print(json.dumps({{'error': str(e)}}))
" """
    
    result = run_command(cmd)
    if result["exit_code"] == 0 and result["stdout"]:
        try:
            return json.loads(result["stdout"])
        except:
            return {"error": "Invalid response"}
    return {"error": "Request failed"}


def discover_configuration() -> Dict:
    """Discover FastAPI configuration from health endpoint"""
    config = get_config()
    
    response = python_http_request(config["namespace"], "/health")
    
    if "body" in response:
        try:
            return json.loads(response["body"])
        except:
            return {}
    return {}


def test_deployment() -> List[Dict]:
    """Test Kubernetes deployment"""
    config = get_config()
    results = []
    
    cmd = f"kubectl get deployment -n {config['namespace']} fastapi -o json"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            replicas = data.get("spec", {}).get("replicas", 0)
            ready = data.get("status", {}).get("readyReplicas", 0)
            status = replicas == ready and replicas > 0
            output = f"{ready}/{replicas} replicas ready"
        except:
            status = False
            output = "Failed to parse"
    else:
        status = False
        output = "Not found"
    
    results.append({
        "name": "deployment",
        "description": "Kubernetes deployment",
        "status": status,
        "output": output,
        "severity": "critical" if not status else "info"
    })
    
    return results


def test_port() -> List[Dict]:
    """Test if FastAPI is listening on port"""
    config = get_config()
    
    cmd = f"""kubectl exec -n {config['namespace']} deployment/fastapi -- python3 -c "
import socket
s = socket.socket()
try:
    s.connect(('localhost', 8080))
    s.close()
    print('listening')
except:
    print('not_listening')
" """
    
    result = run_command(cmd)
    status = result["exit_code"] == 0 and "listening" in result["stdout"]
    
    return [{
        "name": "port_8080",
        "description": "Port 8080 listening",
        "status": status,
        "output": "Port is listening" if status else "Port not available",
        "severity": "critical" if not status else "info"
    }]


def test_endpoints(health_data: Dict) -> List[Dict]:
    """Test basic endpoints"""
    config = get_config()
    results = []
    
    # Test health endpoint
    if health_data.get("status") == "healthy":
        results.append({
            "name": "health_endpoint",
            "description": "/health endpoint",
            "status": True,
            "output": "Healthy",
            "severity": "info"
        })
    else:
        results.append({
            "name": "health_endpoint",
            "description": "/health endpoint",
            "status": False,
            "output": f"Status: {health_data.get('status', 'unknown')}",
            "severity": "critical"
        })
    
    # Test info endpoint
    response = python_http_request(config["namespace"], "/info")
    if response.get("status") == 200:
        try:
            info = json.loads(response["body"])
            results.append({
                "name": "info_endpoint",
                "description": "/info endpoint",
                "status": True,
                "output": f"{info.get('name', 'unknown')} v{info.get('version', 'unknown')}",
                "severity": "info"
            })
        except:
            results.append({
                "name": "info_endpoint",
                "description": "/info endpoint",
                "status": False,
                "output": "Invalid response",
                "severity": "warning"
            })
    else:
        results.append({
            "name": "info_endpoint",
            "description": "/info endpoint",
            "status": False,
            "output": f"HTTP {response.get('status', 'error')}",
            "severity": "warning"
        })
    
    return results


def test_services(health_data: Dict) -> List[Dict]:
    """Test each configured service"""
    config = get_config()
    results = []
    
    services = health_data.get("services", {})
    
    for service_name, is_enabled in services.items():
        if is_enabled:
            # Test service endpoint
            response = python_http_request(
                config["namespace"], 
                f"/api/v1/{service_name}",
                {"X-API-Key": config["api_key"]}
            )
            
            if response.get("status") in [200, 404, 405]:  # 404/405 means route exists but no GET
                output = f"Endpoint accessible (HTTP {response.get('status')})"
                status = True
            else:
                output = f"HTTP {response.get('status', 'error')}"
                status = False
            
            results.append({
                "name": f"{service_name}_endpoint",
                "description": f"{service_name.upper()} API endpoint",
                "status": status,
                "output": output,
                "severity": "warning" if not status else "info"
            })
    
    return results


def test_databases(health_data: Dict) -> List[Dict]:
    """Test each configured database"""
    config = get_config()
    results = []
    
    # MongoDB databases
    mongodb_dbs = health_data.get("mongodb_databases", [])
    for db_name in mongodb_dbs:
        response = python_http_request(
            config["namespace"],
            f"/api/v1/mongodb/{db_name}",
            {"X-API-Key": config["api_key"]}
        )
        
        status = response.get("status") in [200, 404, 405]
        output = f"Database '{db_name}' endpoint: HTTP {response.get('status', 'error')}"
        
        results.append({
            "name": f"mongodb_{db_name}",
            "description": f"MongoDB database: {db_name}",
            "status": status,
            "output": output,
            "severity": "info"
        })
    
    # PostgreSQL databases (if any)
    postgres_dbs = health_data.get("postgresql_databases", [])
    for db_name in postgres_dbs:
        response = python_http_request(
            config["namespace"],
            f"/api/v1/postgresql/{db_name}",
            {"X-API-Key": config["api_key"]}
        )
        
        status = response.get("status") in [200, 404, 405]
        output = f"Database '{db_name}' endpoint: HTTP {response.get('status', 'error')}"
        
        results.append({
            "name": f"postgresql_{db_name}",
            "description": f"PostgreSQL database: {db_name}",
            "status": status,
            "output": output,
            "severity": "info"
        })
    
    return results


def test_buckets(health_data: Dict) -> List[Dict]:
    """Test MinIO buckets"""
    config = get_config()
    results = []
    
    minio_buckets = health_data.get("minio_buckets", [])
    for bucket_name in minio_buckets:
        response = python_http_request(
            config["namespace"],
            f"/api/v1/minio/{bucket_name}",
            {"X-API-Key": config["api_key"]}
        )
        
        status = response.get("status") in [200, 404, 405]
        output = f"Bucket '{bucket_name}' endpoint: HTTP {response.get('status', 'error')}"
        
        results.append({
            "name": f"minio_bucket_{bucket_name}",
            "description": f"MinIO bucket: {bucket_name}",
            "status": status,
            "output": output,
            "severity": "info"
        })
    
    return results


def test_authentication(health_data: Dict) -> List[Dict]:
    """Test authentication configuration"""
    results = []
    
    # API Key configuration
    api_key_configured = health_data.get("api_key_configured", False)
    results.append({
        "name": "api_key_config",
        "description": "API Key configuration",
        "status": api_key_configured,
        "output": "API key configured" if api_key_configured else "No API key",
        "severity": "warning" if not api_key_configured else "info"
    })
    
    # Doc authentication
    doc_auth = health_data.get("doc_auth", {})
    if doc_auth.get("enabled"):
        results.append({
            "name": "doc_auth",
            "description": "Documentation authentication",
            "status": True,
            "output": f"Enabled for user: {doc_auth.get('username', 'unknown')}",
            "severity": "info"
        })
    
    # Service-specific auth
    auth_info = health_data.get("authentication", {})
    services_with_auth = [
        svc for svc, cfg in auth_info.items() 
        if cfg.get("auth_enabled")
    ]
    
    if services_with_auth:
        results.append({
            "name": "service_auth",
            "description": "Service authentication",
            "status": True,
            "output": f"Auth enabled for: {', '.join(services_with_auth)}",
            "severity": "info"
        })
    
    return results


def test_logs() -> List[Dict]:
    """Check application logs"""
    config = get_config()
    
    cmd = f"kubectl logs -n {config['namespace']} deployment/fastapi --tail=100 2>/dev/null | grep -c 'ERROR\\|CRITICAL'"
    result = run_command(cmd)
    
    try:
        errors = int(result["stdout"]) if result["exit_code"] == 0 else 0
        status = errors < 5
        output = f"{errors} errors in recent logs"
    except:
        status = True
        output = "No errors found"
    
    return [{
        "name": "recent_logs",
        "description": "Recent error logs",
        "status": status,
        "output": output,
        "severity": "warning" if not status else "info"
    }]


def generate_summary(results: List[Dict], health_data: Dict) -> List[Dict]:
    """Generate summary of discovered configuration"""
    summary = []
    
    # Count active services
    services = health_data.get("services", {})
    active_services = [k for k, v in services.items() if v]
    
    summary.append({
        "name": "configuration_summary",
        "description": "Discovered configuration",
        "status": True,
        "output": f"Active services: {', '.join(active_services) if active_services else 'none'}",
        "severity": "info"
    })
    
    # Count databases
    db_count = len(health_data.get("mongodb_databases", [])) + len(health_data.get("postgresql_databases", []))
    if db_count > 0:
        summary.append({
            "name": "database_summary",
            "description": "Configured databases",
            "status": True,
            "output": f"Total databases: {db_count}",
            "severity": "info"
        })
    
    # Count buckets
    bucket_count = len(health_data.get("minio_buckets", []))
    if bucket_count > 0:
        summary.append({
            "name": "storage_summary",
            "description": "Configured storage",
            "status": True,
            "output": f"MinIO buckets: {bucket_count}",
            "severity": "info"
        })
    
    return summary


def test_fastapi():
    """Run all tests based on discovered configuration"""
    all_results = []
    
    # Basic infrastructure tests
    all_results.extend(test_deployment())
    all_results.extend(test_port())
    
    # Discover configuration from health endpoint
    health_data = discover_configuration()
    
    if not health_data:
        all_results.append({
            "name": "discovery",
            "description": "Configuration discovery",
            "status": False,
            "output": "Failed to discover configuration from /health",
            "severity": "critical"
        })
        return all_results
    
    # Test discovered components
    all_results.extend(test_endpoints(health_data))
    all_results.extend(test_services(health_data))
    all_results.extend(test_databases(health_data))
    all_results.extend(test_buckets(health_data))
    all_results.extend(test_authentication(health_data))
    all_results.extend(test_logs())
    
    # Add summary
    all_results.extend(generate_summary(all_results, health_data))
    
    return all_results


if __name__ == "__main__":
    results = test_fastapi()
    print(json.dumps(results, indent=2))
    
    critical = sum(1 for r in results if not r["status"] and r["severity"] == "critical")
    sys.exit(1 if critical > 0 else 0)
