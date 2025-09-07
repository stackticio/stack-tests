#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_fastapi_dynamic.py - Dynamic FastAPI tester that discovers and tests all routes
Handles authentication requirements automatically
"""

import os
import sys
import json
import subprocess
import base64
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

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
        "port": os.getenv("FASTAPI_PORT", "8080"),
        "api_key": os.getenv("API_KEY", "a1b2c3d4e5f6789012345678901234567890abcd"),
        "basic_auth": {
            "username": os.getenv("DOC_USERNAME", "admin"),
            "password": os.getenv("DOC_PASSWORD", "Default_Pass1!")
        }
    }


def python_http_request(namespace: str, path: str, method: str = "GET", 
                        headers: Dict = None, data: str = None, 
                        basic_auth: Tuple[str, str] = None) -> Dict:
    """Make HTTP request using Python urllib with authentication support"""
    
    # Build headers
    headers_lines = []
    if headers:
        for k, v in headers.items():
            headers_lines.append(f"req.add_header('{k}', '{v}')")
    
    # Add basic auth if provided
    auth_lines = []
    if basic_auth:
        auth_lines.append(f"import base64")
        auth_lines.append(f"credentials = base64.b64encode('{basic_auth[0]}:{basic_auth[1]}'.encode()).decode()")
        auth_lines.append(f"req.add_header('Authorization', f'Basic {{credentials}}')")
    
    # Prepare data
    data_setup = "data = None"
    if data:
        data_setup = f"data = {repr(data)}.encode('utf-8')"
    
    # Combine all setup lines
    setup_lines = auth_lines + headers_lines
    setup_str = "\n    ".join(setup_lines) if setup_lines else "pass"
    
    cmd = f"""kubectl exec -n {namespace} deployment/fastapi -- python3 -c "
import urllib.request, urllib.error, json
try:
    req = urllib.request.Request('http://localhost:8080{path}', method='{method}')
    {setup_str}
    {data_setup}
    resp = urllib.request.urlopen(req, data=data, timeout=10)
    body = resp.read().decode()
    print(json.dumps({{'status': resp.status, 'body': body}}))
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(json.dumps({{'status': e.code, 'body': body}}))
except Exception as e:
    print(json.dumps({{'error': str(e)}}))
" """
    
    result = run_command(cmd, timeout=15)
    if result["exit_code"] == 0 and result["stdout"]:
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"error": f"Invalid JSON: {result['stdout'][:200]}"}
    return {"error": f"Command failed: {result.get('stderr', 'Unknown')}"}


def discover_health_config() -> Dict:
    """Get health endpoint data for configuration discovery"""
    config = get_config()
    
    # Health endpoint usually doesn't require auth
    response = python_http_request(config["namespace"], "/health")
    
    if response.get("status") == 200 and "body" in response:
        try:
            return json.loads(response["body"])
        except:
            pass
    return {}


def discover_openapi_schema() -> Dict:
    """Discover all routes from OpenAPI schema with auth fallback"""
    config = get_config()
    
    # Try different auth methods
    auth_attempts = [
        ("No auth", {}, None),
        ("API Key", {"X-API-Key": config["api_key"]}, None),
        ("Basic Auth", {}, (config["basic_auth"]["username"], config["basic_auth"]["password"])),
        ("Both", {"X-API-Key": config["api_key"]}, (config["basic_auth"]["username"], config["basic_auth"]["password"]))
    ]
    
    for auth_name, headers, basic_auth in auth_attempts:
        response = python_http_request(
            config["namespace"], 
            "/openapi.json",
            headers=headers,
            basic_auth=basic_auth
        )
        
        if response.get("status") == 200 and "body" in response:
            try:
                schema = json.loads(response["body"])
                print(f"  ✓ OpenAPI retrieved using: {auth_name}")
                return schema
            except:
                pass
    
    print("  ✗ Could not retrieve OpenAPI schema")
    return {}


def analyze_routes(openapi_schema: Dict) -> Dict[str, List[Dict]]:
    """Analyze OpenAPI schema to categorize routes"""
    routes = defaultdict(list)
    
    paths = openapi_schema.get("paths", {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                route_info = {
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "tags": details.get("tags", []),
                    "requires_auth": False,
                    "auth_type": None,
                    "requires_body": False,
                    "path_params": [],
                    "query_params": []
                }
                
                # Check for authentication requirements
                security = details.get("security", [])
                parameters = details.get("parameters", [])
                
                # Check security definitions
                if security:
                    route_info["requires_auth"] = True
                    if any("apiKey" in s for s in security):
                        route_info["auth_type"] = "api_key"
                    elif any("basic" in str(s).lower() for s in security):
                        route_info["auth_type"] = "basic"
                
                # Check parameters for auth headers
                for param in parameters:
                    param_name = param.get("name", "").lower()
                    if param.get("in") == "header":
                        if "api" in param_name or "key" in param_name:
                            route_info["requires_auth"] = True
                            route_info["auth_type"] = "api_key"
                    elif param.get("in") == "path":
                        route_info["path_params"].append(param.get("name"))
                    elif param.get("in") == "query":
                        route_info["query_params"].append(param.get("name"))
                
                # Check for request body
                if "requestBody" in details:
                    route_info["requires_body"] = True
                
                # Categorize by service
                if "/api/v1/" in path:
                    service = path.split("/api/v1/")[1].split("/")[0]
                    routes[service].append(route_info)
                else:
                    routes["core"].append(route_info)
    
    return dict(routes)


def test_route(route: Dict, config: Dict, health_data: Dict) -> Dict:
    """Test a single route intelligently based on its characteristics"""
    path = route["path"]
    method = route["method"]
    
    # Determine authentication needs
    headers = {}
    basic_auth = None
    
    # Check if this service requires auth based on health data
    service_name = None
    if "/api/v1/" in path:
        service_name = path.split("/api/v1/")[1].split("/")[0]
    
    # Apply authentication if needed
    if route["requires_auth"] or service_name:
        # Check health data for service auth requirements
        auth_config = health_data.get("authentication", {}).get(service_name, {})
        if auth_config.get("auth_enabled") or route["requires_auth"]:
            # Always include API key for authenticated endpoints
            headers["X-API-Key"] = config["api_key"]
            
            # Add basic auth if it's a docs endpoint
            if "/docs" in path or "/redoc" in path:
                basic_auth = (config["basic_auth"]["username"], config["basic_auth"]["password"])
    
    # Handle path parameters
    test_path = path
    for param in route["path_params"]:
        # Use reasonable test values
        if "id" in param.lower():
            test_value = "test-id-123"
        elif "name" in param.lower():
            test_value = "test-name"
        elif "bucket" in param.lower():
            test_value = "bucket"  # Use actual bucket name from health
        elif "database" in param.lower() or "db" in param.lower():
            test_value = "mongo1"  # Use actual db name from health
        else:
            test_value = "test-value"
        
        test_path = test_path.replace(f"{{{param}}}", test_value)
    
    # Handle query parameters for GET requests
    if route["query_params"] and method == "GET":
        query_params = []
        for param in route["query_params"][:2]:  # Limit to 2 params for testing
            if "limit" in param.lower():
                query_params.append(f"{param}=10")
            elif "skip" in param.lower() or "offset" in param.lower():
                query_params.append(f"{param}=0")
            else:
                query_params.append(f"{param}=test")
        if query_params:
            test_path += "?" + "&".join(query_params)
    
    # Prepare test data for POST/PUT/PATCH
    test_data = None
    if route["requires_body"] and method in ["POST", "PUT", "PATCH"]:
        # Service-specific test data
        if "user" in path.lower():
            test_data = json.dumps({
                "username": "testuser",
                "email": "test@example.com",
                "password": "TestPass123!"
            })
        elif "upload" in path.lower():
            test_data = json.dumps({"filename": "test.txt", "content": "test content"})
        else:
            test_data = json.dumps({"test": "data", "id": "test-123", "name": "test"})
        headers["Content-Type"] = "application/json"
    
    # Make the request
    response = python_http_request(
        config["namespace"],
        test_path,
        method,
        headers,
        test_data,
        basic_auth
    )
    
    # Analyze response
    status_code = response.get("status", 0)
    error_msg = response.get("error", "")
    
    # Interpret results
    if status_code in [200, 201, 204]:
        result = "success"
        severity = "info"
        output = f"✓ Endpoint working (HTTP {status_code})"
    elif status_code == 400:
        result = "partial"
        severity = "warning"
        output = f"⚠ Bad request - needs valid data (HTTP 400)"
    elif status_code == 401:
        result = "auth_failed"
        severity = "critical"
        output = f"✗ Authentication failed (HTTP 401)"
    elif status_code == 403:
        result = "forbidden"
        severity = "warning"
        output = f"⚠ Forbidden - check permissions (HTTP 403)"
    elif status_code == 404:
        if any(p in path for p in ["{", "}"]):  # Has path parameters
            result = "partial"
            severity = "warning"
            output = f"⚠ Resource not found - needs valid ID (HTTP 404)"
        else:
            result = "failed"
            severity = "critical"
            output = f"✗ Endpoint not found (HTTP 404)"
    elif status_code == 405:
        result = "partial"
        severity = "info"
        output = f"⚠ Method not allowed - endpoint exists (HTTP 405)"
    elif status_code == 422:
        result = "partial"
        severity = "warning"
        output = f"⚠ Validation error - needs correct data (HTTP 422)"
    elif status_code >= 500:
        result = "error"
        severity = "critical"
        output = f"✗ Server error (HTTP {status_code})"
    elif error_msg:
        result = "error"
        severity = "critical"
        output = f"✗ Connection error: {error_msg[:50]}"
    else:
        result = "unknown"
        severity = "warning"
        output = f"? Unexpected status: {status_code}"
    
    return {
        "name": f"{method}_{path.replace('/', '_')}",
        "description": f"{method} {path}",
        "path": path,
        "method": method,
        "status_code": status_code,
        "result": result,
        "status": result in ["success", "partial"],
        "output": output,
        "severity": severity,
        "tags": route.get("tags", [])
    }


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
            output = "Failed to parse deployment"
    else:
        status = False
        output = "Deployment not found"
    
    results.append({
        "name": "deployment",
        "description": "Kubernetes deployment",
        "status": status,
        "output": f"{'✓' if status else '✗'} {output}",
        "severity": "critical" if not status else "info"
    })
    
    return results


def test_core_endpoints(health_data: Dict) -> List[Dict]:
    """Test core endpoints with appropriate authentication"""
    config = get_config()
    results = []
    
    # Determine if doc auth is enabled
    doc_auth_enabled = health_data.get("doc_auth", {}).get("enabled", False)
    
    core_endpoints = [
        ("/health", "Health check", False, False),
        ("/info", "Application info", False, False),
        ("/", "Root endpoint", True, False),
        ("/docs", "API documentation", True, doc_auth_enabled),
        ("/openapi.json", "OpenAPI schema", True, doc_auth_enabled)
    ]
    
    for path, description, needs_api_key, needs_basic_auth in core_endpoints:
        headers = {}
        basic_auth = None
        
        if needs_api_key:
            headers["X-API-Key"] = config["api_key"]
        
        if needs_basic_auth:
            basic_auth = (config["basic_auth"]["username"], config["basic_auth"]["password"])
        
        response = python_http_request(
            config["namespace"], 
            path,
            headers=headers,
            basic_auth=basic_auth
        )
        
        status_code = response.get("status", 0)
        is_success = status_code == 200
        
        # Adjust severity based on endpoint importance
        if path == "/health" and not is_success:
            severity = "critical"
        elif path in ["/", "/docs"] and status_code == 401:
            severity = "info"  # Auth required is ok
        else:
            severity = "warning" if not is_success else "info"
        
        results.append({
            "name": f"core_{path.replace('/', '_') or 'root'}",
            "description": description,
            "status": is_success,
            "output": f"{'✓' if is_success else '✗'} HTTP {status_code}",
            "severity": severity
        })
    
    return results


def test_configured_services(health_data: Dict) -> List[Dict]:
    """Test services that are configured according to health endpoint"""
    config = get_config()
    results = []
    
    services = health_data.get("services", {})
    
    for service_name, is_enabled in services.items():
        if is_enabled:
            # Test main service endpoint
            headers = {"X-API-Key": config["api_key"]}
            response = python_http_request(
                config["namespace"],
                f"/api/v1/{service_name}",
                headers=headers
            )
            
            status_code = response.get("status", 0)
            is_success = status_code in [200, 405]  # 405 means endpoint exists
            
            results.append({
                "name": f"service_{service_name}",
                "description": f"{service_name.upper()} service endpoint",
                "status": is_success,
                "output": f"{'✓' if is_success else '✗'} HTTP {status_code}",
                "severity": "critical" if not is_success else "info"
            })
    
    return results


def generate_service_summary(routes_by_service: Dict, test_results: List[Dict]) -> List[Dict]:
    """Generate summary by service"""
    summary = []
    
    for service, routes in routes_by_service.items():
        if service == "core":
            continue
            
        service_results = [
            r for r in test_results 
            if any(route["path"] in r.get("path", "") for route in routes)
        ]
        
        if service_results:
            total = len(service_results)
            successful = sum(1 for r in service_results if r.get("result") == "success")
            partial = sum(1 for r in service_results if r.get("result") == "partial")
            failed = sum(1 for r in service_results if r.get("result") in ["failed", "error", "auth_failed"])
            
            status = failed == 0
            severity = "critical" if failed > 0 else "warning" if partial > 0 else "info"
            
            summary.append({
                "name": f"summary_{service}",
                "description": f"{service.upper()} service test summary",
                "status": status,
                "output": f"✓ {successful}/{total} | ⚠ {partial}/{total} | ✗ {failed}/{total}",
                "severity": severity,
                "endpoints_tested": total
            })
    
    return summary


def print_results(results: List[Dict]):
    """Pretty print test results"""
    print("\n" + "="*70)
    print(" "*25 + "TEST RESULTS")
    print("="*70)
    
    # Group by severity
    by_severity = defaultdict(list)
    for r in results:
        by_severity[r.get("severity", "info")].append(r)
    
    # Print critical issues
    if by_severity["critical"]:
        print("\n❌ CRITICAL ISSUES:")
        for r in by_severity["critical"]:
            if not r.get("status"):
                print(f"  • {r['description']}: {r['output']}")
    
    # Print warnings
    if by_severity["warning"]:
        print("\n⚠️  WARNINGS:")
        for r in by_severity["warning"]:
            if not r.get("status"):
                print(f"  • {r['description']}: {r['output']}")
    
    # Print successes
    success_count = sum(1 for r in results if r.get("status"))
    total_count = len([r for r in results if "status" in r])
    
    print(f"\n✅ SUCCESSES: {success_count}/{total_count}")
    
    # Print summary
    summary = next((r for r in results if r["name"] == "overall_summary"), None)
    if summary:
        print(f"\n📊 OVERALL: {summary['output']}")
    
    print("="*70 + "\n")


def test_fastapi_dynamic():
    """Dynamically discover and test all FastAPI endpoints"""
    all_results = []
    config = get_config()
    
    print("\n🔍 Starting FastAPI Dynamic Testing...")
    print(f"  Namespace: {config['namespace']}")
    print(f"  API Key: {config['api_key'][:10]}...")
    
    # Test deployment
    print("\n📦 Testing deployment...")
    all_results.extend(test_deployment())
    
    # Discover configuration from health
    print("🔧 Discovering configuration...")
    health_data = discover_health_config()
    
    if health_data:
        print(f"  ✓ Health endpoint responsive")
        print(f"  ✓ Services found: {', '.join([k for k,v in health_data.get('services', {}).items() if v])}")
    else:
        print("  ✗ Could not retrieve health data")
    
    # Test core endpoints with auth
    print("🌐 Testing core endpoints...")
    all_results.extend(test_core_endpoints(health_data))
    
    # Test configured services
    print("🔌 Testing configured services...")
    all_results.extend(test_configured_services(health_data))
    
    # Discover all routes from OpenAPI
    print("📖 Discovering API routes...")
    openapi_schema = discover_openapi_schema()
    
    if not openapi_schema or not openapi_schema.get("paths"):
        all_results.append({
            "name": "route_discovery",
            "description": "API route discovery",
            "status": False,
            "output": "✗ Failed to discover routes from OpenAPI",
            "severity": "warning"
        })
    else:
        # Analyze and categorize routes
        routes_by_service = analyze_routes(openapi_schema)
        total_routes = sum(len(routes) for routes in routes_by_service.values())
        
        all_results.append({
            "name": "route_discovery",
            "description": "API route discovery",
            "status": True,
            "output": f"✓ Discovered {total_routes} routes in {len(routes_by_service)} services",
            "severity": "info"
        })
        
        # Test each discovered route
        print(f"🧪 Testing {total_routes} discovered routes...")
        route_results = []
        
        for service, routes in routes_by_service.items():
            if service != "core":  # Skip core endpoints (already tested)
                print(f"  Testing {service} service ({len(routes)} routes)...")
                for route in routes[:10]:  # Limit to 10 routes per service for speed
                    # Skip docs endpoints
                    if any(skip in route["path"] for skip in ["/docs", "/redoc", "/openapi.json"]):
                        continue
                    
                    result = test_route(route, config, health_data)
                    result["service"] = service
                    route_results.append(result)
        
        all_results.extend(route_results)
        
        # Generate service summaries
        print("📊 Generating summaries...")
        all_results.extend(generate_service_summary(routes_by_service, route_results))
    
    # Overall summary
    total_tests = len([r for r in all_results if "status" in r])
    passed_tests = len([r for r in all_results if r.get("status") == True])
    critical_issues = len([r for r in all_results if r.get("severity") == "critical" and not r.get("status")])
    
    all_results.append({
        "name": "overall_summary",
        "description": "Overall test summary",
        "status": critical_issues == 0,
        "output": f"Passed: {passed_tests}/{total_tests} | Critical issues: {critical_issues}",
        "severity": "critical" if critical_issues > 0 else "info"
    })
    
    return all_results


if __name__ == "__main__":
    try:
        results = test_fastapi_dynamic()
        
        # Pretty print for humans
        print_results(results)
        
        # Output JSON for automation (optional)
        if "--json" in sys.argv:
            print(json.dumps(results, indent=2))
        
        # Exit with error if critical issues
        critical = sum(1 for r in results if not r.get("status") and r.get("severity") == "critical")
        sys.exit(1 if critical > 0 else 0)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        sys.exit(1)
