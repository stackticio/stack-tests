#!/usr/bin/env python3
"""
FastAPI Generic Service Test Script
- Discovers available services dynamically from health endpoint
- Tests whatever is actually deployed
- No assumptions about service types

ENV VARS:
  FASTAPI_HOST (default: fastapi.fastapi.svc.cluster.local)
  FASTAPI_PORT (default: 8080)
  FASTAPI_API_KEY (optional)

Output: JSON array of test results to stdout
"""

import os
import json
import time
import sys
import requests
from typing import Dict, List, Any, Optional

# Configuration
FASTAPI_HOST = os.getenv('FASTAPI_HOST', 'fastapi.fastapi.svc.cluster.local')
FASTAPI_PORT = os.getenv('FASTAPI_PORT', '8080')
FASTAPI_API_KEY = os.getenv('FASTAPI_API_KEY', '')
BASE_URL = f"http://{FASTAPI_HOST}:{FASTAPI_PORT}"

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }

def make_request(method: str, endpoint: str, headers: Optional[Dict] = None, timeout: int = 10) -> Dict[str, Any]:
    """Make HTTP request"""
    url = f"{BASE_URL}{endpoint}"
    headers = headers or {}
    
    try:
        response = requests.request(method, url, headers=headers, timeout=timeout)
        result = {
            "status_code": response.status_code,
            "success": 200 <= response.status_code < 300
        }
        try:
            result["json"] = response.json()
        except:
            result["text"] = response.text
        return result
    except Exception as e:
        return {"status_code": -1, "error": str(e)}

def test_fastapi() -> List[Dict[str, Any]]:
    """Run all tests"""
    results = []
    
    # 1. Test connectivity
    response = make_request('GET', '/')
    if response['status_code'] in [200, 307, 308]:
        results.append(create_test_result(
            "connectivity",
            "Check FastAPI connectivity",
            True,
            f"Connected to {BASE_URL}",
            "INFO"
        ))
    else:
        results.append(create_test_result(
            "connectivity",
            "Check FastAPI connectivity",
            False,
            f"Connection failed: {response.get('error', 'Unknown error')}",
            "CRITICAL"
        ))
        return results
    
    # 2. Get health and discover what's available
    response = make_request('GET', '/health')
    if response['status_code'] == 200 and 'json' in response:
        health = response['json']
        
        results.append(create_test_result(
            "health",
            "Health endpoint",
            health.get('status') == 'healthy',
            f"Status: {health.get('status', 'unknown')}",
            "INFO"
        ))
        
        # Discover services
        services = health.get('services', {})
        active = [k for k, v in services.items() if v]
        
        if active:
            results.append(create_test_result(
                "services_discovered",
                "Discovered services",
                True,
                f"Found: {', '.join(active)}",
                "INFO"
            ))
            
            # Test each discovered service endpoint
            headers = {'X-API-Key': FASTAPI_API_KEY} if FASTAPI_API_KEY else {}
            
            for service in active:
                # Try common API patterns
                endpoints = [
                    f"/api/v1/{service}",
                    f"/api/v1/{service}/",
                    f"/api/{service}",
                    f"/{service}"
                ]
                
                for endpoint in endpoints:
                    r = make_request('GET', endpoint, headers)
                    if r['status_code'] in [200, 201]:
                        results.append(create_test_result(
                            f"service_{service}",
                            f"Test {service} service",
                            True,
                            f"Service accessible at {endpoint}",
                            "INFO"
                        ))
                        break
                else:
                    results.append(create_test_result(
                        f"service_{service}",
                        f"Test {service} service",
                        False,
                        f"Service not accessible at common endpoints",
                        "WARNING"
                    ))
        
        # Check for any lists in health data
        for key, value in health.items():
            if isinstance(value, list) and value:
                results.append(create_test_result(
                    f"discovered_{key}",
                    f"Discovered {key}",
                    True,
                    f"{key}: {', '.join(value[:5])}{'...' if len(value) > 5 else ''}",
                    "INFO"
                ))
                
                # Test first item from each list
                if any(x in key.lower() for x in ['database', 'bucket', 'queue', 'topic', 'exchange']):
                    item = value[0]
                    service_type = key.split('_')[0] if '_' in key else key
                    
                    # Try to access it
                    test_endpoints = [
                        f"/api/v1/{service_type}/{item}",
                        f"/api/v1/{service_type}/{item}/info",
                        f"/api/v1/{service_type}/{item}/health"
                    ]
                    
                    headers = {'X-API-Key': FASTAPI_API_KEY} if FASTAPI_API_KEY else {}
                    for endpoint in test_endpoints:
                        r = make_request('GET', endpoint, headers)
                        if r['status_code'] == 200:
                            results.append(create_test_result(
                                f"item_{item}",
                                f"Test {service_type} item '{item}'",
                                True,
                                f"Accessible at {endpoint}",
                                "INFO"
                            ))
                            break
    
    # 3. Test info endpoint
    response = make_request('GET', '/info')
    if response['status_code'] == 200 and 'json' in response:
        info = response['json']
        results.append(create_test_result(
            "info",
            "Info endpoint",
            True,
            f"{info.get('name', 'unknown')} v{info.get('version', '?')}",
            "INFO"
        ))
    
    # 4. Test docs
    response = make_request('GET', '/docs')
    if response['status_code'] in [200, 307, 308]:
        results.append(create_test_result(
            "docs",
            "Documentation endpoint",
            True,
            "Swagger UI accessible",
            "INFO"
        ))
    elif response['status_code'] == 401:
        results.append(create_test_result(
            "docs",
            "Documentation endpoint",
            True,
            "Swagger UI requires authentication",
            "INFO"
        ))
    
    # 5. Test OpenAPI
    response = make_request('GET', '/openapi.json')
    if response['status_code'] == 200:
        results.append(create_test_result(
            "openapi",
            "OpenAPI schema",
            True,
            "OpenAPI schema accessible",
            "INFO"
        ))
    
    return results

def main():
    """Main entry point"""
    try:
        results = test_fastapi()
        print(json.dumps(results, indent=2))
        
        critical = [r for r in results if r['severity'] == 'critical' and not r['status']]
        sys.exit(1 if critical else 0)
        
    except Exception as e:
        error_result = [create_test_result(
            "test_execution",
            "Test script execution",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()
