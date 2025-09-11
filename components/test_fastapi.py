> #!/usr/bin/env python3
> """
> FastAPI Service Test Script
> - Tests health and service endpoints with proper authentication
> - Tests actual deployed endpoints
> 
> ENV VARS
>   FASTAPI_NS (default: fastapi)
>   FASTAPI_PORT (default: 8080)
>   FASTAPI_API_KEY
>   FASTAPI_LOGIN
> 
> Output: JSON array of test results to stdout
> Each result: {
>   name, description, status (bool), severity (info|warning|critical), output
> }
> """
> 
> import os
> import json
> import subprocess
> import sys
> from typing import Dict, List, Any, Optional, Tuple
> from collections import defaultdict
> 
> # ------------------------------------------------------------
> # Utilities & configuration
> # ------------------------------------------------------------
> 
> def get_config() -> Dict[str, str]:
>     """Get configuration from environment"""
>     return {
>         "namespace": os.getenv("FASTAPI_NS", "fastapi"),
>         "port": os.getenv("FASTAPI_PORT", "8080"),
>         "api_key": os.getenv("FASTAPI_API_KEY", ""),
>         "doc_password": os.getenv("FASTAPI_LOGIN", "")
>     }
> 
> CONFIG = get_config()
> NAMESPACE = CONFIG["namespace"]
> PORT = CONFIG["port"]
> API_KEY = CONFIG["api_key"]
> 
> # ------------------------------------------------------------
> # Shell helper
> # ------------------------------------------------------------
> 
> def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
>     """Run shell command and return results"""
>     try:
>         completed = subprocess.run(
>             command,
>             shell=True,
>             capture_output=True,
>             text=True,
>             timeout=timeout
>         )
>         return {
>             "exit_code": completed.returncode,
>             "stdout": completed.stdout.strip(),
>             "stderr": completed.stderr.strip()
>         }
>     except subprocess.TimeoutExpired:
>         return {"exit_code": 124, "stdout": "", "stderr": "Timeout"}
>     except Exception as e:
>         return {"exit_code": 1, "stdout": "", "stderr": str(e)}
> 
> def ok(proc: Dict[str, Any]) -> bool:
>     """Check if command executed successfully"""
>     return proc.get("exit_code", 1) == 0
> 
> # ------------------------------------------------------------
> # Result helper
> # ------------------------------------------------------------
> 
> def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
>     """Create standardized test result"""
>     return {
>         "name": name,
>         "description": description,
>         "status": bool(passed),
>         "output": output,
>         "severity": severity.lower(),
>     }
> 
> # ------------------------------------------------------------
> # HTTP Request Helper
> # ------------------------------------------------------------
> 
> def python_http_request(namespace: str, path: str, method: str = "GET", 
>                         headers: Dict = None, data: str = None) -> Dict:
>     """Make HTTP request using Python urllib with authentication support"""
>     
>     # Build headers
>     headers_lines = []
>     if headers:
>         for k, v in headers.items():
>             headers_lines.append(f"req.add_header('{k}', '{v}')")
>     
>     # Prepare data
>     data_setup = "data = None"
>     if data:
>         data_setup = f"data = {repr(data)}.encode('utf-8')"
>     
>     setup_str = "\n    ".join(headers_lines) if headers_lines else "pass"
>     
>     cmd = f"""kubectl exec -n {namespace} deployment/fastapi -- python3 -c "
> import urllib.request, urllib.error, json
> try:
>     req = urllib.request.Request('http://localhost:8080{path}', method='{method}')
>     {setup_str}
>     {data_setup}
>     resp = urllib.request.urlopen(req, data=data, timeout=10)
>     body = resp.read().decode()
>     print(json.dumps({{'status': resp.status, 'body': body}}))
> except urllib.error.HTTPError as e:
>     body = e.read().decode()
>     print(json.dumps({{'status': e.code, 'body': body}}))
> except Exception as e:
>     print(json.dumps({{'error': str(e)}}))
> " """
>     
>     result = run_command(cmd, timeout=15)
>     if result["exit_code"] == 0 and result["stdout"]:
>         try:
>             return json.loads(result["stdout"])
>         except json.JSONDecodeError:
>             return {"error": f"Invalid JSON: {result['stdout'][:200]}"}
>     return {"error": f"Command failed: {result.get('stderr', 'Unknown')}"}
> 
> # ------------------------------------------------------------
> # Tests
> # ------------------------------------------------------------
> 
> def test_deployment() -> List[Dict[str, Any]]:
>     """Test Kubernetes deployment"""
>     results = []
>     
>     cmd = f"kubectl get deployment -n {NAMESPACE} fastapi -o json"
>     result = run_command(cmd)
>     
>     if ok(result):
>         try:
>             data = json.loads(result["stdout"])
>             replicas = data.get("spec", {}).get("replicas", 0)
>             ready = data.get("status", {}).get("readyReplicas", 0)
>             status = replicas == ready and replicas > 0
>             output = f"{ready}/{replicas} replicas ready"
>         except:
>             status = False
>             output = "Failed to parse deployment"
>     else:
>         status = False
>         output = "Deployment not found"
>     
>     results.append(create_test_result(
>         "deployment",
>         "Kubernetes deployment",
>         status,
>         f"{'✓' if status else '✗'} {output}",
>         "critical" if not status else "info"
>     ))
>     
>     return results
> 
> def test_health_endpoint() -> Tuple[List[Dict[str, Any]], Dict]:
>     """Test health endpoint and return results + health data"""
>     response = python_http_request(NAMESPACE, "/health")
>     
>     status_code = response.get("status", 0)
>     is_success = status_code == 200
>     
>     result = create_test_result(
>         "health_endpoint",
>         "Health check endpoint",
>         is_success,
>         f"{'✓' if is_success else '✗'} /health → HTTP {status_code}",
>         "critical" if not is_success else "info"
>     )
>     
>     health_data = {}
>     if is_success and "body" in response:
>         try:
>             health_data = json.loads(response["body"])
>         except:
>             pass
>     
>     return [result], health_data
> 
> def test_core_endpoints() -> List[Dict[str, Any]]:
>     """Test core endpoints"""
>     results = []
>     
>     endpoints = [
>         ("/health", "Health endpoint", True),  # We already tested but include for completeness
>         ("/openapi.json", "OpenAPI schema", False)
>     ]
>     
>     for path, description, required in endpoints:
>         # Skip health since we already tested it
>         if path == "/health":
>             continue
>             
>         # Try without auth first
>         response = python_http_request(NAMESPACE, path)
>         status_code = response.get("status", 0)
>         
>         # If 401, try with API key
>         if status_code == 401 and API_KEY:
>             response = python_http_request(
>                 NAMESPACE, 
>                 path,
>                 headers={"X-API-Key": API_KEY}
>             )
>             status_code = response.get("status", 0)
>             auth_used = " (with API key)"
>         else:
>             auth_used = ""
>         
>         is_success = status_code in [200, 201]
>         severity = "critical" if required and not is_success else "info"
>         
>         results.append(create_test_result(
>             f"core_{path.replace('/', '_').strip('_')}",
>             description,
>             is_success,
>             f"{'✓' if is_success else '✗'} {path} → HTTP {status_code}{auth_used}",
>             severity
>         ))
>     
>     return results
> 
> def test_service_endpoints(health_data: Dict) -> List[Dict[str, Any]]:
>     """Test service endpoints based on what's enabled"""
>     results = []
>     
>     # Define known service endpoints
>     service_endpoints = {
>         "rabbitmq": [
>             ("/api/v1/rabbitmq/queues", "GET", "List queues"),
>             ("/api/v1/rabbitmq/exchanges", "GET", "List exchanges"),
>             ("/api/v1/rabbitmq/publish", "POST", "Publish message"),
>         ],
>         "stack_agent_api": [
>             ("/api/v1/stack_agent_api/hosts", "GET", "List hosts"),
>             ("/api/v1/stack_agent_api/stacks", "GET", "List stacks"),
>             ("/api/v1/stack_agent_api/register-stack", "POST", "Register stack"),
>         ]
>     }
>     
>     # Get enabled services from health data
>     services = health_data.get("services", {})
>     
>     for service_name, endpoints in service_endpoints.items():
>         # Check if service should be tested
>         if service_name == "stack_agent_api" or services.get(service_name.replace("_api", ""), False):
>             for path, method, description in endpoints:
>                 # Prepare test data for POST requests
>                 test_data = None
>                 if method == "POST":
>                     if "publish" in path:
>                         test_data = json.dumps({"message": "test", "queue": "test-queue"})
>                     elif "register" in path:
>                         test_data = json.dumps({"stack": "test", "version": "1.0"})
>                     else:
>                         test_data = json.dumps({"test": "data"})
>                 
>                 # Test endpoint
>                 response = python_http_request(
>                     NAMESPACE,
>                     path,
>                     method,
>                     data=test_data
>                 )
>                 
>                 status_code = response.get("status", 0)
>                 
>                 # If 401, retry with API key
>                 if status_code == 401 and API_KEY:
>                     response = python_http_request(
>                         NAMESPACE,
>                         path,
>                         method,
>                         headers={"X-API-Key": API_KEY},
>                         data=test_data
>                     )
>                     status_code = response.get("status", 0)
>                     auth_used = " (with API key)"
>                 else:
>                     auth_used = ""
>                 
>                 # Evaluate result
>                 if status_code in [200, 201, 204]:
>                     status = True
>                     severity = "info"
>                     symbol = "✓"
>                 elif status_code == 404:
>                     status = False
>                     severity = "warning"
>                     symbol = "✗"
>                 else:
>                     status = False
>                     severity = "warning"
>                     symbol = "✗"
>                 
>                 results.append(create_test_result(
>                     f"{service_name}_{path.split('/')[-1]}_{method.lower()}",
>                     f"{service_name.upper()}: {description}",
>                     status,
>                     f"{symbol} {method} {path} → HTTP {status_code}{auth_used}",
>                     severity
>                 ))
>     
>     return results
> 
> def generate_summary(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
>     """Generate overall summary"""
>     total = len(all_results)
>     successful = len([r for r in all_results if r.get("status")])
>     critical_issues = len([r for r in all_results if r.get("severity") == "critical" and not r.get("status")])
>     
>     return create_test_result(
>         "overall_summary",
>         "Overall test summary",
>         critical_issues == 0,
>         f"Passed: {successful}/{total} | Critical issues: {critical_issues}",
>         "critical" if critical_issues > 0 else "info"
>     )
> 
> # ------------------------------------------------------------
> # Runner
> # ------------------------------------------------------------
> 
> def test_fastapi() -> List[Dict[str, Any]]:
>     """Main test function"""
>     all_results = []
>     
>     # Test deployment
>     all_results.extend(test_deployment())
>     
>     # Test health endpoint
>     health_results, health_data = test_health_endpoint()
>     all_results.extend(health_results)
>     
>     # Test core endpoints
>     all_results.extend(test_core_endpoints())
>     
>     # Test service endpoints
>     all_results.extend(test_service_endpoints(health_data))
>     
>     # Generate summary
>     all_results.append(generate_summary(all_results))
>     
>     return all_results
> 
> # ------------------------------------------------------------
> # Main entry point
> # ------------------------------------------------------------
> 
> if __name__ == "__main__":
>     try:
>         results = test_fastapi()
>         
>         # Output JSON
>         print(json.dumps(results, indent=2))
>         
>         # Exit with error if critical issues
>         critical = sum(1 for r in results if not r.get("status") and r.get("severity") == "critical")
>         sys.exit(1 if critical > 0 else 0)
>         
>     except KeyboardInterrupt:
>         sys.exit(1)
>     except Exception as e:
>         sys.exit(1)
> EOF
taskagent@stack-agent-58977ccfdd-x52t2:/app$ 
taskagent@stack-agent-58977ccfdd-x52t2:/app$ 
taskagent@stack-agent-58977ccfdd-x52t2:/app$ 
taskagent@stack-agent-58977ccfdd-x52t2:/app$ cat <<EOF > test.py
taskagent@stack-agent-58977ccfdd-x52t2:/app$ python3 test.py 
taskagent@stack-agent-58977ccfdd-x52t2:/app$ python3 test.py 
[
  {
    "name": "deployment",
    "description": "Kubernetes deployment",
    "status": true,
    "output": "\u2713 1/1 replicas ready",
    "severity": "info"
  },
  {
    "name": "health_endpoint",
    "description": "Health check endpoint",
    "status": true,
    "output": "\u2713 /health \u2192 HTTP 200",
    "severity": "info"
  },
  {
    "name": "core_openapi.json",
    "description": "OpenAPI schema",
    "status": false,
    "output": "\u2717 /openapi.json \u2192 HTTP 401 (with API key)",
    "severity": "info"
  },
  {
    "name": "rabbitmq_queues_get",
    "description": "RABBITMQ: List queues",
    "status": true,
    "output": "\u2713 GET /api/v1/rabbitmq/queues \u2192 HTTP 200",
    "severity": "info"
  },
  {
    "name": "rabbitmq_exchanges_get",
    "description": "RABBITMQ: List exchanges",
    "status": true,
    "output": "\u2713 GET /api/v1/rabbitmq/exchanges \u2192 HTTP 200",
    "severity": "info"
  },
  {
    "name": "rabbitmq_publish_post",
    "description": "RABBITMQ: Publish message",
    "status": false,
    "output": "\u2717 POST /api/v1/rabbitmq/publish \u2192 HTTP 404",
    "severity": "warning"
  },
  {
    "name": "stack_agent_api_hosts_get",
    "description": "STACK_AGENT_API: List hosts",
    "status": true,
    "output": "\u2713 GET /api/v1/stack_agent_api/hosts \u2192 HTTP 200",
    "severity": "info"
  },
  {
    "name": "stack_agent_api_stacks_get",
    "description": "STACK_AGENT_API: List stacks",
    "status": true,
    "output": "\u2713 GET /api/v1/stack_agent_api/stacks \u2192 HTTP 200",
    "severity": "info"
  },
  {
    "name": "stack_agent_api_register-stack_post",
    "description": "STACK_AGENT_API: Register stack",
    "status": false,
    "output": "\u2717 POST /api/v1/stack_agent_api/register-stack \u2192 HTTP 422",
    "severity": "warning"
  },
  {
    "name": "overall_summary",
    "description": "Overall test summary",
    "status": true,
    "output": "Passed: 6/9 | Critical issues: 0",
    "severity": "info"
  }
]
