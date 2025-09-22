#!/usr/bin/env python3
"""
FastAPI Service Test Script
- Tests FastAPI endpoints based on configured links from environment
- Dynamically discovers and tests components (exchanges, databases, buckets, etc.)
- Validates authentication, health checks, and component-specific operations

ENV VARS:
  FASTAPI_HOST (default: fastapi.fastapi.svc.cluster.local)
  FASTAPI_PORT (default: 8080)
  FASTAPI_NS (default: fastapi)
  FASTAPI_API_KEY (API key for authenticated endpoints)
  FASTAPI_LOGIN (Basic auth username, default: admin)
  FASTAPI_PASSWORD (Basic auth password)
  FASTAPI_LINKS (Format: name:type:auth_enabled,name2:type2:auth_enabled)
    Types: exchange, queue, db, bucket, topic

Output: JSON array of test results to stdout
"""

import os
import json
import time
import requests
import subprocess
import sys
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
import base64

# ------------------------------------------------------------
# Configuration & Utilities
# ------------------------------------------------------------

@dataclass
class ComponentLink:
    """Represents a linked component from FASTAPI_LINKS"""
    name: str
    type: str  # exchange, queue, db, bucket, topic
    api_key_required: bool
    
    @property
    def service_name(self):
        """Map component type to service name"""
        mapping = {
            'exchange': 'rabbitmq',
            'queue': 'rabbitmq',
            'db': 'postgresql',  # or mongodb, depends on context
            'bucket': 'minio',
            'topic': 'kafka'
        }
        return mapping.get(self.type, self.type)

def parse_fastapi_links() -> List[ComponentLink]:
    """Parse FASTAPI_LINKS environment variable"""
    links = []
    links_env = os.getenv('FASTAPI_LINKS', '')
    
    if not links_env:
        print("Warning: FASTAPI_LINKS not found", file=sys.stderr)
        return links
    
    for link in links_env.split(','):
        if link.strip():
            parts = link.strip().split(':')
            if len(parts) >= 2:
                name = parts[0]
                comp_type = parts[1]
                # Parse auth requirement
                api_key = False
                if len(parts) > 2:
                    auth_part = parts[2].lower()
                    if 'api_key=true' in auth_part or 'api-key=true' in auth_part:
                        api_key = True
                
                links.append(ComponentLink(
                    name=name,
                    type=comp_type,
                    api_key_required=api_key
                ))
    
    return links

# Configuration
FASTAPI_HOST = os.getenv('FASTAPI_HOST', 'fastapi.fastapi.svc.cluster.local')
FASTAPI_PORT = os.getenv('FASTAPI_PORT', '8080')
FASTAPI_NS = os.getenv('FASTAPI_NS', 'fastapi')
FASTAPI_API_KEY = os.getenv('FASTAPI_API_KEY', '')
FASTAPI_LOGIN = os.getenv('FASTAPI_LOGIN', 'admin')
FASTAPI_PASSWORD = os.getenv('FASTAPI_PASSWORD', '')

# Parse component links
COMPONENT_LINKS = parse_fastapi_links()

# Base URL for FastAPI
BASE_URL = f"http://{FASTAPI_HOST}:{FASTAPI_PORT}"

# ------------------------------------------------------------
# HTTP Client Helper
# ------------------------------------------------------------

class FastAPIClient:
    """HTTP client for FastAPI with auth support"""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None, 
                 username: Optional[str] = None, password: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
        self.username = username
        self.password = password
        self.session = requests.Session()
        self._setup_auth()
    
    def _setup_auth(self):
        """Setup authentication headers"""
        if self.api_key:
            self.session.headers['X-API-Key'] = self.api_key
        
        if self.username and self.password:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.session.headers['Authorization'] = f"Basic {credentials}"
    
    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """GET request"""
        url = f"{self.base_url}{endpoint}"
        return self.session.get(url, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> requests.Response:
        """POST request"""
        url = f"{self.base_url}{endpoint}"
        return self.session.post(url, **kwargs)
    
    def put(self, endpoint: str, **kwargs) -> requests.Response:
        """PUT request"""
        url = f"{self.base_url}{endpoint}"
        return self.session.put(url, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        """DELETE request"""
        url = f"{self.base_url}{endpoint}"
        return self.session.delete(url, **kwargs)

# ------------------------------------------------------------
# Result Helper
# ------------------------------------------------------------

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }

# ------------------------------------------------------------
# Core Tests
# ------------------------------------------------------------

def check_fastapi_health(client: FastAPIClient) -> List[Dict[str, Any]]:
    """Check FastAPI basic health and connectivity"""
    tests = []
    
    # Test root endpoint
    try:
        response = client.get("/")
        if response.status_code in [200, 307]:  # 307 is redirect to /docs
            tests.append(create_test_result(
                "fastapi_root",
                "Check FastAPI root endpoint",
                True,
                f"FastAPI is responding (status: {response.status_code})",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                "fastapi_root",
                "Check FastAPI root endpoint",
                False,
                f"Unexpected status code: {response.status_code}",
                "WARNING"
            ))
    except Exception as e:
        tests.append(create_test_result(
            "fastapi_root",
            "Check FastAPI root endpoint",
            False,
            f"Failed to connect: {str(e)}",
            "CRITICAL"
        ))
        return tests  # Early exit if can't connect
    
    # Test health endpoint
    try:
        response = client.get("/health")
        if response.status_code == 200:
            health_data = response.json()
            
            # Check overall status
            is_healthy = health_data.get('status') == 'healthy'
            
            # Build output message
            services = health_data.get('services', {})
            active_services = [k for k, v in services.items() if v]
            
            output = f"Health status: {health_data.get('status', 'unknown')}\n"
            output += f"Active services: {', '.join(active_services) if active_services else 'none'}"
            
            # Check for authentication configuration
            if 'authentication' in health_data:
                auth_info = health_data['authentication']
                auth_enabled = [k for k, v in auth_info.items() if v.get('auth_enabled')]
                if auth_enabled:
                    output += f"\nAuth-enabled services: {', '.join(auth_enabled)}"
            
            tests.append(create_test_result(
                "fastapi_health",
                "Check FastAPI health endpoint",
                is_healthy,
                output,
                "INFO" if is_healthy else "WARNING"
            ))
            
            # Store health data for other tests
            tests.append(create_test_result(
                "fastapi_services",
                "Detected FastAPI services",
                True,
                f"Services detected: {json.dumps(services, indent=2)}",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                "fastapi_health",
                "Check FastAPI health endpoint",
                False,
                f"Health check failed with status: {response.status_code}",
                "WARNING"
            ))
    except Exception as e:
        tests.append(create_test_result(
            "fastapi_health",
            "Check FastAPI health endpoint",
            False,
            f"Failed to check health: {str(e)}",
            "WARNING"
        ))
    
    # Test info endpoint
    try:
        response = client.get("/info")
        if response.status_code == 200:
            info = response.json()
            tests.append(create_test_result(
                "fastapi_info",
                "Check FastAPI info endpoint",
                True,
                f"App: {info.get('name', 'unknown')} v{info.get('version', 'unknown')}",
                "INFO"
            ))
    except:
        pass  # Info endpoint is optional
    
    return tests

def check_docs_authentication(client: FastAPIClient) -> List[Dict[str, Any]]:
    """Check if documentation endpoints require authentication"""
    tests = []
    
    # Test OpenAPI endpoint
    try:
        response = client.get("/openapi.json")
        if response.status_code == 200:
            tests.append(create_test_result(
                "openapi_access",
                "Check OpenAPI schema access",
                True,
                "OpenAPI schema is accessible",
                "INFO"
            ))
        elif response.status_code == 401:
            tests.append(create_test_result(
                "openapi_auth",
                "Check OpenAPI authentication",
                True,
                "OpenAPI schema is protected (requires auth)",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                "openapi_access",
                "Check OpenAPI schema access",
                False,
                f"Unexpected status: {response.status_code}",
                "WARNING"
            ))
    except Exception as e:
        tests.append(create_test_result(
            "openapi_access",
            "Check OpenAPI schema access",
            False,
            f"Failed to access OpenAPI: {str(e)}",
            "WARNING"
        ))
    
    # Test Swagger UI
    try:
        response = client.get("/docs")
        if response.status_code in [200, 307]:
            tests.append(create_test_result(
                "swagger_ui",
                "Check Swagger UI access",
                True,
                "Swagger UI is accessible",
                "INFO"
            ))
        elif response.status_code == 401:
            tests.append(create_test_result(
                "swagger_ui_auth",
                "Check Swagger UI authentication",
                True,
                "Swagger UI is protected (requires auth)",
                "INFO"
            ))
    except:
        pass
    
    return tests

def test_postgresql_component(client: FastAPIClient, component: ComponentLink) -> List[Dict[str, Any]]:
    """Test PostgreSQL database component"""
    tests = []
    base_path = f"/api/v1/postgresql/{component.name}"
    
    # Test database info
    try:
        response = client.get(f"{base_path}/info")
        if response.status_code == 200:
            info = response.json()
            tests.append(create_test_result(
                f"postgres_{component.name}_info",
                f"Check PostgreSQL database '{component.name}' info",
                True,
                f"Database: {info.get('database', 'unknown')} on {info.get('host', 'unknown')}",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                f"postgres_{component.name}_info",
                f"Check PostgreSQL database '{component.name}' info",
                False,
                f"Failed with status: {response.status_code}",
                "WARNING"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"postgres_{component.name}_info",
            f"Check PostgreSQL database '{component.name}' info",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    # Test user operations
    try:
        # List users
        response = client.get(f"{base_path}/users?limit=5")
        if response.status_code == 200:
            users = response.json()
            tests.append(create_test_result(
                f"postgres_{component.name}_users",
                f"List users in database '{component.name}'",
                True,
                f"Found {len(users)} user(s)",
                "INFO"
            ))
        
        # Try to create a test user
        test_user = {
            "email": f"test_{int(time.time())}@example.com",
            "username": f"testuser_{int(time.time())}",
            "password": "testpass123",
            "is_active": True,
            "is_superuser": False
        }
        
        response = client.post(f"{base_path}/users", json=test_user)
        if response.status_code in [200, 201]:
            user_data = response.json()
            user_id = user_data.get('id')
            
            tests.append(create_test_result(
                f"postgres_{component.name}_create",
                f"Create user in database '{component.name}'",
                True,
                f"Created user with ID: {user_id}",
                "INFO"
            ))
            
            # Clean up - delete the test user
            if user_id:
                client.delete(f"{base_path}/users/{user_id}")
        elif response.status_code == 400:
            # User might already exist
            tests.append(create_test_result(
                f"postgres_{component.name}_create",
                f"Create user in database '{component.name}'",
                True,
                "User creation test completed (user may already exist)",
                "INFO"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"postgres_{component.name}_operations",
            f"Test operations on database '{component.name}'",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    return tests

def test_mongodb_component(client: FastAPIClient, component: ComponentLink) -> List[Dict[str, Any]]:
    """Test MongoDB database component"""
    tests = []
    base_path = f"/api/v1/mongodb/{component.name}"
    
    # Test database info
    try:
        response = client.get(f"{base_path}/info")
        if response.status_code == 200:
            info = response.json()
            tests.append(create_test_result(
                f"mongodb_{component.name}_info",
                f"Check MongoDB database '{component.name}' info",
                True,
                f"Database: {info.get('database', 'unknown')}, Collection: {info.get('collection', 'unknown')}",
                "INFO"
            ))
        else:
            tests.append(create_test_result(
                f"mongodb_{component.name}_info",
                f"Check MongoDB database '{component.name}' info",
                False,
                f"Failed with status: {response.status_code}",
                "WARNING"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"mongodb_{component.name}_info",
            f"Check MongoDB database '{component.name}' info",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    # Test collection operations
    try:
        # Count users
        response = client.get(f"{base_path}/users/count")
        if response.status_code == 200:
            count_data = response.json()
            tests.append(create_test_result(
                f"mongodb_{component.name}_count",
                f"Count documents in database '{component.name}'",
                True,
                f"Document count: {count_data.get('count', 0)}",
                "INFO"
            ))
        
        # Health check
        response = client.get(f"{base_path}/health")
        if response.status_code == 200:
            health = response.json()
            is_healthy = health.get('status') == 'healthy'
            tests.append(create_test_result(
                f"mongodb_{component.name}_health",
                f"Check MongoDB database '{component.name}' health",
                is_healthy,
                health.get('message', 'Health check completed'),
                "INFO" if is_healthy else "WARNING"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"mongodb_{component.name}_operations",
            f"Test operations on database '{component.name}'",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    return tests

def test_rabbitmq_component(client: FastAPIClient, component: ComponentLink) -> List[Dict[str, Any]]:
    """Test RabbitMQ queue/exchange component"""
    tests = []
    
    if component.type == 'queue':
        base_path = f"/api/v1/rabbitmq/queues/{component.name}"
        
        # Test queue info
        try:
            response = client.get(f"{base_path}/info")
            if response.status_code == 200:
                info = response.json()
                tests.append(create_test_result(
                    f"rabbitmq_queue_{component.name}_info",
                    f"Check RabbitMQ queue '{component.name}' info",
                    True,
                    f"Queue: {info.get('name', 'unknown')} on vhost: {info.get('vhost', '/')}",
                    "INFO"
                ))
            
            # Test message publishing
            test_message = {
                "content": {
                    "test": "message",
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "test_script"
                }
            }
            
            response = client.post(f"{base_path}/publish", json=test_message)
            if response.status_code == 200:
                tests.append(create_test_result(
                    f"rabbitmq_queue_{component.name}_publish",
                    f"Publish message to queue '{component.name}'",
                    True,
                    "Successfully published test message",
                    "INFO"
                ))
        except Exception as e:
            tests.append(create_test_result(
                f"rabbitmq_queue_{component.name}",
                f"Test RabbitMQ queue '{component.name}'",
                False,
                f"Error: {str(e)}",
                "WARNING"
            ))
    
    elif component.type == 'exchange':
        base_path = f"/api/v1/rabbitmq/exchanges/{component.name}"
        
        # Test exchange operations
        try:
            # Test exchange declaration
            response = client.post(f"{base_path}/declare?exchange_type=direct")
            if response.status_code in [200, 409]:  # 409 if already exists
                tests.append(create_test_result(
                    f"rabbitmq_exchange_{component.name}_declare",
                    f"Declare RabbitMQ exchange '{component.name}'",
                    True,
                    "Exchange declared or already exists",
                    "INFO"
                ))
            
            # Test message publishing to exchange
            test_message = {
                "content": {
                    "test": "exchange_message",
                    "timestamp": datetime.utcnow().isoformat()
                },
                "routing_key": "test.route"
            }
            
            response = client.post(f"{base_path}/publish", json=test_message)
            if response.status_code == 200:
                tests.append(create_test_result(
                    f"rabbitmq_exchange_{component.name}_publish",
                    f"Publish message to exchange '{component.name}'",
                    True,
                    "Successfully published test message to exchange",
                    "INFO"
                ))
        except Exception as e:
            tests.append(create_test_result(
                f"rabbitmq_exchange_{component.name}",
                f"Test RabbitMQ exchange '{component.name}'",
                False,
                f"Error: {str(e)}",
                "WARNING"
            ))
    
    return tests

def test_minio_component(client: FastAPIClient, component: ComponentLink) -> List[Dict[str, Any]]:
    """Test MinIO bucket component"""
    tests = []
    base_path = f"/api/v1/minio/{component.name}"
    
    # Test bucket configuration
    try:
        response = client.get(f"{base_path}/config")
        if response.status_code == 200:
            config = response.json()
            tests.append(create_test_result(
                f"minio_bucket_{component.name}_config",
                f"Check MinIO bucket '{component.name}' configuration",
                True,
                f"Bucket: {config.get('bucket_name', 'unknown')} on {config.get('endpoint', 'unknown')}",
                "INFO"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"minio_bucket_{component.name}_config",
            f"Check MinIO bucket '{component.name}' configuration",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    # Test bucket existence
    try:
        response = client.get(f"{base_path}/exists")
        if response.status_code == 200:
            data = response.json()
            exists = data.get('exists', False)
            tests.append(create_test_result(
                f"minio_bucket_{component.name}_exists",
                f"Check if bucket '{component.name}' exists",
                exists,
                f"Bucket {'exists' if exists else 'does not exist'}",
                "INFO" if exists else "WARNING"
            ))
    except:
        pass
    
    # Test listing objects
    try:
        response = client.get(f"{base_path}/list?max_results=10")
        if response.status_code == 200:
            data = response.json()
            object_count = data.get('total_count', 0)
            tests.append(create_test_result(
                f"minio_bucket_{component.name}_list",
                f"List objects in bucket '{component.name}'",
                True,
                f"Found {object_count} object(s) in bucket",
                "INFO"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"minio_bucket_{component.name}_list",
            f"List objects in bucket '{component.name}'",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    return tests

def test_kafka_component(client: FastAPIClient, component: ComponentLink) -> List[Dict[str, Any]]:
    """Test Kafka topic component"""
    tests = []
    base_path = f"/api/v1/kafka/topics/{component.name}"
    
    # Test topic info
    try:
        response = client.get(f"{base_path}/info")
        if response.status_code == 200:
            info = response.json()
            tests.append(create_test_result(
                f"kafka_topic_{component.name}_info",
                f"Check Kafka topic '{component.name}' info",
                True,
                f"Topic: {info.get('topic', 'unknown')}, Partitions: {info.get('partitions', 'unknown')}",
                "INFO"
            ))
        
        # Test producing a message
        test_message = {
            "key": f"test_{int(time.time())}",
            "value": {
                "test": "message",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        response = client.post(f"{base_path}/produce", json=test_message)
        if response.status_code == 200:
            tests.append(create_test_result(
                f"kafka_topic_{component.name}_produce",
                f"Produce message to topic '{component.name}'",
                True,
                "Successfully produced test message",
                "INFO"
            ))
    except Exception as e:
        tests.append(create_test_result(
            f"kafka_topic_{component.name}",
            f"Test Kafka topic '{component.name}'",
            False,
            f"Error: {str(e)}",
            "WARNING"
        ))
    
    return tests

def test_component_endpoints(client: FastAPIClient, component: ComponentLink) -> List[Dict[str, Any]]:
    """Test endpoints for a specific component based on its type"""
    
    # Create client with or without API key based on component requirements
    if component.api_key_required and FASTAPI_API_KEY:
        auth_client = FastAPIClient(BASE_URL, api_key=FASTAPI_API_KEY)
    else:
        auth_client = client
    
    # Route to appropriate test function based on component type
    if component.type == 'db':
        # Try PostgreSQL first, then MongoDB
        tests = test_postgresql_component(auth_client, component)
        if not any(t['status'] for t in tests):
            # If PostgreSQL tests failed, try MongoDB
            tests.extend(test_mongodb_component(auth_client, component))
    elif component.type in ['queue', 'exchange']:
        tests = test_rabbitmq_component(auth_client, component)
    elif component.type == 'bucket':
        tests = test_minio_component(auth_client, component)
    elif component.type == 'topic':
        tests = test_kafka_component(auth_client, component)
    else:
        tests = [create_test_result(
            f"unknown_component_{component.name}",
            f"Test component '{component.name}'",
            False,
            f"Unknown component type: {component.type}",
            "WARNING"
        )]
    
    return tests

def check_api_endpoints(client: FastAPIClient) -> List[Dict[str, Any]]:
    """Check main API endpoints"""
    tests = []
    
    # Test main API health
    try:
        response = client.get("/api/v1/health")
        if response.status_code == 200:
            tests.append(create_test_result(
                "api_v1_health",
                "Check API v1 health endpoint",
                True,
                "API v1 is healthy",
                "INFO"
            ))
    except:
        pass
    
    # Test service-specific endpoints based on health check
    try:
        response = client.get("/health")
        if response.status_code == 200:
            health_data = response.json()
            services = health_data.get('services', {})
            
            for service, is_active in services.items():
                if is_active:
                    # Test service endpoint
                    try:
                        response = client.get(f"/api/v1/{service}/")
                        if response.status_code == 200:
                            tests.append(create_test_result(
                                f"api_{service}_list",
                                f"Check {service} API listing",
                                True,
                                f"{service} API is accessible",
                                "INFO"
                            ))
                    except:
                        pass
    except:
        pass
    
    return tests

# ------------------------------------------------------------
# Main Test Runner
# ------------------------------------------------------------

def test_fastapi() -> List[Dict[str, Any]]:
    """Run all FastAPI validation tests"""
    results = []
    
    # Create client with basic auth if configured
    client = FastAPIClient(
        BASE_URL,
        username=FASTAPI_LOGIN if FASTAPI_PASSWORD else None,
        password=FASTAPI_PASSWORD if FASTAPI_PASSWORD else None
    )
    
    # 1. Test basic health and connectivity
    results.extend(check_fastapi_health(client))
    
    # Check if we can connect
    if not any(r['name'] == 'fastapi_root' and r['status'] for r in results):
        return results  # Exit early if can't connect
    
    # 2. Test documentation endpoints
    results.extend(check_docs_authentication(client))
    
    # 3. Test main API endpoints
    results.extend(check_api_endpoints(client))
    
    # 4. Test each configured component
    for component in COMPONENT_LINKS:
        results.append(create_test_result(
            f"component_{component.name}_detected",
            f"Detected component '{component.name}'",
            True,
            f"Type: {component.type}, API Key Required: {component.api_key_required}",
            "INFO"
        ))
        
        # Test component endpoints
        component_tests = test_component_endpoints(client, component)
        results.extend(component_tests)
    
    # 5. Test authentication if API key is configured
    if FASTAPI_API_KEY:
        # Test with API key
        auth_client = FastAPIClient(BASE_URL, api_key=FASTAPI_API_KEY)
        
        # Try a protected endpoint
        try:
            response = auth_client.get("/api/v1/postgresql/")
            tests_auth = create_test_result(
                "api_key_auth",
                "Test API key authentication",
                response.status_code != 401,
                f"API key auth test: status {response.status_code}",
                "INFO" if response.status_code != 401 else "WARNING"
            )
            results.append(tests_auth)
        except:
            pass
    
    return results

def main():
    """Main entry point"""
    try:
        print(f"Testing FastAPI at {BASE_URL}", file=sys.stderr)
        print(f"Detected {len(COMPONENT_LINKS)} component link(s)", file=sys.stderr)
        
        # Run tests
        results = test_fastapi()
        
        # Output JSON results
        print(json.dumps(results, indent=2))
        
        # Exit with appropriate code
        critical_failures = [r for r in results if r['severity'] == 'critical' and not r['status']]
        warnings = [r for r in results if r['severity'] == 'warning' and not r['status']]
        
        if critical_failures:
            sys.exit(2)  # Critical issues
        elif warnings:
            sys.exit(1)  # Warnings
        else:
            sys.exit(0)  # All good
        
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
