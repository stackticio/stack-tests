# stack_test_definitions.py - Fully Generic Test Framework
# This file NEVER needs to be modified - all customization via test_{component}.py files
{% raw %}

import os
import sys
import importlib
from typing import Dict, List

# Add paths for component test files
sys.path.insert(0, '/app/test_modules/components')
sys.path.insert(0, '/app/test_modules')

def get_component_tests(component: str) -> Dict[str, List[Dict]]:
    """
    Main entry point - discovers single component tests.
    """
    component_tests = {}

    component_tests = load_component_tests(component)
    print(f"Loaded {len(component_tests)} tests for {component}")            
    
    return component_tests

def get_all_tests() -> Dict[str, List[Dict]]:
    """
    Main entry point - discovers components and loads their tests.
    DO NOT MODIFY THIS FUNCTION!
    """
    all_tests = {}
    
    # Discover all components from environment variables
    components = discover_components_from_env()
    print(f"Discovered components: {components}")
    
    for component in components:
        tests = load_component_tests(component)
        if tests:
            all_tests[component] = tests
            print(f"Loaded {len(tests)} tests for {component}")
    
    if not all_tests:
        all_tests['system'] = [{
            'name': 'system_health',
            'description': 'No components configured',
            'command': 'echo',
            'args': ['Stack Agent ready but no components found in environment'],
            'expected_exit_code': 0,
            'component': 'system'
        }]
    
    total = sum(len(tests) for tests in all_tests.values())
    print(f"Total: {len(all_tests)} components, {total} tests")
    
    return all_tests

def discover_components_from_env() -> List[str]:
    """
    Discovers components from _HOST environment variables.
    Looks for patterns like MONGODB_HOST, RABBITMQ_RABBITMQ_HOST, etc.
    DO NOT MODIFY THIS FUNCTION!
    """
    components = set()
    
    for key in os.environ:
        if '_HOST' in key:
            # Extract component name from patterns like:
            # MONGODB_MONGODB_HOST -> mongodb
            # POSTGRES_HOST -> postgres
            # APISIX_APISIX_HOST -> apisix
            parts = key.replace('_HOST', '').lower().split('_')
            if parts:
                component = parts[0]
                # Skip generic names
                if component not in ['service', 'cluster', 'internal']:
                    components.add(component)
    
    return sorted(list(components))

def load_component_tests(component: str) -> List[Dict]:
    """
    Loads tests for a component.
    Priority order:
    1. Try to import test_{component}.py and call get_{component}_tests()
    2. Try to import test_{component}.py and call get_tests()
    3. Generate basic connectivity tests
    DO NOT MODIFY THIS FUNCTION!
    """
    
    # Try to load custom test file
    try:
        module_name = f'test_{component}'
        module = importlib.import_module(module_name)
        
        # Try component-specific function name
        func_name = f'get_{component}_tests'
        if hasattr(module, func_name):
            func = getattr(module, func_name)
            if callable(func):
                tests = func()
                if tests:
                    print(f"  Using custom test file: {module_name}.py")
                    return tests
        
        # Try generic function name
        if hasattr(module, 'get_tests'):
            func = getattr(module, 'get_tests')
            if callable(func):
                tests = func()
                if tests:
                    print(f"  Using custom test file: {module_name}.py (generic)")
                    return tests
                    
    except ImportError:
        # No custom test file exists
        pass
    except Exception as e:
        print(f"  Error loading test_{component}.py: {e}")
    
    # Generate basic tests if no custom file
    print(f"  Generating basic tests for {component}")
    return generate_basic_tests(component)

def generate_basic_tests(component: str) -> List[Dict]:
    """
    Generates basic connectivity and health tests when no custom file exists.
    DO NOT MODIFY THIS FUNCTION!
    """
    tests = []
    
    # Get connection info from environment
    host = get_component_env(component, 'HOST')
    if not host:
        return []
    
    port = get_component_env(component, 'PORT')
    if not port:
        port = get_default_port(component)
    
    # Always add connectivity test
    tests.append({
        'name': f'{component}_connectivity',
        'description': f'Test {component} connectivity',
        'command': 'bash',
        'args': ['-c', f'nc -zv {host} {port} 2>&1 || echo "Connection to {host}:{port} failed"'],
        'timeout': 10,
        'component': component
    })
    
    # Add component-specific basic tests based on type
    if component in ['postgresql', 'postgres', 'cnpg']:
        admin_pass = get_component_env(component, 'ADMIN_PASSWORD') or 'default_password'
        tests.append({
            'name': f'{component}_version',
            'description': f'{component.upper()} version check',
            'command': 'psql',
            'args': [
                f'postgresql://postgres:{admin_pass}@{host}:{port}/postgres',
                '-c', 'SELECT version()'
            ],
            'timeout': 10,
            'component': component
        })
        
        # Check for database configs
        databases = os.getenv(f'{component.upper()}_DATABASES', '')
        if not databases:
            databases = os.getenv('POSTGRES_DATABASES', '')
        
        for db_config in databases.split(';'):
            if db_config.strip():
                parts = db_config.strip().split(':')
                if len(parts) >= 4:
                    name, user, password, database = parts[:4]
                    tests.append({
                        'name': f'{component}_{name}_connectivity',
                        'description': f'Test {database} connectivity',
                        'command': 'psql',
                        'args': [
                            f'postgresql://{user}:{password}@{host}:{port}/{database}',
                            '-c', 'SELECT current_database()'
                        ],
                        'timeout': 10,
                        'component': component
                    })
    
    elif component == 'mongodb':
        admin_pass = get_component_env(component, 'CLUSTER_ADMIN_PASSWORD') or 'default_password'
        tests.append({
            'name': f'{component}_ping',
            'description': 'MongoDB ping test',
            'command': 'mongosh',
            'args': [
                f'--host={host}:{port}',
                '--username=clusterAdmin',
                f'--password={admin_pass}',
                '--authenticationDatabase=admin',
                '--quiet',
                '--eval', 'db.adminCommand({ ping: 1 })'
            ],
            'timeout': 30,
            'component': component
        })
        
        # Check for database configs
        databases = os.getenv('MONGODB_DATABASES', '')
        for db_config in databases.split(';'):
            if db_config.strip():
                parts = db_config.strip().split(':')
                if len(parts) >= 4:
                    name, user, password, database = parts[:4]
                    tests.append({
                        'name': f'{component}_{name}_connectivity',
                        'description': f'Test {database} connectivity',
                        'command': 'mongosh',
                        'args': [
                            f'--host={host}:{port}',
                            f'--username={user}',
                            f'--password={password}',
                            f'--authenticationDatabase={database}',
                            '--quiet',
                            '--eval', f'db.getSiblingDB("{database}").runCommand({{ ping: 1 }})'
                        ],
                        'timeout': 30,
                        'component': component
                    })
    
    elif component == 'rabbitmq':
        user = get_component_env(component, 'USER') or 'user'
        password = get_component_env(component, 'PASSWORD') or 'default_pass1'
        mgmt_port = '15672'
        
        tests.append({
            'name': f'{component}_management_api',
            'description': 'Check RabbitMQ Management API',
            'command': 'curl',
            'args': ['-f', '-s', f'http://{host}:{mgmt_port}/api/overview', '-u', f'{user}:{password}'],
            'timeout': 10,
            'component': component
        })
        
        # Check for queues
        queues = os.getenv('RABBITMQ_QUEUES', '')
        for queue in queues.split(','):
            if queue.strip():
                tests.append({
                    'name': f'{component}_queue_{queue.strip()}',
                    'description': f'Check queue {queue.strip()}',
                    'command': 'curl',
                    'args': ['-s', f'http://{host}:{mgmt_port}/api/queues/%2F/{queue.strip()}', 
                            '-u', f'{user}:{password}'],
                    'timeout': 10,
                    'component': component
                })
        
        # Check for exchanges
        exchanges = os.getenv('RABBITMQ_EXCHANGES', '')
        for exchange in exchanges.split(','):
            if exchange.strip():
                tests.append({
                    'name': f'{component}_exchange_{exchange.strip()}',
                    'description': f'Check exchange {exchange.strip()}',
                    'command': 'curl',
                    'args': ['-s', f'http://{host}:{mgmt_port}/api/exchanges/%2F/{exchange.strip()}', 
                            '-u', f'{user}:{password}'],
                    'timeout': 10,
                    'component': component
                })
    
    elif component == 'minio':
        tests.append({
            'name': f'{component}_health',
            'description': 'MinIO health check',
            'command': 'curl',
            'args': ['-f', '-s', '-I', f'http://{host}:{port}/minio/health/live'],
            'timeout': 10,
            'component': component
        })
        
        # Check for buckets
        buckets = os.getenv('MINIO_BUCKETS', '')
        for bucket_config in buckets.split(';'):
            if bucket_config.strip():
                parts = bucket_config.strip().split(':')
                if len(parts) >= 4:
                    name, bucket, access_key, secret_key = parts[:4]
                    tests.append({
                        'name': f'{component}_{name}_config',
                        'description': f'Configure mc for {bucket}',
                        'command': 'mc',
                        'args': ['alias', 'set', f'minio-{name}', f'http://{host}:{port}', 
                                access_key, secret_key],
                        'timeout': 10,
                        'component': component
                    })
                    tests.append({
                        'name': f'{component}_{name}_list',
                        'description': f'List {bucket}',
                        'command': 'mc',
                        'args': ['ls', f'minio-{name}/{bucket}'],
                        'timeout': 10,
                        'component': component
                    })
    
    else:
        # For unknown components, try common HTTP health endpoints
        if port in ['80', '443', '8080', '8000', '3000', '9090', '9200', '3100']:
            for endpoint in ['/health', '/healthz', '/-/healthy', '/api/health', '/status']:
                tests.append({
                    'name': f'{component}_health_{endpoint.replace("/", "_").replace("-", "_")}',
                    'description': f'Try {component} health endpoint {endpoint}',
                    'command': 'curl',
                    'args': ['-f', '-s', '--max-time', '5', f'http://{host}:{port}{endpoint}'],
                    'timeout': 10,
                    'component': component
                })
    
    return tests

def get_component_env(component: str, suffix: str) -> str:
    """
    Gets environment variable for a component.
    Tries patterns: COMPONENT_COMPONENT_SUFFIX, COMPONENT_SUFFIX
    DO NOT MODIFY THIS FUNCTION!
    """
    upper = component.upper()
    
    patterns = [
        f'{upper}_{upper}_{suffix}',  # MONGODB_MONGODB_HOST
        f'{upper}_{suffix}'            # MONGODB_HOST
    ]
    
    for pattern in patterns:
        value = os.environ.get(pattern)
        if value:
            return value
    
    return None

def get_default_port(component: str) -> str:
    """
    Returns default port for known components.
    DO NOT MODIFY THIS FUNCTION!
    """
    defaults = {
        'postgresql': '5432',
        'postgres': '5432',
        'cnpg': '5432',
        'mongodb': '27017',
        'mysql': '3306',
        'redis': '6379',
        'rabbitmq': '5672',
        'kafka': '9092',
        'elasticsearch': '9200',
        'opensearch': '9200',
        'minio': '9000',
        'prometheus': '9090',
        'grafana': '3000',
        'keycloak': '8080',
        'airflow': '8080',
        'loki': '3100',
        'apisix': '80',
        'opa': '8181'
    }
    return defaults.get(component, '80')

# Export
__all__ = ['get_all_tests']

{% endraw %}
