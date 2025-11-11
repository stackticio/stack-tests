
# test_keycloak.py - Smart Keycloak testing with database validation
import os
from typing import List, Dict

def get_keycloak_tests() -> List[Dict]:
    """Generate smart Keycloak tests that validate actual functionality"""
    tests = []
    
    host = os.getenv('KEYCLOAK_KEYCLOAK_HOST', 'keycloak.keycloak.svc.cluster.local')
    port = os.getenv('KEYCLOAK_KEYCLOAK_PORT', '8080')
    admin_password = os.getenv('KEYCLOAK_KEYCLOAK_ADMIN_PASSWORD', 'default_password')
    
    # Test 1: Check pod status and crash reasons
    tests.append({
        'name': 'keycloak_pod_diagnostics',
        'description': 'Diagnose Keycloak pod issues',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Pod Status ===" &&
            kubectl get pods -n keycloak -o json | 
            jq -r '.items[] | "\\(.metadata.name): Status=\\(.status.phase), Restarts=\\(.status.containerStatuses[0].restartCount // 0)"' &&
            echo "" &&
            echo "=== Recent Events ===" &&
            kubectl get events -n keycloak --sort-by='.lastTimestamp' | grep -i "keycloak" | tail -5 &&
            echo "" &&
            echo "=== Last Crash Logs ===" &&
            POD=$(kubectl get pod -n keycloak -l app.kubernetes.io/name=keycloak -o jsonpath='{.items[0].metadata.name}' 2>/dev/null) &&
            if [ ! -z "$POD" ]; then
                kubectl logs -n keycloak $POD --previous --tail=10 2>/dev/null | grep -E "ERROR|FATAL|Exception" || echo "No previous logs"
            fi
            '''
        ],
        'timeout': 20,
        'component': 'keycloak'
    })
    
    # Test 2: Validate PostgreSQL database
    tests.append({
        'name': 'keycloak_database_validation',
        'description': 'Validate Keycloak PostgreSQL database',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Database Validation ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT version();" &&
            echo "" &&
            echo "=== Database Size ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname)) AS size FROM pg_database WHERE datname = 'bitnami_keycloak';" &&
            echo "" &&
            echo "=== Keycloak Tables ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT schemaname, tablename FROM pg_tables WHERE schemaname = 'public' LIMIT 10;" &&
            echo "" &&
            echo "=== Active Connections ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT datname, usename, application_name, state FROM pg_stat_activity WHERE datname = 'bitnami_keycloak';"
            '''
        ],
        'timeout': 20,
        'component': 'keycloak'
    })
    
    # Test 3: Check Keycloak realms in database
    tests.append({
        'name': 'keycloak_realms_check',
        'description': 'Check Keycloak realms in database',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Keycloak Realms ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT id, name, enabled, ssl_required FROM realm;" 2>/dev/null || echo "Realm table might not exist yet" &&
            echo "" &&
            echo "=== Realm Clients ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT client_id, realm_id, enabled FROM client LIMIT 5;" 2>/dev/null || echo "Client table might not exist yet" &&
            echo "" &&
            echo "=== Users Count ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- psql -U bn_keycloak -d bitnami_keycloak -c "SELECT realm_id, COUNT(*) as user_count FROM user_entity GROUP BY realm_id;" 2>/dev/null || echo "User table might not exist yet"
            '''
        ],
        'timeout': 15,
        'component': 'keycloak'
    })
    
    # Test 4: Check Keycloak configuration
    tests.append({
        'name': 'keycloak_config_check',
        'description': 'Check Keycloak configuration and environment',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Keycloak Environment ===" &&
            kubectl exec -n keycloak keycloak-0 -- env | grep -E "KC_|KEYCLOAK_" | sort 2>/dev/null || echo "Pod not running" &&
            echo "" &&
            echo "=== Import Files ===" &&
            kubectl exec -n keycloak keycloak-0 -- ls -la /opt/bitnami/keycloak/data/import/ 2>/dev/null || echo "Cannot access import directory" &&
            echo "" &&
            echo "=== Providers ===" &&
            kubectl exec -n keycloak keycloak-0 -- ls -la /opt/bitnami/keycloak/providers/ 2>/dev/null || echo "Cannot access providers directory"
            '''
        ],
        'timeout': 15,
        'component': 'keycloak'
    })
    
    # Test 5: Test Keycloak API endpoints
    tests.append({
        'name': 'keycloak_api_test',
        'description': 'Test Keycloak API endpoints',
        'command': 'bash',
        'args': [
            '-c',
            f'''
            echo "=== Keycloak API Test ===" &&
            echo "Testing master realm endpoint..." &&
            STATUS=$(curl -s -o /dev/null -w "%{{http_code}}" http://{host}/realms/master --connect-timeout 5) &&
            echo "Master realm status: $STATUS" &&
            if [ "$STATUS" = "200" ]; then
                echo "Getting realm info..." &&
                curl -s http://{host}/realms/master | jq -r '"Realm: \\(.realm), Public Key: \\(.public_key[0:50])..."' 
            else
                echo "Keycloak not responding properly"
            fi &&
            echo "" &&
            echo "Testing admin console..." &&
            ADMIN_STATUS=$(curl -s -o /dev/null -w "%{{http_code}}" http://{host}/admin/ --connect-timeout 5) &&
            echo "Admin console status: $ADMIN_STATUS" &&
            echo "" &&
            echo "Testing health endpoint..." &&
            curl -s http://{host}/health --connect-timeout 5 | jq '.' 2>/dev/null || echo "No health endpoint"
            '''
        ],
        'timeout': 15,
        'component': 'keycloak'
    })
    
    # Test 6: Get token and test authentication
    tests.append({
        'name': 'keycloak_auth_test',
        'description': 'Test Keycloak authentication flow',
        'command': 'bash',
        'args': [
            '-c',
            f'''
            echo "=== Testing Authentication ===" &&
            echo "Getting admin token..." &&
            TOKEN=$(curl -s -X POST http://{host}/realms/master/protocol/openid-connect/token \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "username=user" \
                -d "password={admin_password}" \
                -d "grant_type=password" \
                -d "client_id=admin-cli" | jq -r '.access_token' 2>/dev/null) &&
            if [ "$TOKEN" != "null" ] && [ ! -z "$TOKEN" ]; then
                echo "Token obtained successfully" &&
                echo "Token prefix: ${{TOKEN:0:50}}..." &&
                echo "" &&
                echo "Testing admin API with token..." &&
                curl -s -H "Authorization: Bearer $TOKEN" http://{host}/admin/realms | jq -r '.[] | "Realm: \\(.realm)"' 2>/dev/null || echo "Could not list realms"
            else
                echo "Failed to obtain token - Keycloak might not be fully initialized"
            fi
            '''
        ],
        'timeout': 15,
        'component': 'keycloak'
    })
    
    # Test 7: Check secrets and passwords
    tests.append({
        'name': 'keycloak_secrets_check',
        'description': 'Validate Keycloak secrets configuration',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Secrets Validation ===" &&
            echo "Checking admin password secret..." &&
            kubectl get secret -n keycloak keycloak-admin-password -o json | jq -r '.data | keys[]' 2>/dev/null || echo "Admin password secret not found" &&
            echo "" &&
            echo "Checking PostgreSQL secret..." &&
            kubectl get secret -n keycloak keycloak-postgresql -o json | jq -r '.data | keys[]' &&
            echo "" &&
            echo "Checking realm import secret..." &&
            kubectl get secret -n keycloak keycloak-realm-secret -o json | jq -r '.data | keys[]' 2>/dev/null || echo "Realm secret not found" &&
            echo "" &&
            echo "=== ConfigMaps ===" &&
            kubectl get configmap -n keycloak keycloak-env-vars -o json | jq -r '.data | to_entries[] | "\\(.key)=\\(.value)"' | grep -v PASSWORD
            '''
        ],
        'timeout': 10,
        'component': 'keycloak'
    })
    
    # Test 8: Check JGroups clustering
    tests.append({
        'name': 'keycloak_clustering_check',
        'description': 'Check Keycloak clustering configuration',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Clustering Status ===" &&
            kubectl exec -n keycloak keycloak-0 -- bash -c "netstat -an | grep 7800" 2>/dev/null || echo "Cannot check clustering port" &&
            echo "" &&
            echo "=== DNS Query Test ===" &&
            kubectl exec -n keycloak keycloak-0 -- nslookup keycloak-headless.keycloak.svc.cluster.local 2>/dev/null || echo "DNS lookup failed" &&
            echo "" &&
            echo "=== Cluster Members ===" &&
            kubectl get pods -n keycloak -l app.kubernetes.io/name=keycloak -o json | jq -r '.items[] | "\\(.metadata.name): \\(.status.podIP)"'
            '''
        ],
        'timeout': 15,
        'component': 'keycloak'
    })
    
    # Test 9: Resource consumption
    tests.append({
        'name': 'keycloak_resources_check',
        'description': 'Check Keycloak resource consumption',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Resource Usage ===" &&
            kubectl top pods -n keycloak --no-headers 2>/dev/null || echo "Metrics server not available" &&
            echo "" &&
            echo "=== Java Memory Settings ===" &&
            kubectl exec -n keycloak keycloak-0 -- bash -c "echo $JAVA_OPTS_APPEND" 2>/dev/null || echo "Cannot read Java opts" &&
            echo "" &&
            echo "=== Disk Usage ===" &&
            kubectl exec -n keycloak keycloak-postgresql-0 -- df -h /bitnami/postgresql 2>/dev/null
            '''
        ],
        'timeout': 10,
        'component': 'keycloak'
    })
    
    # Test 10: Fix attempt for crashed pod
    tests.append({
        'name': 'keycloak_troubleshoot',
        'description': 'Troubleshoot and attempt to fix Keycloak issues',
        'command': 'bash',
        'args': [
            '-c',
            '''
            echo "=== Troubleshooting Keycloak ===" &&
            POD_STATUS=$(kubectl get pod -n keycloak keycloak-0 -o jsonpath='{.status.phase}') &&
            if [ "$POD_STATUS" != "Running" ]; then
                echo "Pod is in $POD_STATUS state" &&
                echo "" &&
                echo "Checking init container logs..." &&
                kubectl logs -n keycloak keycloak-0 -c prepare-write-dirs --tail=20 2>/dev/null &&
                echo "" &&
                echo "Checking main container logs..." &&
                kubectl logs -n keycloak keycloak-0 -c keycloak --tail=30 2>/dev/null | grep -E "ERROR|WARN|Exception" &&
                echo "" &&
                echo "Common issues:" &&
                echo "1. Database connection failed - check PostgreSQL" &&
                echo "2. Import realm failed - check realm JSON validity" &&
                echo "3. Memory issues - check resource limits" &&
                echo "4. Permission issues - check volume mounts"
            else
                echo "Pod is running normally"
            fi
            '''
        ],
        'timeout': 20,
        'component': 'keycloak'
    })
    
    return tests
