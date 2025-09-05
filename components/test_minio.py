#!/usr/bin/env python3
"""
Comprehensive MinIO Service Validation Script - Production Ready
Supports multiple buckets, dynamic namespace, and environment-based configuration
"""

import os
import json
import subprocess
import time
import uuid
import tempfile
from typing import List, Dict, Optional, Tuple
from datetime import datetime

def run_command(command: str, env: Dict = None, timeout: int = 30) -> Dict:
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


def get_minio_namespace() -> str:
    """Get MinIO namespace from env or default"""
    return os.getenv("MINIO_NS", os.getenv("MINIO_NAMESPACE", "minio"))


def get_minio_host() -> str:
    """Get MinIO host from env - support multiple formats"""
    return os.getenv("MINIO_HOST", 
                     os.getenv("MINIO_MINIO_HOST", 
                              "minio.minio.svc.cluster.local"))


def get_minio_port() -> str:
    """Get MinIO port from env"""
    return os.getenv("MINIO_PORT", 
                     os.getenv("MINIO_MINIO_PORT", "9000"))


def get_minio_credentials() -> Tuple[str, str]:
    """Get MinIO access and secret keys - try multiple sources"""
    # First try environment variables
    access_key = os.getenv("MINIO_ACCESS_KEY", 
                           os.getenv("MINIO_MINIO_ACCESS_KEY"))
    secret_key = os.getenv("MINIO_SECRET_KEY", 
                           os.getenv("MINIO_MINIO_SECRET_KEY"))
    
    # If not in env, try to get from Kubernetes secret
    if not access_key or not secret_key:
        namespace = get_minio_namespace()
        
        # Try to get from minio-credentials secret
        cmd_access = f"kubectl get secret -n {namespace} minio-credentials -o jsonpath='{{.data.rootUser}}' 2>/dev/null | base64 -d"
        cmd_secret = f"kubectl get secret -n {namespace} minio-credentials -o jsonpath='{{.data.rootPassword}}' 2>/dev/null | base64 -d"
        
        result_access = run_command(cmd_access, timeout=5)
        result_secret = run_command(cmd_secret, timeout=5)
        
        if result_access["exit_code"] == 0 and result_access["stdout"]:
            access_key = result_access["stdout"]
        if result_secret["exit_code"] == 0 and result_secret["stdout"]:
            secret_key = result_secret["stdout"]
    
    # Default fallback
    return (access_key or "minioadmin", secret_key or "minioadmin")


def parse_buckets_from_env() -> List[Dict]:
    """
    Parse MINIO_BUCKETS environment variable
    Format: bucket1:user1:pass1:pass2;bucket2:user2:pass3:pass4
    Note: pass2 seems to be redundant in your setup, we'll use pass1
    """
    buckets_str = os.getenv("MINIO_BUCKETS", "")
    buckets = []
    
    if buckets_str:
        for bucket_config in buckets_str.split(";"):
            parts = bucket_config.split(":")
            if len(parts) >= 1:
                bucket_info = {
                    "name": parts[0].strip(),
                    "user": parts[1].strip() if len(parts) > 1 else None,
                    "password": parts[2].strip() if len(parts) > 2 else None
                }
                # Additional passwords might be for different purposes
                if len(parts) > 3:
                    bucket_info["alt_password"] = parts[3].strip()
                buckets.append(bucket_info)
    
    return buckets


def get_minio_pod() -> Optional[str]:
    """Dynamically find the first RUNNING MinIO pod (not job pods)"""
    namespace = get_minio_namespace()
    
    # First, try to find statefulset pods (minio-0, minio-1, etc.)
    cmd = f"kubectl get pods -n {namespace} -l app=minio --field-selector=status.phase=Running --no-headers 2>/dev/null | grep -E 'minio-[0-9]+' | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    # Fallback: find any running pod with minio label (excluding jobs)
    cmd = f"kubectl get pods -n {namespace} -l app=minio --field-selector=status.phase=Running --no-headers 2>/dev/null | grep -v job | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    return None


def setup_mc_alias(pod: str) -> Dict:
    """Setup MinIO client alias in the pod"""
    namespace = get_minio_namespace()
    host = get_minio_host()
    port = get_minio_port()
    access_key, secret_key = get_minio_credentials()
    
    # Check if mc is available in the pod
    cmd_check = f"kubectl exec -n {namespace} {pod} -- which mc 2>&1"
    result_check = run_command(cmd_check, timeout=5)
    
    if result_check["exit_code"] != 0:
        # mc not installed in pod, try to use localhost from within pod
        return {
            "name": "minio_mc_setup",
            "status": False,
            "output": "MinIO client (mc) not available in pod",
            "severity": "WARNING"
        }
    
    # Setup mc alias using localhost (more reliable from within pod)
    cmd = f"kubectl exec -n {namespace} {pod} -- mc alias set myminio http://localhost:{port} '{access_key}' '{secret_key}' --api S3v4 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        # Fallback to service hostname
        cmd = f"kubectl exec -n {namespace} {pod} -- mc alias set myminio http://{host}:{port} '{access_key}' '{secret_key}' --api S3v4 2>&1"
        result = run_command(cmd, timeout=10)
    
    return {
        "name": "minio_mc_setup",
        "status": result["exit_code"] == 0,
        "output": "MinIO client configured" if result["exit_code"] == 0 else f"Failed to configure mc: {result['stderr']}",
        "severity": "CRITICAL" if result["exit_code"] != 0 else "INFO"
    }


def test_minio_connectivity() -> List[Dict]:
    """Test MinIO server connectivity"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    
    if not pod:
        return [{
            "name": "minio_connectivity",
            "status": False,
            "output": f"No running MinIO pods found in namespace {namespace}",
            "severity": "CRITICAL"
        }]
    
    results = []
    
    # Setup mc alias first
    setup_result = setup_mc_alias(pod)
    if not setup_result["status"]:
        # If mc not available in pod, try direct HTTP health check
        host = get_minio_host()
        port = get_minio_port()
        
        cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}/minio/health/live 2>&1"
        result = run_command(cmd, timeout=10)
        
        if result["exit_code"] == 0 and result["stdout"] == "200":
            results.append({
                "name": "minio_connectivity",
                "status": True,
                "output": f"MinIO health endpoint responding (HTTP 200) - Pod: {pod}",
                "severity": "INFO"
            })
        else:
            results.append({
                "name": "minio_connectivity",
                "status": False,
                "output": f"MinIO not responding - Pod: {pod}",
                "severity": "CRITICAL"
            })
        return results
    
    # Test with mc admin info
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin info myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        lines = result["stdout"].split("\n")
        server_info = []
        for line in lines[:5]:
            if line.strip():
                server_info.append(line.strip())
        
        output = f"Using pod: {pod}\n"
        output += "Server Info:\n"
        for info in server_info:
            output += f"  {info}\n"
        
        results.append({
            "name": "minio_connectivity",
            "status": True,
            "output": output.strip(),
            "severity": "INFO"
        })
    else:
        results.append({
            "name": "minio_connectivity",
            "status": False,
            "output": f"Pod: {pod} - Connection failed: {result['stderr']}",
            "severity": "CRITICAL"
        })
    
    return results


def test_minio_cluster_health() -> List[Dict]:
    """Check MinIO cluster health and pod status"""
    namespace = get_minio_namespace()
    results = []
    
    # Check all MinIO pods (including pending ones)
    cmd = f"kubectl get pods -n {namespace} -l app=minio --no-headers 2>/dev/null | grep -E 'minio-[0-9]+'"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = result["stdout"].strip().split("\n")
        total_pods = len(lines)
        running_pods = 0
        pod_details = []
        
        for line in lines:
            if line:
                parts = line.split()
                pod_name = parts[0]
                ready = parts[1]
                status = parts[2]
                
                if "Running" in status and "/" in ready:
                    ready_containers, total_containers = ready.split("/")
                    if ready_containers == total_containers:
                        running_pods += 1
                
                pod_details.append(f"{pod_name} ({ready}, {status})")
        
        output = f"MinIO pods: {running_pods}/{total_pods} healthy\n"
        output += "  Pods:\n"
        for detail in pod_details:
            output += f"    - {detail}\n"
        
        # Warning if not all pods are running (could be normal in dev)
        severity = "WARNING" if running_pods < total_pods else "INFO"
        
        results.append({
            "name": "minio_pod_health",
            "status": running_pods > 0,  # At least one pod should be running
            "output": output.strip(),
            "severity": severity
        })
    else:
        results.append({
            "name": "minio_pod_health",
            "status": False,
            "output": f"No MinIO pods found in namespace {namespace}",
            "severity": "CRITICAL"
        })
    
    # Check MinIO service health if we have a running pod
    pod = get_minio_pod()
    if pod:
        setup_result = setup_mc_alias(pod)
        
        if setup_result["status"]:
            cmd = f"kubectl exec -n {namespace} {pod} -- mc admin service status myminio 2>&1"
            result = run_command(cmd, timeout=10)
            
            if result["exit_code"] == 0:
                output = "MinIO service status: Online"
                status = True
            else:
                output = "MinIO service status: Degraded or Limited"
                status = False
            
            results.append({
                "name": "minio_service_health",
                "status": status,
                "output": output,
                "severity": "WARNING" if not status else "INFO"
            })
    
    return results


def test_minio_buckets() -> List[Dict]:
    """Test all configured buckets"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    results = []
    
    if not pod:
        return [{
            "name": "minio_buckets",
            "status": False,
            "output": f"No running MinIO pod available",
            "severity": "CRITICAL"
        }]
    
    # Setup mc alias
    setup_result = setup_mc_alias(pod)
    
    if not setup_result["status"]:
        # Can't use mc, try to check via HTTP API
        return [{
            "name": "minio_buckets",
            "status": False,
            "output": "Cannot test buckets - mc not available",
            "severity": "WARNING"
        }]
    
    # Get configured buckets from environment
    configured_buckets = parse_buckets_from_env()
    
    # List existing buckets
    cmd = f"kubectl exec -n {namespace} {pod} -- mc ls myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    existing_buckets = []
    if result["exit_code"] == 0 and result["stdout"]:
        lines = result["stdout"].split("\n")
        for line in lines:
            if line.strip():
                # Parse bucket name from mc ls output
                parts = line.split()
                if len(parts) >= 1:
                    bucket_name = parts[-1].rstrip("/")
                    existing_buckets.append(bucket_name)
    
    # Report on existing buckets
    if existing_buckets:
        results.append({
            "name": "minio_buckets_found",
            "status": True,
            "output": f"Found {len(existing_buckets)} buckets: {', '.join(existing_buckets)}",
            "severity": "INFO"
        })
    
    # Test each configured bucket
    for bucket_config in configured_buckets:
        bucket_name = bucket_config["name"]
        
        if bucket_name in existing_buckets:
            results.append({
                "name": f"minio_bucket_{bucket_name}_exists",
                "status": True,
                "output": f"Bucket '{bucket_name}' exists",
                "severity": "INFO"
            })
            
            # Test bucket operations
            results.extend(test_bucket_operations(pod, bucket_name))
        else:
            results.append({
                "name": f"minio_bucket_{bucket_name}_exists",
                "status": False,
                "output": f"Bucket '{bucket_name}' not found (may need to run bucket creation jobs)",
                "severity": "WARNING"
            })
    
    # Report on unconfigured buckets
    if configured_buckets:
        configured_names = [c["name"] for c in configured_buckets]
        unconfigured = [b for b in existing_buckets if b not in configured_names]
        if unconfigured:
            results.append({
                "name": "minio_unconfigured_buckets",
                "status": True,
                "output": f"Additional buckets found (not in MINIO_BUCKETS): {', '.join(unconfigured)}",
                "severity": "INFO"
            })
    
    return results


def test_bucket_operations(pod: str, bucket: str) -> List[Dict]:
    """Test read/write operations on a specific bucket"""
    namespace = get_minio_namespace()
    results = []
    
    # Generate test file name
    test_file = f"test-{uuid.uuid4().hex[:8]}.txt"
    test_content = f"MinIO test at {datetime.now().isoformat()}"
    
    # Write test
    write_cmd = f"""kubectl exec -n {namespace} {pod} -- sh -c "echo '{test_content}' > /tmp/{test_file} && mc cp /tmp/{test_file} myminio/{bucket}/ 2>&1 && rm /tmp/{test_file}" """
    write_result = run_command(write_cmd, timeout=15)
    
    if write_result["exit_code"] == 0:
        results.append({
            "name": f"minio_bucket_{bucket}_write",
            "status": True,
            "output": f"Write test passed for bucket '{bucket}'",
            "severity": "INFO"
        })
        
        # Read test
        read_cmd = f"kubectl exec -n {namespace} {pod} -- mc ls myminio/{bucket}/{test_file} 2>&1"
        read_result = run_command(read_cmd, timeout=10)
        
        if read_result["exit_code"] == 0:
            results.append({
                "name": f"minio_bucket_{bucket}_read",
                "status": True,
                "output": f"Read test passed for bucket '{bucket}'",
                "severity": "INFO"
            })
        else:
            results.append({
                "name": f"minio_bucket_{bucket}_read",
                "status": False,
                "output": f"Read test failed for bucket '{bucket}'",
                "severity": "WARNING"
            })
        
        # Cleanup
        cleanup_cmd = f"kubectl exec -n {namespace} {pod} -- mc rm myminio/{bucket}/{test_file} 2>&1"
        run_command(cleanup_cmd, timeout=10)
        
    else:
        # Check if it's a permission issue
        if "Access Denied" in write_result["stderr"] or "access denied" in write_result["stderr"].lower():
            results.append({
                "name": f"minio_bucket_{bucket}_write",
                "status": False,
                "output": f"Access denied for bucket '{bucket}' (check permissions)",
                "severity": "WARNING"
            })
        else:
            results.append({
                "name": f"minio_bucket_{bucket}_write",
                "status": False,
                "output": f"Write failed for bucket '{bucket}': {write_result['stderr'][:100]}",
                "severity": "WARNING"
            })
    
    return results


def test_minio_bucket_users() -> List[Dict]:
    """Test MinIO bucket-specific users from environment configuration"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    
    if not pod:
        return [{
            "name": "minio_bucket_users",
            "status": False,
            "output": "No running MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    setup_result = setup_mc_alias(pod)
    
    if not setup_result["status"]:
        return [{
            "name": "minio_bucket_users",
            "status": False,
            "output": "Cannot test users - mc not available",
            "severity": "WARNING"
        }]
    
    # Get configured buckets with users
    configured_buckets = parse_buckets_from_env()
    
    # List all users
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin user list myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    existing_users = []
    if result["exit_code"] == 0:
        lines = result["stdout"].split("\n")
        for line in lines:
            if "enabled" in line.lower() or "disabled" in line.lower():
                user_parts = line.split()
                if user_parts:
                    existing_users.append(user_parts[0])
    
    # Check each bucket's user
    users_found = 0
    users_expected = 0
    
    for bucket_config in configured_buckets:
        if bucket_config.get("user"):
            users_expected += 1
            user = bucket_config["user"]
            
            if user in existing_users:
                users_found += 1
                results.append({
                    "name": f"minio_user_{user}",
                    "status": True,
                    "output": f"User '{user}' exists for bucket '{bucket_config['name']}'",
                    "severity": "INFO"
                })
            else:
                results.append({
                    "name": f"minio_user_{user}",
                    "status": False,
                    "output": f"User '{user}' not found for bucket '{bucket_config['name']}'",
                    "severity": "WARNING"
                })
    
    # Summary
    if users_expected > 0:
        results.append({
            "name": "minio_bucket_users_summary",
            "status": users_found == users_expected,
            "output": f"Bucket users: {users_found}/{users_expected} configured",
            "severity": "INFO" if users_found == users_expected else "WARNING"
        })
    else:
        results.append({
            "name": "minio_bucket_users_summary",
            "status": True,
            "output": "No bucket-specific users configured in MINIO_BUCKETS",
            "severity": "INFO"
        })
    
    return results


def test_minio_statistics() -> List[Dict]:
    """Get MinIO storage statistics"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    
    if not pod:
        return [{
            "name": "minio_statistics",
            "status": False,
            "output": "No running MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    setup_result = setup_mc_alias(pod)
    
    if not setup_result["status"]:
        # Try basic df command as fallback
        cmd = f"kubectl exec -n {namespace} {pod} -- df -h /data 2>&1"
        df_result = run_command(cmd, timeout=10)
        
        if df_result["exit_code"] == 0:
            lines = df_result["stdout"].split("\n")
            if len(lines) > 1:
                output = "Storage Statistics (filesystem):\n"
                data_line = lines[1].split()
                if len(data_line) >= 5:
                    output += f"  Total: {data_line[1]}\n"
                    output += f"  Used: {data_line[2]} ({data_line[4]})\n"
                    output += f"  Available: {data_line[3]}"
                
                results.append({
                    "name": "minio_storage_stats",
                    "status": True,
                    "output": output,
                    "severity": "INFO"
                })
        return results
    
    # Get disk usage via mc
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin info myminio --json 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        try:
            info = json.loads(result["stdout"])
            
            servers = info.get("servers", [])
            total_disks = 0
            online_disks = 0
            total_space = 0
            used_space = 0
            
            for server in servers:
                disks = server.get("disks", [])
                for disk in disks:
                    total_disks += 1
                    if disk.get("state", "") == "ok":
                        online_disks += 1
                    total_space += disk.get("totalspace", 0)
                    used_space += disk.get("usedspace", 0)
            
            def bytes_to_human(bytes_val):
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if bytes_val < 1024.0:
                        return f"{bytes_val:.2f} {unit}"
                    bytes_val /= 1024.0
                return f"{bytes_val:.2f} PB"
            
            usage_percent = (used_space / total_space * 100) if total_space > 0 else 0
            
            output = f"Storage Statistics:\n"
            output += f"  Disks: {online_disks}/{total_disks} online\n"
            output += f"  Total Space: {bytes_to_human(total_space)}\n"
            output += f"  Used Space: {bytes_to_human(used_space)} ({usage_percent:.1f}%)\n"
            output += f"  Free Space: {bytes_to_human(total_space - used_space)}"
            
            # Add warning if usage is high
            severity = "WARNING" if usage_percent > 80 else "INFO"
            
            results.append({
                "name": "minio_storage_stats",
                "status": True,
                "output": output,
                "severity": severity
            })
            
        except (json.JSONDecodeError, KeyError):
            # Fallback to non-JSON output
            cmd = f"kubectl exec -n {namespace} {pod} -- mc admin info myminio 2>&1"
            result = run_command(cmd, timeout=10)
            
            if result["exit_code"] == 0:
                lines = result["stdout"].split("\n")[:10]
                output = "Storage Info:\n"
                for line in lines:
                    if line.strip():
                        output += f"  {line.strip()}\n"
                
                results.append({
                    "name": "minio_storage_stats",
                    "status": True,
                    "output": output.strip(),
                    "severity": "INFO"
                })
    
    return results


def test_minio_recent_logs() -> List[Dict]:
    """Check recent MinIO logs for errors"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    
    if not pod:
        return [{
            "name": "minio_logs",
            "status": False,
            "output": "No running MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    
    # Check logs for errors in last 50 lines
    cmd = f"kubectl logs -n {namespace} {pod} --tail=50 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        error_count = 0
        warning_count = 0
        fatal_count = 0
        
        lines = result["stdout"].split("\n")
        for line in lines:
            line_lower = line.lower()
            if "error" in line_lower or "err" in line_lower:
                # Ignore common non-critical errors
                if "no such object" not in line_lower and "key does not exist" not in line_lower:
                    error_count += 1
            if "warning" in line_lower or "warn" in line_lower:
                warning_count += 1
            if "fatal" in line_lower or "panic" in line_lower:
                fatal_count += 1
        
        if fatal_count > 0:
            status = False
            severity = "CRITICAL"
            output = f"CRITICAL: {fatal_count} fatal errors in logs!"
        elif error_count > 5:
            status = False
            severity = "WARNING"
            output = f"Logs show {error_count} errors, {warning_count} warnings"
        else:
            status = True
            severity = "INFO"
            output = f"Logs healthy: {error_count} errors, {warning_count} warnings in last 50 lines"
        
        results.append({
            "name": "minio_log_health",
            "status": status,
            "output": output,
            "severity": severity
        })
    else:
        results.append({
            "name": "minio_logs",
            "status": False,
            "output": "Failed to retrieve logs",
            "severity": "WARNING"
        })
    
    return results


def test_minio_network() -> List[Dict]:
    """Test MinIO network connectivity and services"""
    namespace = get_minio_namespace()
    host = get_minio_host()
    port = get_minio_port()
    results = []
    
    # Check if MinIO service exists
    cmd = f"kubectl get svc -n {namespace} minio --no-headers 2>&1"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0:
        parts = result["stdout"].split()
        if len(parts) >= 5:
            svc_type = parts[1]
            cluster_ip = parts[2]
            ports = parts[4]
            
            output = f"MinIO Service:\n"
            output += f"  Type: {svc_type}\n"
            output += f"  ClusterIP: {cluster_ip}\n"
            output += f"  Ports: {ports}"
            
            results.append({
                "name": "minio_service",
                "status": True,
                "output": output,
                "severity": "INFO"
            })
    else:
        results.append({
            "name": "minio_service",
            "status": False,
            "output": "MinIO service not found",
            "severity": "CRITICAL"
        })
    
    # Test health endpoint
    pod = get_minio_pod()
    if pod:
        cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}/minio/health/live 2>&1"
        result = run_command(cmd, timeout=10)
        
        if result["exit_code"] == 0 and result["stdout"] == "200":
            results.append({
                "name": "minio_health_endpoint",
                "status": True,
                "output": f"Health endpoint responding (HTTP 200)",
                "severity": "INFO"
            })
        else:
            results.append({
                "name": "minio_health_endpoint",
                "status": False,
                "output": f"Health endpoint not responding",
                "severity": "CRITICAL"
            })
    
    return results


# Main execution
if __name__ == "__main__":
    all_results = []
    
    # Display configuration
    namespace = get_minio_namespace()
    host = get_minio_host()
    port = get_minio_port()
    access_key, secret_key = get_minio_credentials()
    
    print("="*60)
    print("MINIO VALIDATION SCRIPT")
    print("="*60)
    print(f"\nConfiguration:")
    print(f"  Namespace: {namespace}")
    print(f"  Host: {host}")
    print(f"  Port: {port}")
    print(f"  Credentials: {'[CONFIGURED]' if access_key else '[NOT SET]'}")
    
    # Parse and display configured buckets
    configured_buckets = parse_buckets_from_env()
    if configured_buckets:
        print(f"\nExpected Buckets ({len(configured_buckets)}):")
        for bucket in configured_buckets:
            user_info = f" (user: {bucket['user']})" if bucket.get('user') else ""
            print(f"  - {bucket['name']}{user_info}")
    else:
        print("\nNo buckets configured in MINIO_BUCKETS environment variable")
    
    print("\n" + "-"*60)
    print("Running validation tests...")
    print("-"*60 + "\n")
    
    # Run all tests
    test_functions = [
        ("Connectivity", test_minio_connectivity),
        ("Cluster Health", test_minio_cluster_health),
        ("Buckets", test_minio_buckets),
        ("Bucket Users", test_minio_bucket_users),
        ("Storage Stats", test_minio_statistics),
        ("Network", test_minio_network),
        ("Log Analysis", test_minio_recent_logs)
    ]
    
    for test_name, test_func in test_functions:
        print(f"Running {test_name} tests...")
        try:
            results = test_func()
            all_results.extend(results)
        except Exception as e:
            all_results.append({
                "name": f"{test_name.lower()}_error",
                "status": False,
                "output": f"Test failed with error: {str(e)}",
                "severity": "WARNING"
            })
    
    # Print results
    print("\n" + "="*60)
    print("TEST RESULTS")
    print("="*60)
    
    # Group by severity
    critical_tests = []
    warning_tests = []
    passed_tests = []
    
    for result in all_results:
        if not result["status"]:
            if result.get("severity") == "CRITICAL":
                critical_tests.append(result)
            else:
                warning_tests.append(result)
        else:
            passed_tests.append(result)
    
    # Show critical issues first
    if critical_tests:
        print("\n❌ CRITICAL ISSUES:")
        print("-" * 40)
        for result in critical_tests:
            print(f"✗ {result['name']}")
            if result["output"]:
                for line in result["output"].split("\n"):
                    print(f"    {line}")
    
    # Show warnings
    if warning_tests:
        print("\n⚠️  WARNINGS:")
        print("-" * 40)
        for result in warning_tests:
            print(f"! {result['name']}")
            if result["output"]:
                for line in result["output"].split("\n"):
                    print(f"    {line}")
    
    # Show passed tests (summarized)
    if passed_tests:
        print("\n✅ PASSED TESTS:")
        print("-" * 40)
        for result in passed_tests:
            print(f"✓ {result['name']}")
            # Only show details for important passed tests
            if "Server Info" in result.get("output", "") or "Statistics" in result.get("output", ""):
                for line in result["output"].split("\n"):
                    print(f"    {line}")
    
    # Summary
    total = len(all_results)
    passed = len(passed_tests)
    warnings = len(warning_tests)
    critical = len(critical_tests)
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total tests: {total}")
    print(f"✅ Passed: {passed}")
    print(f"⚠️  Warnings: {warnings}")
    print(f"❌ Critical: {critical}")
    
    # Overall status
    if critical > 0:
        print("\n🔴 STATUS: CRITICAL ISSUES FOUND")
        exit_code = 2
    elif warnings > 0:
        print("\n🟡 STATUS: WARNINGS PRESENT (but functional)")
        exit_code = 1
    else:
        print("\n🟢 STATUS: ALL TESTS PASSED")
        exit_code = 0
    
    print("="*60)
    exit(exit_code)
