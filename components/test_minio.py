# test_minio.py - Comprehensive MinIO Service Validation Script

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
    """Get MinIO host from env"""
    return os.getenv("MINIO_HOST", os.getenv("MINIO_MINIO_HOST", "minio.minio.svc.cluster.local"))


def get_minio_port() -> str:
    """Get MinIO port from env"""
    return os.getenv("MINIO_PORT", os.getenv("MINIO_MINIO_PORT", "9000"))


def get_minio_credentials() -> Tuple[str, str]:
    """Get MinIO access and secret keys"""
    access_key = os.getenv("MINIO_ACCESS_KEY", os.getenv("MINIO_MINIO_ACCESS_KEY", "minioadmin"))
    secret_key = os.getenv("MINIO_SECRET_KEY", os.getenv("MINIO_MINIO_SECRET_KEY", "minioadmin"))
    return access_key, secret_key


def parse_buckets_from_env() -> List[Dict]:
    """Parse MINIO_BUCKETS environment variable
    Format: bucket1:user1:pass1:pass2;bucket2:user2:pass3:pass4
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
                buckets.append(bucket_info)
    
    return buckets


def get_minio_pod() -> Optional[str]:
    """Dynamically find the first MinIO pod"""
    namespace = get_minio_namespace()
    
    # Try to find MinIO pods using common labels
    labels = [
        "app=minio",
        "stacktic.io/app=minio",
        "release=minio"
    ]
    
    for label in labels:
        cmd = f"kubectl get pods -n {namespace} -l {label} --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
        result = run_command(cmd, timeout=5)
        
        if result["exit_code"] == 0 and result["stdout"]:
            return result["stdout"].strip()
    
    # Fallback: look for any pod with "minio" in the name
    cmd = f"kubectl get pods -n {namespace} --no-headers 2>/dev/null | grep -i minio | head -1 | awk '{{print $1}}'"
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
    
    # Setup mc alias
    cmd = f"kubectl exec -n {namespace} {pod} -- mc alias set myminio http://{host}:{port} {access_key} {secret_key} 2>&1"
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
            "output": f"No MinIO pods found in namespace {namespace}",
            "severity": "CRITICAL"
        }]
    
    results = []
    
    # Setup mc alias first
    setup_result = setup_mc_alias(pod)
    if not setup_result["status"]:
        return [setup_result]
    
    # Test basic connectivity with mc admin info
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin info myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        # Parse server info
        lines = result["stdout"].split("\n")
        server_info = []
        for line in lines[:5]:  # First 5 lines of info
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
    
    # Check MinIO pods
    cmd = f"kubectl get pods -n {namespace} -l app=minio --no-headers 2>/dev/null"
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
        
        results.append({
            "name": "minio_pod_health",
            "status": running_pods == total_pods,
            "output": output.strip(),
            "severity": "CRITICAL" if running_pods != total_pods else "INFO"
        })
    else:
        results.append({
            "name": "minio_pod_health",
            "status": False,
            "output": f"No MinIO pods found in namespace {namespace}",
            "severity": "CRITICAL"
        })
    
    # Check MinIO server health using mc admin
    pod = get_minio_pod()
    if pod:
        setup_mc_alias(pod)
        
        # Check service health
        cmd = f"kubectl exec -n {namespace} {pod} -- mc admin service status myminio 2>&1"
        result = run_command(cmd, timeout=10)
        
        if result["exit_code"] == 0:
            output = "MinIO service status: Online"
            status = True
        else:
            output = "MinIO service status: Offline or Degraded"
            status = False
        
        results.append({
            "name": "minio_service_health",
            "status": status,
            "output": output,
            "severity": "CRITICAL" if not status else "INFO"
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
            "output": f"No MinIO pod available",
            "severity": "CRITICAL"
        }]
    
    # Setup mc alias
    setup_mc_alias(pod)
    
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
    
    # Test each configured bucket
    for bucket_config in configured_buckets:
        bucket_name = bucket_config["name"]
        
        # Check if bucket exists
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
                "output": f"Bucket '{bucket_name}' not found",
                "severity": "CRITICAL"
            })
    
    # Report on unconfigured buckets
    unconfigured = [b for b in existing_buckets if b not in [c["name"] for c in configured_buckets]]
    if unconfigured:
        results.append({
            "name": "minio_unconfigured_buckets",
            "status": True,
            "output": f"Additional buckets found: {', '.join(unconfigured)}",
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
    
    # Write test - create a temporary file and upload
    write_cmd = f"""kubectl exec -n {namespace} {pod} -- sh -c "echo '{test_content}' > /tmp/{test_file} && mc cp /tmp/{test_file} myminio/{bucket}/ && rm /tmp/{test_file}" 2>&1"""
    write_result = run_command(write_cmd, timeout=15)
    
    if write_result["exit_code"] == 0:
        results.append({
            "name": f"minio_bucket_{bucket}_write",
            "status": True,
            "output": f"Successfully wrote test file to bucket '{bucket}'",
            "severity": "INFO"
        })
        
        # Read test - list and verify the file exists
        read_cmd = f"kubectl exec -n {namespace} {pod} -- mc ls myminio/{bucket}/{test_file} 2>&1"
        read_result = run_command(read_cmd, timeout=10)
        
        if read_result["exit_code"] == 0:
            results.append({
                "name": f"minio_bucket_{bucket}_read",
                "status": True,
                "output": f"Successfully verified file in bucket '{bucket}'",
                "severity": "INFO"
            })
        else:
            results.append({
                "name": f"minio_bucket_{bucket}_read",
                "status": False,
                "output": f"Failed to read from bucket '{bucket}'",
                "severity": "WARNING"
            })
        
        # Cleanup - remove test file
        cleanup_cmd = f"kubectl exec -n {namespace} {pod} -- mc rm myminio/{bucket}/{test_file} 2>&1"
        run_command(cleanup_cmd, timeout=10)
        
    else:
        results.append({
            "name": f"minio_bucket_{bucket}_write",
            "status": False,
            "output": f"Failed to write to bucket '{bucket}': {write_result['stderr']}",
            "severity": "CRITICAL"
        })
        results.append({
            "name": f"minio_bucket_{bucket}_read",
            "status": False,
            "output": f"Skipped read test due to write failure",
            "severity": "WARNING"
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
            "output": "No MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    setup_mc_alias(pod)
    
    # Get disk usage
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin info myminio --json 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        try:
            info = json.loads(result["stdout"])
            
            # Extract relevant statistics
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
            
            # Convert bytes to human readable
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
            
            results.append({
                "name": "minio_storage_stats",
                "status": True,
                "output": output,
                "severity": "INFO"
            })
            
        except (json.JSONDecodeError, KeyError) as e:
            # Fallback to basic df command
            cmd = f"kubectl exec -n {namespace} {pod} -- df -h /data 2>&1"
            df_result = run_command(cmd, timeout=10)
            
            if df_result["exit_code"] == 0:
                output = "Storage Statistics (filesystem):\n"
                lines = df_result["stdout"].split("\n")
                if len(lines) > 1:
                    # Parse df output
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
            else:
                results.append({
                    "name": "minio_storage_stats",
                    "status": False,
                    "output": "Failed to retrieve storage statistics",
                    "severity": "WARNING"
                })
    else:
        results.append({
            "name": "minio_storage_stats",
            "status": False,
            "output": "Failed to get MinIO statistics",
            "severity": "WARNING"
        })
    
    # Count buckets and objects
    cmd = f"kubectl exec -n {namespace} {pod} -- mc ls myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        bucket_count = len([l for l in result["stdout"].split("\n") if l.strip()])
        
        # Get total object count (sample from first few buckets)
        total_objects = 0
        buckets_checked = 0
        
        for line in result["stdout"].split("\n")[:5]:  # Check first 5 buckets
            if line.strip():
                bucket_name = line.split()[-1].rstrip("/")
                obj_cmd = f"kubectl exec -n {namespace} {pod} -- mc ls myminio/{bucket_name} --recursive --summarize 2>&1 | grep 'Total Objects:' | awk '{{print $3}}'"
                obj_result = run_command(obj_cmd, timeout=5)
                
                if obj_result["exit_code"] == 0 and obj_result["stdout"].isdigit():
                    total_objects += int(obj_result["stdout"])
                    buckets_checked += 1
        
        output = f"Bucket Statistics:\n"
        output += f"  Total Buckets: {bucket_count}\n"
        if buckets_checked > 0:
            output += f"  Sample Objects: {total_objects} (from {buckets_checked} buckets)"
        
        results.append({
            "name": "minio_bucket_stats",
            "status": True,
            "output": output,
            "severity": "INFO"
        })
    
    return results


def test_minio_policies() -> List[Dict]:
    """Test MinIO policies and access controls"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    
    if not pod:
        return [{
            "name": "minio_policies",
            "status": False,
            "output": "No MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    setup_mc_alias(pod)
    
    # List users
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin user list myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        users = []
        lines = result["stdout"].split("\n")
        for line in lines:
            if "enabled" in line.lower() or "disabled" in line.lower():
                user_parts = line.split()
                if user_parts:
                    users.append(user_parts[0])
        
        output = f"Users: {len(users)} configured\n"
        if users:
            output += f"  Users: {', '.join(users[:5])}"  # Show first 5 users
            if len(users) > 5:
                output += f" (+{len(users)-5} more)"
        
        results.append({
            "name": "minio_users",
            "status": True,
            "output": output,
            "severity": "INFO"
        })
    
    # List policies
    cmd = f"kubectl exec -n {namespace} {pod} -- mc admin policy list myminio 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        policies = []
        lines = result["stdout"].split("\n")
        for line in lines:
            if line.strip() and not line.startswith("Policy"):
                policies.append(line.strip())
        
        output = f"Policies: {len(policies)} configured\n"
        if policies:
            output += f"  Policies: {', '.join(policies[:5])}"  # Show first 5 policies
            if len(policies) > 5:
                output += f" (+{len(policies)-5} more)"
        
        results.append({
            "name": "minio_policies",
            "status": True,
            "output": output,
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
            "output": "No MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    
    # Check logs for errors in last 100 lines
    cmd = f"kubectl logs -n {namespace} {pod} --tail=100 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        error_count = 0
        warning_count = 0
        fatal_count = 0
        
        lines = result["stdout"].split("\n")
        for line in lines:
            line_lower = line.lower()
            if "error" in line_lower or "err" in line_lower:
                error_count += 1
            if "warning" in line_lower or "warn" in line_lower:
                warning_count += 1
            if "fatal" in line_lower or "panic" in line_lower:
                fatal_count += 1
        
        if fatal_count > 0:
            status = False
            severity = "CRITICAL"
            output = f"Logs contain {fatal_count} FATAL errors!"
        elif error_count > 10:  # Threshold for concerning number of errors
            status = False
            severity = "WARNING"
            output = f"Logs contain {error_count} errors, {warning_count} warnings"
        else:
            status = True
            severity = "INFO"
            output = f"Logs healthy: {error_count} errors, {warning_count} warnings in last 100 lines"
        
        results.append({
            "name": "minio_log_health",
            "status": status,
            "output": output,
            "severity": severity
        })
        
        # Show last error if any
        if error_count > 0:
            for line in reversed(lines):
                if "error" in line.lower() or "err" in line.lower():
                    results.append({
                        "name": "minio_last_error",
                        "status": False,
                        "output": f"Last error: {line[:200]}",  # Truncate long lines
                        "severity": "WARNING"
                    })
                    break
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
    
    # Test network connectivity from a pod
    pod = get_minio_pod()
    if pod:
        # Test internal connectivity
        cmd = f"kubectl exec -n {namespace} {pod} -- curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{port}/minio/health/live 2>&1"
        result = run_command(cmd, timeout=10)
        
        if result["exit_code"] == 0 and result["stdout"] == "200":
            results.append({
                "name": "minio_health_endpoint",
                "status": True,
                "output": f"Health endpoint responding (HTTP 200) at {host}:{port}",
                "severity": "INFO"
            })
        else:
            results.append({
                "name": "minio_health_endpoint",
                "status": False,
                "output": f"Health endpoint not responding at {host}:{port}",
                "severity": "CRITICAL"
            })
    
    return results


def test_minio_performance() -> List[Dict]:
    """Basic performance test for MinIO"""
    namespace = get_minio_namespace()
    pod = get_minio_pod()
    
    if not pod:
        return [{
            "name": "minio_performance",
            "status": False,
            "output": "No MinIO pod available",
            "severity": "WARNING"
        }]
    
    results = []
    setup_mc_alias(pod)
    
    # Create a test bucket for performance testing
    test_bucket = f"perftest-{uuid.uuid4().hex[:8]}"
    
    # Create bucket
    cmd = f"kubectl exec -n {namespace} {pod} -- mc mb myminio/{test_bucket} 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0:
        # Perform a simple speed test with small file
        start_time = time.time()
        
        # Create and upload a 1MB test file
        test_cmd = f"""kubectl exec -n {namespace} {pod} -- sh -c "dd if=/dev/zero of=/tmp/testfile bs=1M count=1 2>/dev/null && mc cp /tmp/testfile myminio/{test_bucket}/ && rm /tmp/testfile" 2>&1"""
        test_result = run_command(test_cmd, timeout=30)
        
        upload_time = time.time() - start_time
        
        if test_result["exit_code"] == 0:
            output = f"Performance Test:\n"
            output += f"  1MB Upload: {upload_time:.2f}s\n"
            output += f"  Throughput: {1/upload_time:.2f} MB/s"
            status = True
            severity = "INFO"
            
            if upload_time > 5:
                status = False
                severity = "WARNING"
                output += "\n  WARNING: Slow upload detected"
        else:
            output = "Performance test failed"
            status = False
            severity = "WARNING"
        
        # Cleanup test bucket
        cleanup_cmd = f"kubectl exec -n {namespace} {pod} -- mc rb --force myminio/{test_bucket} 2>&1"
        run_command(cleanup_cmd, timeout=10)
        
        results.append({
            "name": "minio_performance",
            "status": status,
            "output": output,
            "severity": severity
        })
    else:
        results.append({
            "name": "minio_performance",
            "status": False,
            "output": "Could not create test bucket for performance testing",
            "severity": "WARNING"
        })
    
    return results


# Main execution
if __name__ == "__main__":
    all_results = []
    
    namespace = get_minio_namespace()
    host = get_minio_host()
    port = get_minio_port()
    
    print(f"Using MinIO configuration:")
    print(f"  Namespace: {namespace}")
    print(f"  Host: {host}")
    print(f"  Port: {port}\n")
    
    # Parse configured buckets
    configured_buckets = parse_buckets_from_env()
    if configured_buckets:
        print(f"Configured buckets: {', '.join([b['name'] for b in configured_buckets])}\n")
    
    # Run all tests
    print("Running MinIO validation tests...\n")
    
    all_results.extend(test_minio_connectivity())
    all_results.extend(test_minio_cluster_health())
    all_results.extend(test_minio_buckets())
    all_results.extend(test_minio_statistics())
    all_results.extend(test_minio_policies())
    all_results.extend(test_minio_network())
    all_results.extend(test_minio_recent_logs())
    all_results.extend(test_minio_performance())
    
    # Print clean results
    print("\n" + "="*60)
    print("MINIO TEST RESULTS")
    print("="*60 + "\n")
    
    # Group results by category
    categories = {
        "connectivity": [],
        "health": [],
        "bucket": [],
        "stats": [],
        "policy": [],
        "network": [],
        "logs": [],
        "performance": []
    }
    
    for result in all_results:
        name = result["name"]
        if "connectivity" in name:
            categories["connectivity"].append(result)
        elif "health" in name or "pod" in name or "service" in name:
            categories["health"].append(result)
        elif "bucket" in name:
            categories["bucket"].append(result)
        elif "stats" in name or "statistics" in name:
            categories["stats"].append(result)
        elif "policy" in name or "users" in name or "policies" in name:
            categories["policy"].append(result)
        elif "network" in name or "endpoint" in name:
            categories["network"].append(result)
        elif "log" in name:
            categories["logs"].append(result)
        elif "performance" in name:
            categories["performance"].append(result)
    
    # Print categorized results
    for category, tests in categories.items():
        if tests:
            print(f"\n{category.upper()} TESTS:")
            print("-" * 40)
            for result in tests:
                status_icon = "✓" if result["status"] else "✗"
                status_text = "PASS" if result["status"] else "FAIL"
                severity_color = {
                    "CRITICAL": "❌",
                    "WARNING": "⚠️",
                    "INFO": "ℹ️"
                }.get(result.get("severity", "INFO"), "")
                
                print(f"{status_icon} {result['name']}: {status_text} {severity_color}")
                if result["output"]:
                    for line in result["output"].split("\n"):
                        print(f"    {line}")
    
    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"])
    failed = total - passed
    critical = sum(1 for r in all_results if r.get("severity") == "CRITICAL" and not r["status"])
    warnings = sum(1 for r in all_results if r.get("severity") == "WARNING" and not r["status"])
    
    print("\n" + "="*60)
    print(f"SUMMARY: {passed}/{total} tests passed")
    if failed > 0:
        print(f"  Failed: {failed} ({critical} critical, {warnings} warnings)")
    print("="*60)
    
    # Exit with appropriate code
    if critical > 0:
        exit(2)  # Critical failures
    elif failed > 0:
        exit(1)  # Non-critical failures
    else:
        exit(0)  # All tests passed
