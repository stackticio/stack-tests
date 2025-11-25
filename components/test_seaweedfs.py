#!/usr/bin/env python3
"""
SeaweedFS S3 Service Health Check Script
Tests SeaweedFS S3-compatible object storage connectivity, buckets, and operations

ENV VARS:
  SEAWEEDFS_HOST (default: seaweedfs-s3.seaweedfs.svc.cluster.local)
  SEAWEEDFS_NS (default: seaweedfs)
  SEAWEEDFS_PORT (default: 8333)
  SEAWEEDFS_ACCESS_KEY (default: admin)
  SEAWEEDFS_SECRET_KEY (default: admin)
  SEAWEEDFS_BUCKETS (format: bucket1:user1:accesskey1:secretkey1;bucket2:user2:accesskey2:secretkey2)

Output: JSON array of test results to stdout
Each result: {
  name, description, status (bool), severity (info|warning|critical), output
}
"""

import os
import json
import subprocess
import sys
import time
import tempfile
import uuid
import shlex
from typing import List, Dict, Optional, Tuple


def run_command(command: str, env: Dict = None, timeout: int = 30) -> Dict:
    """Run shell command and return results"""
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


def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict:
    """Create standardized test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.upper()
    }


def get_seaweedfs_config() -> Dict[str, str]:
    """Get SeaweedFS configuration from environment"""
    return {
        "host": os.getenv("SEAWEEDFS_HOST", "seaweedfs-s3.seaweedfs.svc.cluster.local"),
        "namespace": os.getenv("SEAWEEDFS_NS", "seaweedfs"),
        "port": os.getenv("SEAWEEDFS_PORT", "8333"),
        "access_key": os.getenv("SEAWEEDFS_ACCESS_KEY", "Change_My_Key1"),
        "secret_key": os.getenv("SEAWEEDFS_SECRET_KEY", "Change_My_Secret!§1")
    }


def parse_buckets_from_env() -> List[Dict]:
    """Parse SEAWEEDFS_BUCKETS environment variable
    Format: bucket1:user1:accesskey1:secretkey1;bucket2:user2:accesskey2:secretkey2
    """
    buckets_str = os.getenv("SEAWEEDFS_BUCKETS", "")
    buckets = []

    if buckets_str:
        for bucket_config in buckets_str.split(";"):
            parts = bucket_config.split(":")
            if len(parts) >= 1:
                bucket_info = {
                    "name": parts[0].strip(),
                    "user": parts[1].strip() if len(parts) > 1 else None,
                    "access_key": parts[2].strip() if len(parts) > 2 else None,
                    "secret_key": parts[3].strip() if len(parts) > 3 else None
                }
                buckets.append(bucket_info)

    return buckets


def setup_mc_alias() -> Dict:
    """Setup MinIO client alias for SeaweedFS (S3-compatible)"""
    config = get_seaweedfs_config()

    # Setup mc alias
    cmd = f"mc alias set seaweedfs http://{config['host']}:{config['port']} {shlex.quote(config['access_key'])} {shlex.quote(config['secret_key'])} --api S3v4 2>&1"
    result = run_command(cmd, timeout=10)

    return create_test_result(
        "seaweedfs_mc_setup",
        "Setup MinIO client for SeaweedFS",
        result["exit_code"] == 0 or "already exists" in result["stdout"],
        "MinIO client configured for SeaweedFS" if result["exit_code"] == 0 or "already exists" in result["stdout"] else f"Failed: {result['stderr']}",
        "CRITICAL" if result["exit_code"] != 0 and "already exists" not in result["stdout"] else "INFO"
    )


def test_seaweedfs_connectivity() -> List[Dict]:
    """Test SeaweedFS S3 API connectivity"""
    results = []
    config = get_seaweedfs_config()

    # Setup mc alias first
    setup_result = setup_mc_alias()
    results.append(setup_result)

    if not setup_result["status"]:
        return results

    # Test admin info
    cmd = "mc admin info seaweedfs 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        results.append(create_test_result(
            "seaweedfs_admin_info",
            "Check SeaweedFS admin info",
            True,
            "SeaweedFS admin API is accessible",
            "INFO"
        ))
    else:
        # Admin API might not be available, try basic S3 API
        cmd = "mc ls seaweedfs 2>&1"
        list_result = run_command(cmd, timeout=10)

        results.append(create_test_result(
            "seaweedfs_s3_api",
            "Check SeaweedFS S3 API",
            list_result["exit_code"] == 0,
            "S3 API is accessible" if list_result["exit_code"] == 0 else f"S3 API failed: {list_result['stderr']}",
            "CRITICAL" if list_result["exit_code"] != 0 else "INFO"
        ))

    return results


def test_seaweedfs_buckets() -> List[Dict]:
    """Test SeaweedFS bucket operations"""
    results = []
    config = get_seaweedfs_config()
    buckets_config = parse_buckets_from_env()

    # List all buckets
    cmd = "mc ls seaweedfs 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] != 0:
        results.append(create_test_result(
            "seaweedfs_list_buckets",
            "List SeaweedFS buckets",
            False,
            f"Failed to list buckets: {result['stderr']}",
            "CRITICAL"
        ))
        return results

    existing_buckets = []
    for line in result["stdout"].split("\n"):
        if line.strip():
            # Parse bucket name from mc ls output
            parts = line.split()
            if len(parts) >= 5:
                bucket_name = parts[-1].strip("/")
                existing_buckets.append(bucket_name)

    results.append(create_test_result(
        "seaweedfs_list_buckets",
        "List SeaweedFS buckets",
        True,
        f"Found {len(existing_buckets)} buckets: {', '.join(existing_buckets) if existing_buckets else 'none'}",
        "INFO"
    ))

    # Test each configured bucket
    if buckets_config:
        for bucket_info in buckets_config:
            bucket_name = bucket_info["name"]

            # Check if bucket exists
            if bucket_name in existing_buckets:
                results.append(create_test_result(
                    f"seaweedfs_bucket_{bucket_name}",
                    f"Check bucket '{bucket_name}'",
                    True,
                    f"Bucket '{bucket_name}' exists",
                    "INFO"
                ))

                # Test read/write if we have credentials
                if bucket_info.get("access_key") and bucket_info.get("secret_key"):
                    # Setup alias with bucket-specific credentials
                    alias_name = f"seaweedfs_{bucket_name}"
                    cmd = f"mc alias set {alias_name} http://{config['host']}:{config['port']} {shlex.quote(bucket_info['access_key'])} {shlex.quote(bucket_info['secret_key'])} --api S3v4 2>&1"
                    alias_result = run_command(cmd, timeout=10)

                    if alias_result["exit_code"] == 0 or "already exists" in alias_result["stdout"]:
                        # Test write
                        test_file = f"/tmp/seaweedfs_test_{uuid.uuid4().hex[:8]}.txt"
                        test_content = f"SeaweedFS test at {time.time()}"

                        with open(test_file, 'w') as f:
                            f.write(test_content)

                        upload_cmd = f"mc cp {test_file} {alias_name}/{bucket_name}/test.txt 2>&1"
                        upload_result = run_command(upload_cmd, timeout=15)

                        if upload_result["exit_code"] == 0:
                            results.append(create_test_result(
                                f"seaweedfs_bucket_{bucket_name}_write",
                                f"Test write to bucket '{bucket_name}'",
                                True,
                                f"Successfully wrote to bucket '{bucket_name}'",
                                "INFO"
                            ))

                            # Cleanup
                            os.remove(test_file)
                            run_command(f"mc rm {alias_name}/{bucket_name}/test.txt 2>&1", timeout=10)
                        else:
                            results.append(create_test_result(
                                f"seaweedfs_bucket_{bucket_name}_write",
                                f"Test write to bucket '{bucket_name}'",
                                False,
                                f"Failed to write: {upload_result['stderr']}",
                                "WARNING"
                            ))
            else:
                results.append(create_test_result(
                    f"seaweedfs_bucket_{bucket_name}",
                    f"Check bucket '{bucket_name}'",
                    False,
                    f"Bucket '{bucket_name}' not found (configured but doesn't exist)",
                    "WARNING"
                ))

    return results


def test_seaweedfs_pods() -> List[Dict]:
    """Test SeaweedFS pod health"""
    results = []
    config = get_seaweedfs_config()
    namespace = config["namespace"]

    # Check master pods
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=seaweedfs,app.kubernetes.io/component=master -o json 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            running_pods = sum(1 for pod in pods if pod.get("status", {}).get("phase") == "Running")
            total_pods = len(pods)

            results.append(create_test_result(
                "seaweedfs_master_pods",
                "Check SeaweedFS master pods",
                running_pods == total_pods and total_pods > 0,
                f"Master pods: {running_pods}/{total_pods} running",
                "CRITICAL" if running_pods == 0 else "WARNING" if running_pods < total_pods else "INFO"
            ))
        except json.JSONDecodeError:
            results.append(create_test_result(
                "seaweedfs_master_pods",
                "Check SeaweedFS master pods",
                False,
                "Failed to parse master pods data",
                "WARNING"
            ))

    # Check volume pods
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=seaweedfs,app.kubernetes.io/component=volume -o json 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            running_pods = sum(1 for pod in pods if pod.get("status", {}).get("phase") == "Running")
            total_pods = len(pods)

            results.append(create_test_result(
                "seaweedfs_volume_pods",
                "Check SeaweedFS volume pods",
                running_pods == total_pods and total_pods > 0,
                f"Volume pods: {running_pods}/{total_pods} running",
                "CRITICAL" if running_pods == 0 else "WARNING" if running_pods < total_pods else "INFO"
            ))
        except json.JSONDecodeError:
            pass

    # Check filer pods
    cmd = f"kubectl get pods -n {namespace} -l app.kubernetes.io/name=seaweedfs,app.kubernetes.io/component=filer -o json 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        try:
            pods_data = json.loads(result["stdout"])
            pods = pods_data.get("items", [])

            running_pods = sum(1 for pod in pods if pod.get("status", {}).get("phase") == "Running")
            total_pods = len(pods)

            results.append(create_test_result(
                "seaweedfs_filer_pods",
                "Check SeaweedFS filer pods",
                running_pods == total_pods and total_pods > 0,
                f"Filer pods: {running_pods}/{total_pods} running",
                "CRITICAL" if running_pods == 0 else "WARNING" if running_pods < total_pods else "INFO"
            ))
        except json.JSONDecodeError:
            pass

    return results


def test_seaweedfs_services() -> List[Dict]:
    """Test SeaweedFS services"""
    results = []
    config = get_seaweedfs_config()
    namespace = config["namespace"]

    # Check S3 service
    cmd = f"kubectl get svc -n {namespace} -l app.kubernetes.io/name=seaweedfs -o json 2>&1"
    result = run_command(cmd, timeout=10)

    if result["exit_code"] == 0:
        try:
            svcs_data = json.loads(result["stdout"])
            services = svcs_data.get("items", [])

            s3_service_found = False
            master_service_found = False
            filer_service_found = False

            for svc in services:
                svc_name = svc["metadata"]["name"]
                if "s3" in svc_name:
                    s3_service_found = True
                if "master" in svc_name:
                    master_service_found = True
                if "filer" in svc_name:
                    filer_service_found = True

            results.append(create_test_result(
                "seaweedfs_s3_service",
                "Check SeaweedFS S3 service",
                s3_service_found,
                "S3 service found" if s3_service_found else "S3 service not found",
                "CRITICAL" if not s3_service_found else "INFO"
            ))

            results.append(create_test_result(
                "seaweedfs_services",
                "Check SeaweedFS services",
                master_service_found and filer_service_found,
                f"Services: S3={'✓' if s3_service_found else '✗'}, Master={'✓' if master_service_found else '✗'}, Filer={'✓' if filer_service_found else '✗'}",
                "WARNING" if not (master_service_found and filer_service_found) else "INFO"
            ))
        except json.JSONDecodeError:
            results.append(create_test_result(
                "seaweedfs_services",
                "Check SeaweedFS services",
                False,
                "Failed to parse services data",
                "WARNING"
            ))
    else:
        results.append(create_test_result(
            "seaweedfs_services",
            "Check SeaweedFS services",
            False,
            f"Failed to get services: {result['stderr']}",
            "CRITICAL"
        ))

    return results


def test_seaweedfs() -> List[Dict]:
    """Run all SeaweedFS health checks"""
    results = []

    # 1) Connectivity tests
    results.extend(test_seaweedfs_connectivity())

    # 2) Bucket tests
    results.extend(test_seaweedfs_buckets())

    # 3) Pod health tests
    results.extend(test_seaweedfs_pods())

    # 4) Service tests
    results.extend(test_seaweedfs_services())

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r["status"])
    critical = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
    warnings = sum(1 for r in results if not r["status"] and r["severity"] == "WARNING")

    results.append(create_test_result(
        "seaweedfs_summary",
        "Overall SeaweedFS health summary",
        critical == 0,
        f"{passed}/{total} checks passed | Critical: {critical} | Warnings: {warnings}",
        "CRITICAL" if critical > 0 else "WARNING" if warnings > 0 else "INFO"
    ))

    return results


def main():
    """Main entry point"""
    try:
        results = test_seaweedfs()

        # Output JSON to stdout
        print(json.dumps(results, indent=2))

        # Exit with appropriate code
        critical_failures = sum(1 for r in results if not r["status"] and r["severity"] == "CRITICAL")
        sys.exit(1 if critical_failures > 0 else 0)

    except Exception as e:
        error_result = [create_test_result(
            "test_execution_error",
            "Test execution failed",
            False,
            f"Unexpected error: {str(e)}",
            "CRITICAL"
        )]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
