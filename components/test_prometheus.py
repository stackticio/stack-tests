# test_prometheus.py - Fixed version
{% raw %}
#!/usr/bin/env python3
"""
Prometheus Health Check Script
Tests various aspects of Prometheus deployment and returns results in JSON format
No external dependencies required - uses only standard library and kubectl/curl
"""

import subprocess
import json
import sys
import time
from datetime import datetime

class PrometheusHealthChecker:
    def __init__(self, prometheus_namespace="prometheus"):
        self.namespace = prometheus_namespace
        self.test_results = []
        
    def run_command(self, command: str) -> tuple:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def create_test_result(self, name: str, description: str, passed: bool, 
                          output: str, severity: str = "info") -> dict:
        """Create a standardized test result"""
        return {
            "name": name,
            "description": description,
            "passed": passed,
            "output": output,
            "severity": severity  # critical, warning, info
        }
    
    def test_prometheus_pods(self) -> dict:
        """Test if all Prometheus pods are running"""
        name = "prometheus_pods_health"
        description = "Check if all Prometheus pods are in Running state"
        
        cmd = f"kubectl get pods -n {self.namespace} -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False, 
                f"Failed to get pods: {stderr}", "critical"
            )
        
        try:
            pods_data = json.loads(stdout)
            unhealthy_pods = []
            
            for pod in pods_data.get("items", []):
                pod_name = pod["metadata"]["name"]
                pod_status = pod["status"]["phase"]
                
                # Check if all containers are ready
                ready = all(
                    container.get("ready", False) 
                    for container in pod["status"].get("containerStatuses", [])
                )
                
                if pod_status != "Running" or not ready:
                    unhealthy_pods.append(f"{pod_name} (Status: {pod_status}, Ready: {ready})")
            
            if unhealthy_pods:
                return self.create_test_result(
                    name, description, False,
                    f"Unhealthy pods found: {', '.join(unhealthy_pods)}", "critical"
                )
            
            total_pods = len(pods_data.get("items", []))
            return self.create_test_result(
                name, description, True,
                f"All {total_pods} pods are healthy and running", "info"
            )
            
        except json.JSONDecodeError as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to parse pod data: {str(e)}", "critical"
            )
    
    def test_service_monitors(self) -> dict:
        """Test ServiceMonitor configurations"""
        name = "service_monitors_health"
        description = "Check if ServiceMonitors are properly configured and scraped"
        
        # Get all ServiceMonitors
        cmd = "kubectl get ServiceMonitor -A -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False,
                f"Failed to get ServiceMonitors: {stderr}", "warning"
            )
        
        try:
            sm_data = json.loads(stdout)
            total_monitors = len(sm_data.get("items", []))
            
            # Get ServiceMonitor details
            monitor_details = []
            for sm in sm_data.get("items", []):
                namespace = sm["metadata"]["namespace"]
                sm_name = sm["metadata"]["name"]
                monitor_details.append(f"{namespace}/{sm_name}")
            
            # Check if Prometheus is scraping targets using curl
            prometheus_pod_cmd = f"kubectl get pods -n {self.namespace} -l app.kubernetes.io/name=prometheus -o jsonpath='{{.items[0].metadata.name}}'"
            pod_name, _, _ = self.run_command(prometheus_pod_cmd)
            pod_name = pod_name.strip()
            
            if pod_name:
                targets_info = self.check_prometheus_targets_with_curl(pod_name)
                
                if targets_info:
                    unhealthy_targets = targets_info.get("unhealthy", [])
                    if unhealthy_targets:
                        return self.create_test_result(
                            name, description, False,
                            f"Found {len(unhealthy_targets)} unhealthy targets: {', '.join(unhealthy_targets[:5])}", 
                            "warning"
                        )
                    
                    return self.create_test_result(
                        name, description, True,
                        f"All {total_monitors} ServiceMonitors configured, {targets_info.get('total', 0)} targets being scraped",
                        "info"
                    )
            
            return self.create_test_result(
                name, description, True,
                f"Found {total_monitors} ServiceMonitors configured: {', '.join(monitor_details[:10])}",
                "info"
            )
            
        except json.JSONDecodeError as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to parse ServiceMonitor data: {str(e)}", "warning"
            )
    
    def check_prometheus_targets_with_curl(self, pod_name: str) -> dict:
        """Check Prometheus targets using kubectl exec and curl"""
        try:
            # Use kubectl exec to curl the Prometheus API from within the pod
            curl_cmd = f"kubectl exec -n {self.namespace} {pod_name} -c prometheus -- curl -s http://localhost:9090/api/v1/targets"
            stdout, stderr, returncode = self.run_command(curl_cmd)
            
            if returncode == 0 and stdout:
                targets_data = json.loads(stdout)
                
                unhealthy_targets = []
                total_targets = 0
                
                for target in targets_data.get("data", {}).get("activeTargets", []):
                    total_targets += 1
                    if target.get("health") != "up":
                        job_name = target.get("labels", {}).get("job", "unknown")
                        health_status = target.get("health", "unknown")
                        unhealthy_targets.append(f"{job_name} - {health_status}")
                
                return {
                    "total": total_targets,
                    "unhealthy": unhealthy_targets
                }
        except Exception as e:
            # If kubectl exec fails, try port-forward approach
            return self.check_targets_with_port_forward(pod_name)
        
        return None
    
    def check_targets_with_port_forward(self, pod_name: str) -> dict:
        """Alternative method using port-forward and curl"""
        try:
            # Start port-forward in background
            port_forward_cmd = f"kubectl port-forward -n {self.namespace} {pod_name} 9090:9090"
            port_forward_proc = subprocess.Popen(
                port_forward_cmd, shell=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            
            # Give it a moment to establish connection
            time.sleep(3)
            
            try:
                # Use curl to query Prometheus targets API
                curl_cmd = "curl -s http://localhost:9090/api/v1/targets"
                stdout, stderr, returncode = self.run_command(curl_cmd)
                
                if returncode == 0 and stdout:
                    targets_data = json.loads(stdout)
                    
                    unhealthy_targets = []
                    total_targets = 0
                    
                    for target in targets_data.get("data", {}).get("activeTargets", []):
                        total_targets += 1
                        if target.get("health") != "up":
                            job_name = target.get("labels", {}).get("job", "unknown")
                            health_status = target.get("health", "unknown")
                            unhealthy_targets.append(f"{job_name} - {health_status}")
                    
                    return {
                        "total": total_targets,
                        "unhealthy": unhealthy_targets
                    }
            except Exception:
                pass
            finally:
                # Kill port-forward process
                port_forward_proc.terminate()
                try:
                    port_forward_proc.wait(timeout=5)
                except:
                    port_forward_proc.kill()
                
        except Exception:
            pass
        
        return None
    
    def test_prometheus_operator(self) -> dict:
        """Test if Prometheus Operator is running"""
        name = "prometheus_operator_health"
        description = "Check if Prometheus Operator is running and healthy"
        
        cmd = f"kubectl get pods -n {self.namespace} -l app.kubernetes.io/name=kube-prometheus-stack-prometheus-operator -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False,
                f"Failed to get operator pod: {stderr}", "critical"
            )
        
        try:
            pods_data = json.loads(stdout)
            if not pods_data.get("items"):
                return self.create_test_result(
                    name, description, False,
                    "Prometheus Operator pod not found", "critical"
                )
            
            operator_pod = pods_data["items"][0]
            pod_status = operator_pod["status"]["phase"]
            pod_name = operator_pod["metadata"]["name"]
            
            if pod_status == "Running":
                # Check recent logs for errors
                log_cmd = f"kubectl logs -n {self.namespace} {pod_name} --tail=50 2>/dev/null | grep -i error | wc -l"
                error_count, _, _ = self.run_command(log_cmd)
                
                try:
                    error_count = int(error_count.strip())
                except:
                    error_count = 0
                
                if error_count > 10:
                    return self.create_test_result(
                        name, description, True,
                        f"Operator is running but found {error_count} errors in recent logs", "warning"
                    )
                
                return self.create_test_result(
                    name, description, True,
                    f"Prometheus Operator is running healthy (pod: {pod_name})", "info"
                )
            else:
                return self.create_test_result(
                    name, description, False,
                    f"Operator pod status: {pod_status}", "critical"
                )
                
        except Exception as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to check operator status: {str(e)}", "critical"
            )
    
    def test_alertmanager(self) -> dict:
        """Test if AlertManager is running and configured"""
        name = "alertmanager_health"
        description = "Check if AlertManager is running and accessible"
        
        cmd = f"kubectl get pods -n {self.namespace} -l app.kubernetes.io/name=alertmanager -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False,
                f"Failed to get AlertManager pod: {stderr}", "warning"
            )
        
        try:
            pods_data = json.loads(stdout)
            if not pods_data.get("items"):
                return self.create_test_result(
                    name, description, False,
                    "AlertManager pod not found", "warning"
                )
            
            am_pod = pods_data["items"][0]
            pod_status = am_pod["status"]["phase"]
            pod_name = am_pod["metadata"]["name"]
            
            if pod_status == "Running":
                # Check if AlertManager API is accessible
                api_check_cmd = f"kubectl exec -n {self.namespace} {pod_name} -c alertmanager -- curl -s http://localhost:9093/-/healthy"
                stdout, stderr, returncode = self.run_command(api_check_cmd)
                
                if returncode == 0:
                    return self.create_test_result(
                        name, description, True,
                        f"AlertManager is running and API is healthy (pod: {pod_name})", "info"
                    )
                else:
                    return self.create_test_result(
                        name, description, True,
                        f"AlertManager is running (pod: {pod_name})", "info"
                    )
            else:
                return self.create_test_result(
                    name, description, False,
                    f"AlertManager pod status: {pod_status}", "warning"
                )
                
        except Exception as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to check AlertManager: {str(e)}", "warning"
            )
    
    def test_node_exporters(self) -> dict:
        """Test if Node Exporters are running on all nodes"""
        name = "node_exporters_health"
        description = "Check if Node Exporters are running on all nodes"
        
        # Get number of nodes
        nodes_cmd = "kubectl get nodes --no-headers | wc -l"
        node_count, _, _ = self.run_command(nodes_cmd)
        
        try:
            node_count = int(node_count.strip())
        except:
            node_count = 0
        
        # Get node exporter pods
        cmd = f"kubectl get pods -n {self.namespace} -l app.kubernetes.io/name=prometheus-node-exporter -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False,
                f"Failed to get Node Exporter pods: {stderr}", "warning"
            )
        
        try:
            pods_data = json.loads(stdout)
            exporter_count = len(pods_data.get("items", []))
            
            unhealthy_exporters = []
            for pod in pods_data.get("items", []):
                if pod["status"]["phase"] != "Running":
                    unhealthy_exporters.append(pod["metadata"]["name"])
            
            if unhealthy_exporters:
                return self.create_test_result(
                    name, description, False,
                    f"Unhealthy node exporters: {', '.join(unhealthy_exporters)}", "warning"
                )
            
            if node_count > 0 and exporter_count < node_count:
                return self.create_test_result(
                    name, description, False,
                    f"Node exporter count ({exporter_count}) doesn't match node count ({node_count})", "warning"
                )
            
            return self.create_test_result(
                name, description, True,
                f"All {exporter_count} node exporters are running on {node_count} nodes", "info"
            )
            
        except Exception as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to check node exporters: {str(e)}", "warning"
            )
    
    def test_persistent_volumes(self) -> dict:
        """Test if Prometheus has persistent volumes attached"""
        name = "persistent_volumes_health"
        description = "Check if Prometheus has persistent volumes properly attached"
        
        cmd = f"kubectl get pvc -n {self.namespace} -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False,
                f"Failed to get PVCs: {stderr}", "warning"
            )
        
        try:
            pvc_data = json.loads(stdout)
            unbound_pvcs = []
            
            for pvc in pvc_data.get("items", []):
                pvc_name = pvc["metadata"]["name"]
                pvc_status = pvc["status"]["phase"]
                
                if pvc_status != "Bound":
                    unbound_pvcs.append(f"{pvc_name} ({pvc_status})")
            
            if unbound_pvcs:
                return self.create_test_result(
                    name, description, False,
                    f"Unbound PVCs found: {', '.join(unbound_pvcs)}", "critical"
                )
            
            total_pvcs = len(pvc_data.get("items", []))
            if total_pvcs == 0:
                return self.create_test_result(
                    name, description, False,
                    "No PVCs found - Prometheus might not have persistent storage", "warning"
                )
            
            return self.create_test_result(
                name, description, True,
                f"All {total_pvcs} PVCs are bound and healthy", "info"
            )
            
        except Exception as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to check PVCs: {str(e)}", "warning"
            )
    
    def test_kube_state_metrics(self) -> dict:
        """Test if kube-state-metrics is running"""
        name = "kube_state_metrics_health"
        description = "Check if kube-state-metrics is running and accessible"
        
        cmd = f"kubectl get pods -n {self.namespace} -l app.kubernetes.io/name=kube-state-metrics -o json"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode != 0:
            return self.create_test_result(
                name, description, False,
                f"Failed to get kube-state-metrics pod: {stderr}", "warning"
            )
        
        try:
            pods_data = json.loads(stdout)
            if not pods_data.get("items"):
                return self.create_test_result(
                    name, description, False,
                    "kube-state-metrics pod not found", "warning"
                )
            
            ksm_pod = pods_data["items"][0]
            pod_status = ksm_pod["status"]["phase"]
            pod_name = ksm_pod["metadata"]["name"]
            
            if pod_status == "Running":
                # Check if metrics endpoint is accessible
                metrics_check_cmd = f"kubectl exec -n {self.namespace} {pod_name} -- curl -s http://localhost:8080/metrics | head -n 1"
                stdout, stderr, returncode = self.run_command(metrics_check_cmd)
                
                if returncode == 0 and stdout:
                    return self.create_test_result(
                        name, description, True,
                        f"kube-state-metrics is running and serving metrics (pod: {pod_name})", "info"
                    )
                else:
                    return self.create_test_result(
                        name, description, True,
                        f"kube-state-metrics is running (pod: {pod_name})", "info"
                    )
            else:
                return self.create_test_result(
                    name, description, False,
                    f"kube-state-metrics pod status: {pod_status}", "warning"
                )
                
        except Exception as e:
            return self.create_test_result(
                name, description, False,
                f"Failed to check kube-state-metrics: {str(e)}", "warning"
            )
    
    def run_all_tests(self) -> list:
        """Run all health check tests"""
        print("Starting Prometheus health checks...")
        print(f"Target namespace: {self.namespace}")
        print("-" * 50)
        
        # Run all test methods
        test_methods = [
            self.test_prometheus_pods,
            self.test_prometheus_operator,
            self.test_service_monitors,
            self.test_alertmanager,
            self.test_node_exporters,
            self.test_kube_state_metrics,
            self.test_persistent_volumes
        ]
        
        results = []
        for test_method in test_methods:
            print(f"Running {test_method.__name__}...")
            result = test_method()
            results.append(result)
            
            # Print summary
            status = "✅ PASSED" if result["passed"] else "❌ FAILED"
            print(f"  {status}: {result['name']}")
            print(f"  Output: {result['output'][:100]}...")
        
        return results

def main():
    """Main execution function"""
    # You can customize the namespace if needed
    namespace = "prometheus"
    
    if len(sys.argv) > 1:
        namespace = sys.argv[1]
    
    checker = PrometheusHealthChecker(namespace)
    results = checker.run_all_tests()
    
    # Calculate summary
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r["passed"])
    failed_tests = total_tests - passed_tests
    
    # Print summary
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    
    # Determine overall health
    if failed_tests == 0:
        print("\n✅ All tests passed! Prometheus is healthy.")
    else:
        critical_failures = sum(1 for r in results if not r["passed"] and r["severity"] == "critical")
        warning_failures = sum(1 for r in results if not r["passed"] and r["severity"] == "warning")
        print(f"\n⚠️  {failed_tests} test(s) failed:")
        print(f"  - Critical: {critical_failures}")
        print(f"  - Warning: {warning_failures}")
    
    # Output JSON results
    print("\n" + "="*50)
    print("JSON OUTPUT")
    print("="*50)
    print(json.dumps(results, indent=2))
    
    # Return results as JSON if called as module
    if __name__ != "__main__":
        return results
    
    # Exit with appropriate code
    sys.exit(0 if failed_tests == 0 else 1)

if __name__ == "__main__":
    main()
{% endraw %}
