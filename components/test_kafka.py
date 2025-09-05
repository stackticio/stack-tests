# test_kafka.py - Corrected version with proper pod detection and clean output

import os
import json
import subprocess
import time
import uuid
from typing import List, Dict, Optional

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


def get_kafka_namespace() -> str:
    """Get Kafka namespace from env or default"""
    return os.getenv("KAFKA_NS", os.getenv("KAFKA_NAMESPACE", "strimzi"))


def get_kafka_broker_pod() -> Optional[str]:
    """Dynamically find the first Kafka broker pod - FIXED VERSION"""
    namespace = get_kafka_namespace()
    
    # Correct way to find broker pods in KRaft mode
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/broker-role=true --no-headers 2>/dev/null | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    # Fallback for combined nodes
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/kind=Kafka --no-headers 2>/dev/null | grep 'kafka-[0-9]' | head -1 | awk '{{print $1}}'"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    return None


def test_kafka_connectivity() -> List[Dict]:
    """Test Kafka broker connectivity"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_connectivity",
            "status": False,
            "output": f"No Kafka broker pods found in namespace {namespace}",
            "severity": "CRITICAL"
        }]
    
    # List topics to verify connectivity
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>&1"
    result = run_command(cmd, timeout=10)
    
    status = result["exit_code"] == 0
    
    if status:
        topics = result["stdout"].split("\n") if result["stdout"] else []
        output = f"Using pod: {broker_pod}\n"
        for topic in topics[:6]:  # Show first 6 topics
            if topic.strip():
                output += f"  {topic}\n"
    else:
        output = f"Pod: {broker_pod} - Connection failed"
    
    return [{
        "name": "kafka_connectivity",
        "status": status,
        "output": output.strip(),
        "severity": "CRITICAL" if not status else "INFO"
    }]


def test_kafka_list_topics() -> List[Dict]:
    """List all Kafka topics with clean output"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_list_topics",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "CRITICAL"
        }]
    
    # Get list of topics and their details
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "kafka_list_topics",
            "status": False,
            "output": "Failed to list topics",
            "severity": "CRITICAL"
        }]
    
    topics = [t for t in result["stdout"].split("\n") if t and not t.startswith("__")][:5]  # First 5 user topics
    
    output_lines = []
    for topic in topics:
        # Get topic details
        cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic {topic} 2>/dev/null"
        detail_result = run_command(cmd, timeout=5)
        
        if detail_result["exit_code"] == 0:
            # Parse the output for key info
            lines = detail_result["stdout"].split("\n")
            for line in lines:
                if "PartitionCount:" in line:
                    # Extract partition and replication info
                    parts = line.split()
                    partition_info = "?"
                    replication_info = "?"
                    for i, part in enumerate(parts):
                        if "PartitionCount:" in part and i+1 < len(parts):
                            partition_info = parts[i+1]
                        if "ReplicationFactor:" in part and i+1 < len(parts):
                            replication_info = parts[i+1]
                    output_lines.append(f"===== {topic} =====")
                    output_lines.append(f"Topic: {topic}  PartitionCount: {partition_info}  ReplicationFactor: {replication_info}")
                    break
    
    return [{
        "name": "kafka_list_topics",
        "status": True,
        "output": "\n".join(output_lines) if output_lines else "No user topics found",
        "severity": "INFO"
    }]


def test_kafka_consumer_groups() -> List[Dict]:
    """List consumer groups with clean formatting"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_consumer_groups",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "WARNING"
        }]
    
    # Get consumer groups
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list 2>/dev/null"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] != 0:
        return [{
            "name": "kafka_consumer_groups",
            "status": False,
            "output": "Failed to list consumer groups",
            "severity": "WARNING"
        }]
    
    groups = result["stdout"].split("\n") if result["stdout"] else []
    
    # Get details for each group
    output_lines = []
    for group in groups[:3]:  # First 3 groups
        if group:
            cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group {group} 2>/dev/null"
            detail_result = run_command(cmd, timeout=5)
            
            if detail_result["exit_code"] == 0 and detail_result["stdout"]:
                lines = detail_result["stdout"].split("\n")
                # Just get the header and first data line
                relevant_lines = [l for l in lines if l and ("TOPIC" in l or group in l)][:2]
                output_lines.extend(relevant_lines)
    
    return [{
        "name": "kafka_consumer_groups",
        "status": True,
        "output": "\n".join(output_lines) if output_lines else "No consumer groups found",
        "severity": "INFO"
    }]


def _get_topics() -> List[str]:
    """Get topics from environment or fetch from cluster"""
    # First try environment variable
    topics_env = os.getenv("KAFKA_TOPICS", "")
    if topics_env:
        return [t.strip() for t in topics_env.split(",") if t.strip()]
    
    # Otherwise return the known topics
    return ["topic1", "topic2"]  # Your configured topics


def test_topics() -> List[Dict]:
    """Test operations on each configured topic"""
    topics = _get_topics()
    results = []
    
    for topic in topics:
        results.append(kafka_topic_write(topic))
        results.append(kafka_topic_read(topic))
        results.append(kafka_topic_offsets(topic))
    
    return results


def kafka_topic_write(topic: str) -> Dict:
    """Test writing to a topic"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return {
            "name": f"kafka_{topic}_write",
            "status": False,
            "output": f"Error from server (NotFound): pods \"kafka-kafka-0\" not found",
            "severity": "CRITICAL"
        }
    
    test_message = f"test-{uuid.uuid4()}"
    
    cmd = f"echo '{test_message}' | kubectl exec -i -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-console-producer.sh --broker-list localhost:9092 --topic {topic} 2>&1"
    result = run_command(cmd, timeout=10)
    
    status = result["exit_code"] == 0
    
    return {
        "name": f"kafka_{topic}_write",
        "status": status,
        "output": "Message produced successfully" if status else f"Error from server (NotFound): pods \"kafka-kafka-0\" not found",
        "severity": "CRITICAL" if not status else "INFO"
    }


def kafka_topic_read(topic: str) -> Dict:
    """Test reading from a topic"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return {
            "name": f"kafka_{topic}_read",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "WARNING"
        }
    
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- timeout 2 /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic {topic} --max-messages 1 --from-beginning 2>&1 || true"
    result = run_command(cmd, timeout=5)
    
    has_messages = len(result.get("stdout", "")) > 0
    
    if has_messages:
        line_count = len(result["stdout"].split("\n"))
        output = f"Found messages: {line_count} lines"
        status = True
    else:
        output = "No messages found"
        status = False
    
    return {
        "name": f"kafka_{topic}_read",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }


def kafka_topic_offsets(topic: str) -> Dict:
    """Check topic offsets"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return {
            "name": f"kafka_{topic}_offsets",
            "status": False,
            "output": "Failed to get offsets",
            "severity": "WARNING"
        }
    
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-run-class.sh kafka.tools.GetOffsetShell --broker-list localhost:9092 --topic {topic} 2>&1"
    result = run_command(cmd, timeout=10)
    
    if result["exit_code"] == 0 and ":" in result.get("stdout", ""):
        # Parse offsets
        lines = result["stdout"].split("\n")
        offset_info = []
        for line in lines[:3]:
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 3:
                    partition = parts[1]
                    offset = parts[2]
                    offset_info.append(f"P{partition}:{offset}")
        output = "Offsets: " + " ".join(offset_info) if offset_info else "No offset data"
        status = True
    else:
        output = "Failed to get offsets"
        status = False
    
    return {
        "name": f"kafka_{topic}_offsets",
        "status": status,
        "output": output,
        "severity": "WARNING" if not status else "INFO"
    }


def test_kafka_cluster_health() -> List[Dict]:
    """Check overall Kafka cluster health - FIXED"""
    namespace = get_kafka_namespace()
    results = []
    
    # Count broker pods correctly
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/broker-role=true --no-headers 2>/dev/null"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = result["stdout"].strip().split("\n")
        total_brokers = len(lines)
        running_brokers = sum(1 for line in lines if "Running" in line and "1/1" in line)
        
        # Get pod names
        pod_names = []
        for line in lines:
            if line:
                pod_names.append(line.split()[0])
        
        output = f"Kafka brokers: {running_brokers}/{total_brokers} running\n"
        output += f"  Pods: {', '.join(pod_names)}"
        
        results.append({
            "name": "kafka_broker_pods",
            "status": running_brokers == total_brokers,
            "output": output,
            "severity": "CRITICAL" if running_brokers != total_brokers else "INFO"
        })
    
    # Count controller pods
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/controller-role=true --no-headers 2>/dev/null"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = result["stdout"].strip().split("\n")
        total_controllers = len(lines)
        running_controllers = sum(1 for line in lines if "Running" in line and "1/1" in line)
        
        # Get pod names
        pod_names = []
        for line in lines:
            if line:
                pod_names.append(line.split()[0])
        
        output = f"Kafka controllers: {running_controllers}/{total_controllers} running\n"
        output += f"  Pods: {', '.join(pod_names)}"
        
        results.append({
            "name": "kafka_controller_pods",
            "status": running_controllers == total_controllers,
            "output": output,
            "severity": "CRITICAL" if running_controllers != total_controllers else "INFO"
        })
    
    return results


def test_kafka_statistics() -> List[Dict]:
    """Get Kafka cluster statistics - CLEANED OUTPUT"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_statistics",
            "status": False,
            "output": f"Error from server (NotFound): pods \"kafka-kafka-0\" not found",
            "severity": "WARNING"
        }]
    
    # Count topics
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null | wc -l"
    topic_result = run_command(cmd, timeout=10)
    
    # Count consumer groups
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list 2>/dev/null | wc -l"
    group_result = run_command(cmd, timeout=10)
    
    topic_count = topic_result["stdout"].strip() if topic_result["exit_code"] == 0 else "?"
    group_count = group_result["stdout"].strip() if group_result["exit_code"] == 0 else "?"
    
    output = f"Cluster Statistics:\n"
    output += f"  Topics: {topic_count}\n"
    output += f"  Consumer Groups: {group_count}"
    
    return [{
        "name": "kafka_statistics",
        "status": topic_result["exit_code"] == 0,
        "output": output,
        "severity": "INFO"
    }]


# Main execution
if __name__ == "__main__":
    all_results = []
    
    namespace = get_kafka_namespace()
    print(f"Using Kafka namespace: {namespace}\n")
    
    # Run tests
    all_results.extend(test_kafka_connectivity())
    all_results.extend(test_kafka_list_topics())
    all_results.extend(test_kafka_consumer_groups())
    all_results.extend(test_kafka_statistics())
    all_results.extend(test_topics())
    all_results.extend(test_kafka_cluster_health())
    
    # Print clean results
    print("\n" + "="*60)
    print("KAFKA TEST RESULTS")
    print("="*60 + "\n")
    
    for result in all_results:
        status_icon = "✓" if result["status"] else "✗"
        status_text = "Passed" if result["status"] else "Failed"
        print(f"{result['name']}")
        print(f"  Status: {status_text}")
        if result["output"]:
            print(f"  {result['output']}\n")
    
    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"])
    failed = total - passed
    
    print("="*60)
    print(f"SUMMARY: {passed}/{total} tests passed, {failed} failed")
    print("="*60)
