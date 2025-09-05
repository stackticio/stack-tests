# test_kafka.py - Generic production version with dynamic pod detection

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
    """Dynamically find the first Kafka broker pod"""
    namespace = get_kafka_namespace()
    
    # Find Kafka broker pods using Strimzi labels
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/kind=Kafka,strimzi.io/name -o jsonpath='{{.items[0].metadata.name}}' 2>&1"
    result = run_command(cmd, timeout=5)
    
    if result["exit_code"] == 0 and result["stdout"]:
        return result["stdout"].strip()
    
    # Fallback: try to find any pod with kafka in the name
    cmd = f"kubectl get pods -n {namespace} --no-headers 2>&1 | grep -E 'kafka-[0-9]' | head -1 | awk '{{print $1}}'"
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
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    # Test by listing topics via kubectl exec
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list 2>&1 | head -10"
    result = run_command(cmd)
    
    status = result["exit_code"] == 0
    severity = "CRITICAL" if not status else "INFO"
    
    output = f"Using pod: {broker_pod}\n"
    output += result.get('stdout', result.get('stderr', ''))[:400]
    
    return [{
        "name": "kafka_connectivity",
        "status": status,
        "output": output,
        "severity": severity
    }]


def test_kafka_list_topics() -> List[Dict]:
    """List all Kafka topics with details"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_list_topics",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "CRITICAL"
        }]
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    cmd = f"""kubectl exec -n {namespace} {broker_pod} -- bash -c '
        topics=$(./bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list | grep -v "^__" | head -5)
        if [ -z "$topics" ]; then
            echo "No user topics found"
        else
            for topic in $topics; do
                echo "===== $topic ====="
                ./bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --topic "$topic" --describe
            done
        fi
    ' 2>&1"""
    
    result = run_command(cmd, timeout=30)
    
    status = result["exit_code"] == 0
    severity = "WARNING" if not status else "INFO"
    
    return [{
        "name": "kafka_list_topics",
        "status": status,
        "output": result.get('stdout', 'No topics found' if status else result.get('stderr', ''))[:1000],
        "severity": severity
    }]


def test_kafka_consumer_groups() -> List[Dict]:
    """List all consumer groups and their lag"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_consumer_groups",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "WARNING"
        }]
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    cmd = f"""kubectl exec -n {namespace} {broker_pod} -- \
        /opt/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server {bootstrap_servers} \
        --all-groups --describe 2>&1 | head -50"""
    
    result = run_command(cmd)
    
    status = result["exit_code"] == 0
    output = result.get('stdout', 'No consumer groups' if status else result.get('stderr', ''))
    severity = "INFO"
    
    return [{
        "name": "kafka_consumer_groups",
        "status": status,
        "output": output[:1000],
        "severity": severity
    }]


def _get_topics() -> List[str]:
    """Get topics from environment or fetch from cluster"""
    # First try environment variable
    topics_env = os.getenv("KAFKA_TOPICS", "")
    if topics_env:
        return [t.strip() for t in topics_env.split(",") if t.strip()]
    
    # Otherwise fetch from cluster
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return []
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    cmd = f"kubectl exec -n {namespace} {broker_pod} -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        topics = [t.strip() for t in result["stdout"].split("\n") if t.strip() and not t.startswith("__")]
        return topics[:3]  # Limit to 3 topics for testing
    
    return []


def test_topics() -> List[Dict]:
    """Test operations on each configured topic"""
    topics = _get_topics()
    results = []
    
    if not topics:
        results.append({
            "name": "kafka_topics_configured",
            "status": False,
            "output": "No topics found or configured",
            "severity": "WARNING"
        })
        return results
    
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
            "output": "No Kafka broker pod available",
            "severity": "CRITICAL"
        }
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    test_message = f'{{"test_id":"{uuid.uuid4()}","timestamp":"{time.strftime("%Y-%m-%d %H:%M:%S")}","source":"stack_agent"}}'
    
    cmd = f"""kubectl exec -n {namespace} {broker_pod} -- bash -c 'echo "{test_message}" | \
        /opt/kafka/bin/kafka-console-producer.sh \
        --broker-list {bootstrap_servers} \
        --topic {topic} 2>&1 && echo "SUCCESS: Message sent"' """
    
    result = run_command(cmd, timeout=10)
    
    status = result["exit_code"] == 0 and "SUCCESS" in result.get("stdout", "")
    severity = "CRITICAL" if not status else "INFO"
    
    return {
        "name": f"kafka_{topic}_write",
        "status": status,
        "output": "Message produced successfully" if status else result.get('stderr', 'Failed')[:200],
        "severity": severity
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
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    cmd = f"""kubectl exec -n {namespace} {broker_pod} -- timeout 3 \
        /opt/kafka/bin/kafka-console-consumer.sh \
        --bootstrap-server {bootstrap_servers} \
        --topic {topic} \
        --max-messages 2 \
        --from-beginning 2>&1 || true"""
    
    result = run_command(cmd, timeout=10)
    
    has_messages = len(result.get("stdout", "")) > 0
    status = result["exit_code"] in [0, 124] and has_messages
    
    output = f"Found messages: {len(result.get('stdout', '').splitlines())} lines" if has_messages else "No messages in topic"
    severity = "WARNING" if not status else "INFO"
    
    return {
        "name": f"kafka_{topic}_read",
        "status": status,
        "output": output,
        "severity": severity
    }


def kafka_topic_offsets(topic: str) -> Dict:
    """Check topic offsets"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return {
            "name": f"kafka_{topic}_offsets",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "WARNING"
        }
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    cmd = f"""kubectl exec -n {namespace} {broker_pod} -- \
        /opt/kafka/bin/kafka-run-class.sh kafka.tools.GetOffsetShell \
        --broker-list {bootstrap_servers} \
        --topic {topic} --time -1 2>&1"""
    
    result = run_command(cmd)
    
    status = result["exit_code"] == 0
    severity = "WARNING" if not status else "INFO"
    
    # Parse offset output
    output = "Offsets: "
    if status and result["stdout"]:
        lines = result["stdout"].split("\n")
        for line in lines[:3]:  # Show first 3 partitions
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 3:
                    output += f"P{parts[1]}:{parts[2].strip()} "
    else:
        output = "Failed to get offsets"
    
    return {
        "name": f"kafka_{topic}_offsets",
        "status": status,
        "output": output,
        "severity": severity
    }


def test_kafka_connect() -> List[Dict]:
    """Test Kafka Connect cluster health"""
    namespace = get_kafka_namespace()
    results = []
    
    # Check if KafkaConnect CR exists and is ready
    cmd = f"kubectl get kafkaconnect -n {namespace} -o json 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            items = data.get("items", [])
            
            if not items:
                results.append({
                    "name": "kafka_connect",
                    "status": True,
                    "output": "No KafkaConnect resources deployed",
                    "severity": "INFO"
                })
            else:
                for connect in items:
                    name = connect.get("metadata", {}).get("name", "unknown")
                    conditions = connect.get("status", {}).get("conditions", [])
                    
                    ready_condition = next((c for c in conditions if c.get("type") == "Ready"), {})
                    is_ready = ready_condition.get("status") == "True"
                    
                    replicas = connect.get("spec", {}).get("replicas", 0)
                    ready_replicas = connect.get("status", {}).get("replicas", 0)
                    
                    output = f"Connect '{name}': {ready_replicas}/{replicas} replicas ready"
                    if not is_ready:
                        output += f"\n  Reason: {ready_condition.get('reason', 'Unknown')}"
                    
                    results.append({
                        "name": f"kafka_connect_{name}",
                        "status": is_ready,
                        "output": output,
                        "severity": "CRITICAL" if not is_ready else "INFO"
                    })
        except Exception as e:
            results.append({
                "name": "kafka_connect",
                "status": False,
                "output": f"Failed to parse KafkaConnect: {str(e)[:100]}",
                "severity": "WARNING"
            })
    else:
        results.append({
            "name": "kafka_connect",
            "status": True,
            "output": "No KafkaConnect resources found",
            "severity": "INFO"
        })
    
    # Check Connect pods if any Connect CR exists
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/kind=KafkaConnect --no-headers 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = [l for l in result["stdout"].split("\n") if l.strip()]
        running = [l for l in lines if "Running" in l and "1/1" in l]
        
        results.append({
            "name": "kafka_connect_pods",
            "status": len(running) == len(lines),
            "output": f"Connect pods: {len(running)}/{len(lines)} running",
            "severity": "CRITICAL" if len(running) != len(lines) else "INFO"
        })
    
    return results


def test_kafka_connectors() -> List[Dict]:
    """Test all KafkaConnector resources generically"""
    namespace = get_kafka_namespace()
    results = []
    
    # Get all KafkaConnector CRs
    cmd = f"kubectl get kafkaconnector -n {namespace} -o json 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            items = data.get("items", [])
            
            if not items:
                results.append({
                    "name": "kafka_connectors",
                    "status": True,
                    "output": "No connectors deployed",
                    "severity": "INFO"
                })
            else:
                results.append({
                    "name": "kafka_connectors_count",
                    "status": True,
                    "output": f"Found {len(items)} connector(s)",
                    "severity": "INFO"
                })
                
                # Check each connector generically
                for item in items:
                    name = item.get("metadata", {}).get("name", "unknown")
                    spec = item.get("spec", {})
                    status = item.get("status", {})
                    
                    # Get connector class (type)
                    connector_class = spec.get("class", "unknown")
                    class_short = connector_class.split(".")[-1] if "." in connector_class else connector_class
                    
                    # Check conditions
                    conditions = status.get("conditions", [])
                    ready_condition = next((c for c in conditions if c.get("type") == "Ready"), {})
                    is_ready = ready_condition.get("status") == "True"
                    
                    # Get task status
                    tasks_max = spec.get("tasksMax", 1)
                    
                    output = f"Type: {class_short}, Tasks: {tasks_max}, "
                    output += f"State: {'Ready' if is_ready else ready_condition.get('reason', 'NotReady')}"
                    
                    # Add any error message if present
                    if not is_ready and ready_condition.get("message"):
                        output += f"\n  Error: {ready_condition['message'][:100]}"
                    
                    severity = "CRITICAL" if not is_ready else "INFO"
                    
                    results.append({
                        "name": f"kafka_connector_{name}",
                        "status": is_ready,
                        "output": output,
                        "severity": severity
                    })
                    
        except Exception as e:
            results.append({
                "name": "kafka_connectors",
                "status": False,
                "output": f"Failed to parse connectors: {str(e)[:200]}",
                "severity": "WARNING"
            })
    else:
        results.append({
            "name": "kafka_connectors",
            "status": True,
            "output": "No KafkaConnector CRs found",
            "severity": "INFO"
        })
    
    return results


def test_kafka_cluster_health() -> List[Dict]:
    """Check overall Kafka cluster health"""
    namespace = get_kafka_namespace()
    results = []
    
    # Check Kafka CR status
    cmd = f"kubectl get kafka -n {namespace} -o json 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            items = data.get("items", [])
            
            if not items:
                results.append({
                    "name": "kafka_cluster_status",
                    "status": False,
                    "output": f"No Kafka CR found in namespace {namespace}",
                    "severity": "CRITICAL"
                })
            else:
                for kafka in items:
                    name = kafka.get("metadata", {}).get("name", "unknown")
                    conditions = kafka.get("status", {}).get("conditions", [])
                    
                    ready_condition = next((c for c in conditions if c.get("type") == "Ready"), {})
                    is_ready = ready_condition.get("status") == "True"
                    
                    # Get replicas info
                    spec_replicas = kafka.get("spec", {}).get("kafka", {}).get("replicas", 0)
                    
                    output = f"Kafka cluster '{name}': {'Ready' if is_ready else 'Not Ready'}"
                    output += f" ({spec_replicas} replicas configured)"
                    
                    results.append({
                        "name": f"kafka_cluster_{name}_status",
                        "status": is_ready,
                        "output": output,
                        "severity": "CRITICAL" if not is_ready else "INFO"
                    })
        except Exception as e:
            results.append({
                "name": "kafka_cluster_status",
                "status": False,
                "output": f"Failed to parse Kafka CR: {str(e)[:100]}",
                "severity": "CRITICAL"
            })
    
    # Check Kafka broker pods using proper Strimzi labels
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/kind=Kafka --no-headers 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = [l for l in result["stdout"].split("\n") if l.strip()]
        running = [l for l in lines if "Running" in l and "1/1" in l]
        
        all_running = len(running) == len(lines)
        
        # Get pod names for debugging
        pod_names = []
        for line in lines[:3]:  # Show first 3 pods
            if line:
                pod_names.append(line.split()[0])
        
        output = f"Kafka brokers: {len(running)}/{len(lines)} running"
        if pod_names:
            output += f"\n  Pods: {', '.join(pod_names)}"
        
        results.append({
            "name": "kafka_broker_pods",
            "status": all_running,
            "output": output,
            "severity": "CRITICAL" if not all_running else "INFO"
        })
    
    # Check for Zookeeper or KRaft mode
    cmd = f"kubectl get pods -n {namespace} -l strimzi.io/name -o jsonpath='{{.items[*].metadata.labels.strimzi\\.io/name}}' 2>&1 | grep -o zookeeper | wc -l"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            zk_count = int(result["stdout"].strip()) if result["stdout"].strip().isdigit() else 0
            mode = "Zookeeper" if zk_count > 0 else "KRaft"
            
            results.append({
                "name": "kafka_cluster_mode",
                "status": True,
                "output": f"Cluster mode: {mode}",
                "severity": "INFO"
            })
        except:
            pass
    
    return results


def test_kafka_statistics() -> List[Dict]:
    """Get Kafka cluster statistics"""
    namespace = get_kafka_namespace()
    broker_pod = get_kafka_broker_pod()
    
    if not broker_pod:
        return [{
            "name": "kafka_statistics",
            "status": False,
            "output": "No Kafka broker pod available",
            "severity": "WARNING"
        }]
    
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap:9092"))
    
    cmd = f"""kubectl exec -n {namespace} {broker_pod} -- bash -c '
        echo "Cluster Statistics:"
        echo -n "  Topics: "
        ./bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list 2>/dev/null | wc -l
        echo -n "  Consumer Groups: "
        ./bin/kafka-consumer-groups.sh --bootstrap-server {bootstrap_servers} --list 2>/dev/null | wc -l
    ' 2>&1"""
    
    result = run_command(cmd, timeout=15)
    
    status = result["exit_code"] == 0
    severity = "INFO"
    
    return [{
        "name": "kafka_statistics",
        "status": status,
        "output": result.get('stdout', 'Failed to get statistics')[:500],
        "severity": severity
    }]


# Main execution matching PostgreSQL test structure
if __name__ == "__main__":
    # Run all tests
    all_results = []
    
    # Show namespace being used
    namespace = get_kafka_namespace()
    print(f"Using Kafka namespace: {namespace}\n")
    
    # Basic connectivity
    all_results.extend(test_kafka_connectivity())
    
    # Cluster information
    all_results.extend(test_kafka_list_topics())
    all_results.extend(test_kafka_consumer_groups())
    all_results.extend(test_kafka_statistics())
    
    # Topic operations
    all_results.extend(test_topics())
    
    # Kafka Connect and Connectors (generic)
    all_results.extend(test_kafka_connect())
    all_results.extend(test_kafka_connectors())
    
    # Overall health
    all_results.extend(test_kafka_cluster_health())
    
    # Print results
    print("\n" + "="*60)
    print("KAFKA TEST RESULTS")
    print("="*60 + "\n")
    
    for result in all_results:
        status_icon = "✓" if result["status"] else "✗"
        print(f"{status_icon} {result['name']} [{result['severity']}]")
        if result["output"]:
            output = result["output"]
            if len(output) > 200:
                output = output[:200] + "..."
            print(f"  Output: {output}")
        print()
    
    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"])
    failed = total - passed
    
    print("\n" + "="*60)
    print(f"SUMMARY: {passed}/{total} tests passed, {failed} failed")
    print("="*60)
