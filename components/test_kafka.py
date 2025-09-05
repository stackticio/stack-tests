# test_kafka.py - Generic production version using kubectl and existing ENVs

import os
import json
import subprocess
import time
import uuid
from typing import List, Dict

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


def test_kafka_connectivity() -> List[Dict]:
    """Test Kafka broker connectivity"""
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS", 
                                           "kafka-kafka-bootstrap.strimzi.svc.cluster.local:9092"))
    
    # Test by listing topics via kubectl exec
    cmd = f"kubectl exec -n strimzi kafka-kafka-0 -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list 2>&1 | head -10"
    result = run_command(cmd)
    
    status = result["exit_code"] == 0
    severity = "CRITICAL" if not status else "INFO"
    
    return [{
        "name": "kafka_connectivity",
        "status": status,
        "output": result.get('stdout', result.get('stderr', ''))[:500],
        "severity": severity
    }]


def test_kafka_list_topics() -> List[Dict]:
    """List all Kafka topics with details"""
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    cmd = f"""kubectl exec -n strimzi kafka-kafka-0 -- bash -c '
        topics=$(./bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list | grep -v "^__" | head -10)
        for topic in $topics; do
            echo "===== $topic ====="
            ./bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --topic "$topic" --describe
        done
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
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    cmd = f"""kubectl exec -n strimzi kafka-kafka-0 -- \
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
    topics_env = os.getenv("KAFKA_TOPICS", "")
    if topics_env:
        return [t.strip() for t in topics_env.split(",") if t.strip()]
    
    # Otherwise fetch from cluster
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    cmd = f"kubectl exec -n strimzi kafka-kafka-0 -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list 2>&1"
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
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    test_message = f'{{"test_id":"{uuid.uuid4()}","timestamp":"{time.strftime("%Y-%m-%d %H:%M:%S")}","source":"stack_agent"}}'
    
    cmd = f"""kubectl exec -n strimzi kafka-kafka-0 -- bash -c 'echo "{test_message}" | \
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
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    cmd = f"""kubectl exec -n strimzi kafka-kafka-0 -- timeout 3 \
        /opt/kafka/bin/kafka-console-consumer.sh \
        --bootstrap-server {bootstrap_servers} \
        --topic {topic} \
        --max-messages 2 \
        --from-beginning 2>&1 || true"""
    
    result = run_command(cmd, timeout=10)
    
    has_messages = len(result.get("stdout", "")) > 0
    status = result["exit_code"] in [0, 124] and has_messages
    
    output = f"Found messages: {len(result.get('stdout', '').split(chr(10)))} lines" if has_messages else "No messages in topic"
    severity = "WARNING" if not status else "INFO"
    
    return {
        "name": f"kafka_{topic}_read",
        "status": status,
        "output": output,
        "severity": severity
    }


def kafka_topic_offsets(topic: str) -> Dict:
    """Check topic offsets"""
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    cmd = f"""kubectl exec -n strimzi kafka-kafka-0 -- \
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
                output += line.split(":")[-1].strip() + " "
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
    results = []
    
    # Check if KafkaConnect CR exists and is ready
    cmd = "kubectl get kafkaconnect -n strimzi -o json 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            items = data.get("items", [])
            
            for connect in items:
                name = connect.get("metadata", {}).get("name", "unknown")
                conditions = connect.get("status", {}).get("conditions", [])
                
                ready_condition = next((c for c in conditions if c.get("type") == "Ready"), {})
                is_ready = ready_condition.get("status") == "True"
                
                replicas = connect.get("spec", {}).get("replicas", 0)
                ready_replicas = connect.get("status", {}).get("replicas", 0)
                
                output = f"Connect '{name}': {ready_replicas}/{replicas} replicas ready"
                
                results.append({
                    "name": f"kafka_connect_{name}",
                    "status": is_ready,
                    "output": output,
                    "severity": "CRITICAL" if not is_ready else "INFO"
                })
        except:
            results.append({
                "name": "kafka_connect",
                "status": False,
                "output": "Failed to parse KafkaConnect status",
                "severity": "WARNING"
            })
    else:
        results.append({
            "name": "kafka_connect",
            "status": False,
            "output": "No KafkaConnect resources found",
            "severity": "INFO"
        })
    
    # Check Connect pods
    cmd = "kubectl get pods -n strimzi -l strimzi.io/kind=KafkaConnect --no-headers 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = [l for l in result["stdout"].split("\n") if l.strip()]
        running = [l for l in lines if "Running" in l and "/1" in l]
        
        results.append({
            "name": "kafka_connect_pods",
            "status": len(running) == len(lines),
            "output": f"Connect pods: {len(running)}/{len(lines)} running",
            "severity": "CRITICAL" if len(running) != len(lines) else "INFO"
        })
    
    return results


def test_kafka_connectors() -> List[Dict]:
    """Test all KafkaConnector resources generically"""
    results = []
    
    # Get all KafkaConnector CRs
    cmd = "kubectl get kafkaconnector -n strimzi -o json 2>&1"
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
                    connector_status = status.get("connectorStatus", {})
                    
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
    results = []
    
    # Check Kafka CR status
    cmd = "kubectl get kafka -n strimzi -o json 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        try:
            data = json.loads(result["stdout"])
            items = data.get("items", [])
            
            for kafka in items:
                name = kafka.get("metadata", {}).get("name", "unknown")
                conditions = kafka.get("status", {}).get("conditions", [])
                
                ready_condition = next((c for c in conditions if c.get("type") == "Ready"), {})
                is_ready = ready_condition.get("status") == "True"
                
                # Get listener status
                listeners = kafka.get("status", {}).get("listeners", [])
                listener_info = f", Listeners: {len(listeners)}" if listeners else ""
                
                output = f"Kafka cluster '{name}': {'Ready' if is_ready else 'Not Ready'}{listener_info}"
                
                results.append({
                    "name": f"kafka_cluster_{name}_status",
                    "status": is_ready,
                    "output": output,
                    "severity": "CRITICAL" if not is_ready else "INFO"
                })
        except:
            pass
    
    # Check Kafka broker pods
    cmd = "kubectl get pods -n strimzi -l strimzi.io/kind=Kafka --no-headers 2>&1"
    result = run_command(cmd)
    
    if result["exit_code"] == 0 and result["stdout"]:
        lines = [l for l in result["stdout"].split("\n") if l.strip()]
        kafka_pods = [l for l in lines if "kafka-" in l]
        running = [l for l in kafka_pods if "Running" in l]
        
        all_running = len(running) == len(kafka_pods)
        
        results.append({
            "name": "kafka_broker_pods",
            "status": all_running,
            "output": f"Kafka brokers: {len(running)}/{len(kafka_pods)} running",
            "severity": "CRITICAL" if not all_running else "INFO"
        })
    
    # Check for Zookeeper or KRaft mode
    cmd = "kubectl get pods -n strimzi -l strimzi.io/name=kafka-zookeeper --no-headers 2>&1 | wc -l"
    result = run_command(cmd)
    
    if result["exit_code"] == 0:
        zk_count = int(result["stdout"].strip()) if result["stdout"].strip().isdigit() else 0
        mode = "Zookeeper" if zk_count > 0 else "KRaft"
        
        results.append({
            "name": "kafka_cluster_mode",
            "status": True,
            "output": f"Cluster mode: {mode}" + (f" ({zk_count} ZK pods)" if zk_count > 0 else ""),
            "severity": "INFO"
        })
    
    return results


def test_kafka_statistics() -> List[Dict]:
    """Get Kafka cluster statistics"""
    bootstrap_servers = os.getenv("KAFKA_KAFKA_BOOTSTRAP_SERVERS", 
                                  os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
    
    cmd = f"""kubectl exec -n strimzi kafka-kafka-0 -- bash -c '
        echo "Cluster Statistics:"
        echo -n "  Topics: "
        ./bin/kafka-topics.sh --bootstrap-server {bootstrap_servers} --list 2>/dev/null | wc -l
        echo -n "  Consumer Groups: "
        ./bin/kafka-consumer-groups.sh --bootstrap-server {bootstrap_servers} --list 2>/dev/null | wc -l
        echo -n "  Brokers: "
        echo "dump" | nc localhost 2181 2>/dev/null | grep brokers | wc -l || echo "N/A (KRaft mode)"
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
