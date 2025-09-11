#!/usr/bin/env python3
"""
Simple Test Script - Message only
Output: JSON array with messages
"""

import json
import sys
from typing import Dict, List, Any

def create_test_result(name: str, description: str, passed: bool, output: str, severity: str = "INFO") -> Dict[str, Any]:
    """Create test result"""
    return {
        "name": name,
        "description": description,
        "status": bool(passed),
        "output": output,
        "severity": severity.lower(),
    }

def test_messages() -> List[Dict[str, Any]]:
    """Your messages here"""
    tests = []
    
    # ADD YOUR MESSAGES HERE - They always pass (True)
    tests.append(create_test_result(
        "message_1",
        "First message",
        True,
        "Replace this with your message",
        "INFO"
    ))
    
    tests.append(create_test_result(
        "message_2",
        "Second message",
        True,
        "Replace this with another message",
        "INFO"
    ))
    
    return tests

def main():
    """Main"""
    try:
        results = test_messages()
        print(json.dumps(results, indent=2))
        sys.exit(0)
    except Exception as e:
        error_result = [{
            "name": "error",
            "description": "Error",
            "status": False,
            "output": str(e),
            "severity": "critical"
        }]
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()
