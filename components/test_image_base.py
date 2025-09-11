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
    
    # FIRST MESSAGE - Instructions
    tests.append(create_test_result(
        "instructions",
        "Script customization instructions",
        True,
        "Please customize your own script for your source code. Here is the basic structure explained below.",
        "INFO"
    ))
    
    # SECOND MESSAGE - Structure explanation
    tests.append(create_test_result(
        "structure",
        "How this script is structured",
        True,
        "STRUCTURE: 1) create_test_result() builds each message with name/description/status/output/severity. 2) test_messages() contains all your messages. 3) main() outputs everything as JSON. To customize: just modify the test_messages() function.",
        "INFO"
    ))
    
    # THIRD MESSAGE - How to use
    tests.append(create_test_result(
        "usage",
        "How to modify this script",
        True,
        "TO CUSTOMIZE: Replace these messages with your own. Set status=True for pass, False for fail. Severity can be INFO/WARNING/CRITICAL. Each message needs: name (unique ID), description (short title), status (pass/fail), output (your actual message).",
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
