#!/usr/bin/env python3
"""
Message Test Script - Always passes, just displays informational messages
Perfect for status updates, system info, or non-failing checks

Output: JSON array of test results to stdout
Each result: {
  name, description, status (always true), severity (info), output (your message)
}
"""

import json
import sys
import time
from typing import Dict, List, Any
from datetime import datetime

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def create_message(name: str, description: str, message: str) -> Dict[str, Any]:
    """Create a message result that always passes"""
    return {
        "name": name,
        "description": description,
        "status": True,  # Always True for messages
        "output": message,
        "severity": "info"  # Always info for messages
    }

# ------------------------------------------------------------
# Message Functions - Customize these
# ------------------------------------------------------------

def show_welcome_message() -> List[Dict[str, Any]]:
    """Display welcome message"""
    return [create_message(
        "welcome",
        "Welcome message",
        "System check initialized - All messages are informational only"
    )]

def show_system_info() -> List[Dict[str, Any]]:
    """Display system information"""
    messages = []
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    messages.append(create_message(
        "timestamp",
        "Current timestamp",
        f"Check performed at: {current_time}"
    ))
    
    messages.append(create_message(
        "environment",
        "Environment status",
        "Running in: PRODUCTION environment"
    ))
    
    return messages

def show_custom_messages() -> List[Dict[str, Any]]:
    """Your custom messages here"""
    messages = []
    
    # Add your custom messages
    messages.append(create_message(
        "custom_message_1",
        "First custom message",
        "This is where you put your first custom message"
    ))
    
    messages.append(create_message(
        "custom_message_2", 
        "Second custom message",
        "This is where you put your second custom message"
    ))
    
    messages.append(create_message(
        "instructions",
        "Instructions for users",
        "Replace these messages with your own content - they will always show as 'passed'"
    ))
    
    return messages

# ------------------------------------------------------------
# Main runner
# ------------------------------------------------------------

def run_messages() -> List[Dict[str, A
