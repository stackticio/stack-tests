import os
from fastapi import APIRouter, HTTPException, Query, Path, Header, Depends
from typing import List, Dict, Any, Optional
from .models import RegisteredStack, Test

import httpx
from .models import RegisteredStack, Test
registered_hosts: Dict[str, str] = {}
registered_stacks: Dict[str, str] = {}

API_KEY = os.getenv('API_KEY')

router = APIRouter()

@router.get("/hosts")
async def list_host():
    return registered_hosts

@router.get("/stacks")
async def list_stacks():
    return registered_stacks

@router.post("/register-stack")
async def register_stack(registered_stack: RegisteredStack):
    registered_stacks[registered_stack.id] = registered_stack.url
    return {"message": f"Stack {registered_stack.id} registered with URL {registered_stack.url}"}

@router.post("/tests/run")
async def run_tests(test: Test):
    if not test.host_url in registered_hosts:
        registered_hosts[test.host_url] = test.stack_url
    
    forward_body = {
        "system_id": test.system_id,
        "component": test.component,
        "host_url": test.host_url,
        "stack_url": test.stack_url,
        "git_url": test.git_url,
        "git_branch": test.git_branch,
        "git_folder_hierarchy": test.git_folder_hierarchy,
        "git_token": test.git_token,
        "custom_tests": test.custom_tests
    }
    
    print(test)
    # Forward to the target service
    async with httpx.AsyncClient(verify=False, timeout=120.0) as client:
        try:
            resp = await client.post(
                f"{test.stack_url}/tests/run-component-tests",  
                json=forward_body,
                headers={
                    "x-api-key": API_KEY,                
                    "Content-Type": "application/json"   
                },
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            import traceback
            traceback.print_exc()
