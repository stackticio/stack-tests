from pydantic import BaseModel
from typing import Dict

class RegisteredStack(BaseModel):
    id: str
    url: str   

class Test(BaseModel):
    system_id: str
    component: str
    host_url: str
    stack_url: str
    git_url: str
    git_branch: str
    git_folder_hierarchy: str
    git_token: str
    custom_tests: Dict[str, str] = {}
    
