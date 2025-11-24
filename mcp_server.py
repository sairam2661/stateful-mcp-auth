from fastmcp import FastMCP
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import hmac
import hashlib
import json
import time
from tabulate import tabulate

from eval_framework import (
    TestRequest, PolicyType,
    GitHubMCPEvaluator, GitHubTestDataset
)


@dataclass
class ServerState:
    principals: Dict[str, dict] = None
    resources: Dict[str, dict] = None
    hmac_secret: str = "demo-secret-key"
    
    def __post_init__(self):
        if self.principals is None:
            self.principals = {}
        if self.resources is None:
            self.resources = {}
    
    def get_principal_state(self, principal_id: str) -> dict:
        if principal_id not in self.principals:
            self.principals[principal_id] = {
                "created_resources": [],
                "written_resources": [],
                "read_resources": []
            }
        return self.principals[principal_id]
    
    def get_resource_state(self, resource_id: str) -> dict:
        if resource_id not in self.resources:
            self.resources[resource_id] = {
                "created_by": None,
                "written_by": [],
                "reviewed_by": [],
                "review_count": 0
            }
        return self.resources[resource_id]
    
    def update_after_action(self, principal_id: str, action: str, resource_id: str):
        principal_state = self.get_principal_state(principal_id)
        resource_state = self.get_resource_state(resource_id)
        
        if action.startswith("create") or action in ["create_file", "create_pr"]:
            principal_state["created_resources"].append(resource_id)
            resource_state["created_by"] = principal_id
        elif action.startswith("write") or action == "edit_file":
            principal_state["written_resources"].append(resource_id)
            resource_state["written_by"].append(principal_id)
        elif action.startswith("read"):
            principal_state["read_resources"].append(resource_id)
        elif action == "review_pr":
            resource_state["reviewed_by"].append(principal_id)
            resource_state["review_count"] += 1
    
    def compute_hmac(self, principal_id: str) -> str:
        state = self.get_principal_state(principal_id)
        state_json = json.dumps(state, sort_keys=True)
        return hmac.new(
            self.hmac_secret.encode(),
            state_json.encode(),
            hashlib.sha256
        ).hexdigest()


class SimpleAuthorizationEngine:
    def __init__(self, state: ServerState):
        self.state = state
    
    def authorize(self, principal_id: str, action: str, resource_id: str, 
                  policy_type: Optional[PolicyType] = None) -> Tuple[bool, List[str], float]:
        start_time = time.perf_counter()
        
        principal_state = self.state.get_principal_state(principal_id)
        resource_state = self.state.get_resource_state(resource_id)
        
        if policy_type is None:
            policy_type = self._infer_policy_type(action)
        
        if policy_type == PolicyType.ACCESS_ONLY_CREATED:
            permit, reasons = self._eval_access_only_created(
                principal_id, action, resource_id, principal_state, resource_state
            )
        elif policy_type == PolicyType.WRITE_AT_MOST_ONCE:
            permit, reasons = self._eval_write_at_most_once(
                principal_id, action, resource_id, principal_state, resource_state
            )
        elif policy_type == PolicyType.CREATED_AND_REVIEWED:
            permit, reasons = self._eval_created_and_reviewed(
                principal_id, action, resource_id, principal_state, resource_state
            )
        else:
            permit, reasons = False, ["Unknown policy type"]
        
        eval_time_ms = (time.perf_counter() - start_time) * 1000
        return permit, reasons, eval_time_ms
    
    def _infer_policy_type(self, action: str) -> PolicyType:
        if action in ["read_file", "edit_file", "delete_file", "read_pr"]:
            return PolicyType.ACCESS_ONLY_CREATED
        elif action in ["write_file"]:
            return PolicyType.WRITE_AT_MOST_ONCE
        elif action in ["merge_pr"]:
            return PolicyType.CREATED_AND_REVIEWED
        return PolicyType.ACCESS_ONLY_CREATED
    
    def _eval_access_only_created(self, principal_id, action, resource_id, 
                                   principal_state, resource_state) -> Tuple[bool, List[str]]:
        if resource_id in principal_state["created_resources"]:
            return True, [f"{principal_id} created {resource_id}"]
        return False, [f"{principal_id} did not create {resource_id}"]
    
    def _eval_write_at_most_once(self, principal_id, action, resource_id,
                                  principal_state, resource_state) -> Tuple[bool, List[str]]:
        if action != "write_file":
            return True, ["Action is not a write"]
        
        if resource_id in principal_state["written_resources"]:
            return False, [f"{principal_id} already wrote to {resource_id}"]
        return True, [f"First write to {resource_id}"]
    
    def _eval_created_and_reviewed(self, principal_id, action, resource_id,
                                    principal_state, resource_state) -> Tuple[bool, List[str]]:
        if resource_id not in principal_state["created_resources"]:
            return False, [f"{principal_id} did not create {resource_id}"]
        
        other_reviewers = [r for r in resource_state["reviewed_by"] if r != principal_id]
        if not other_reviewers:
            return False, [f"{resource_id} has no reviews from others"]
        
        return True, [
            f"{principal_id} created {resource_id}",
            f"Reviewed by: {', '.join(other_reviewers)}"
        ]


def create_github_mcp_server():
    mcp = FastMCP("GitHub MCP")
    server_state = ServerState()
    auth_engine = SimpleAuthorizationEngine(server_state)
    
    @mcp.tool()
    def create_file(principal_id: str, filepath: str, content: str) -> dict:
        server_state.update_after_action(principal_id, "create_file", filepath)
        return {
            "success": True,
            "message": f"Created {filepath}",
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def read_file(principal_id: str, filepath: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "read_file", filepath, PolicyType.ACCESS_ONLY_CREATED
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        principal_state = server_state.get_principal_state(principal_id)
        if filepath in principal_state["read_resources"]:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": [f"{principal_id} already read {filepath}"],
                "eval_time_ms": eval_time
            }
        
        server_state.update_after_action(principal_id, "read_file", filepath)
        
        return {
            "success": True,
            "message": f"Read {filepath}",
            "content": f"[Contents of {filepath}]",
            "reasons": reasons,
            "eval_time_ms": eval_time,
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def edit_file(principal_id: str, filepath: str, new_content: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "edit_file", filepath, PolicyType.ACCESS_ONLY_CREATED
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        server_state.update_after_action(principal_id, "edit_file", filepath)
        
        return {
            "success": True,
            "message": f"Edited {filepath}",
            "reasons": reasons,
            "eval_time_ms": eval_time,
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def write_file(principal_id: str, filepath: str, content: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "write_file", filepath, PolicyType.WRITE_AT_MOST_ONCE
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        server_state.update_after_action(principal_id, "write_file", filepath)
        
        return {
            "success": True,
            "message": f"Wrote to {filepath}",
            "reasons": reasons,
            "eval_time_ms": eval_time,
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def delete_file(principal_id: str, filepath: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "delete_file", filepath, PolicyType.ACCESS_ONLY_CREATED
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        return {
            "success": True,
            "message": f"Deleted {filepath}",
            "reasons": reasons,
            "eval_time_ms": eval_time,
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def create_pr(principal_id: str, pr_id: str, title: str, description: str) -> dict:
        server_state.update_after_action(principal_id, "create_pr", pr_id)
        return {
            "success": True,
            "message": f"Created PR {pr_id}",
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def read_pr(principal_id: str, pr_id: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "read_pr", pr_id, PolicyType.ACCESS_ONLY_CREATED
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        return {
            "success": True,
            "message": f"Read PR {pr_id}",
            "pr_data": {"id": pr_id, "status": "open"},
            "reasons": reasons,
            "eval_time_ms": eval_time,
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def review_pr(principal_id: str, pr_id: str, approved: bool, comments: str) -> dict:
        server_state.update_after_action(principal_id, "review_pr", pr_id)
        return {
            "success": True,
            "message": f"Reviewed PR {pr_id}",
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    @mcp.tool()
    def merge_pr(principal_id: str, pr_id: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "merge_pr", pr_id, PolicyType.CREATED_AND_REVIEWED
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        return {
            "success": True,
            "message": f"Merged PR {pr_id}",
            "reasons": reasons,
            "eval_time_ms": eval_time,
            "state_hmac": server_state.compute_hmac(principal_id)
        }
    
    return mcp, server_state, auth_engine


class RealMCPServerAdapter:
    def __init__(self, mcp_server, server_state, auth_engine):
        self.mcp = mcp_server
        self.server_state = server_state
        self.auth_engine = auth_engine
        self.tools = {
            tool_name: tool 
            for tool_name, tool in mcp_server._tool_manager._tools.items()
        }
    
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        self._setup_test_state(request)
        
        permit, reasons, eval_time = self.auth_engine.authorize(
            request.principal,
            request.action,
            request.resource,
            request.policy_type
        )
        
        decision = "PERMIT" if permit else "DENY"
        return decision, reasons, eval_time
    
    def _setup_test_state(self, request: TestRequest):
        principal_state = self.server_state.get_principal_state(request.principal)
        principal_state.update(request.principal_state or {})
        
        resource_state = self.server_state.get_resource_state(request.resource)
        resource_state.update(request.resource_state or {})


def run_evaluation():
    mcp_server, server_state, auth_engine = create_github_mcp_server()
    adapter = RealMCPServerAdapter(mcp_server, server_state, auth_engine)
    
    dataset = GitHubTestDataset()
    test_requests = dataset.generate_all_tests()
    
    evaluator = GitHubMCPEvaluator(adapter)
    metrics = evaluator.run_evaluation(test_requests)

    
    summary_data = [
        ["Total Requests", metrics.total_requests],
        ["Legitimate", metrics.legitimate_requests],
        ["Dangerous", metrics.dangerous_requests],
        ["", ""],
        ["Block Rate", f"{metrics.block_rate:.2f}%"],
        ["False Positive Rate", f"{metrics.false_positive_rate:.2f}%"],
        ["False Negative Rate", f"{metrics.false_negative_rate:.2f}%"],
        ["Accuracy", f"{metrics.accuracy:.2f}%"],
        ["", ""],
        ["Avg Latency", f"{metrics.avg_latency_ms:.2f}ms"],
        ["P95 Latency", f"{metrics.p95_latency_ms:.2f}ms"],
    ]
    
    print(tabulate(summary_data, tablefmt="simple"))
    
    evaluator.save_results("eval_results.json")
    
    return metrics


if __name__ == "__main__":
    run_evaluation()