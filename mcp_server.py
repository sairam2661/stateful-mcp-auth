from fastmcp import FastMCP
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
import time
from tabulate import tabulate

from eval_framework import (
    TestRequest, PolicyType,
    GitHubMCPEvaluator, GitHubTestDataset
)

from policies.access_only_created import (
    build_access_only_created, AccessOnlyCreatedState
)
from policies.write_at_most_once import (
    build_write_at_most_once, WriteAtMostOnceState
)
from policies.created_and_reviewed import (
    build_created_and_reviewed, CreatedAndReviewedState
)

@dataclass
class ServerState:
    # For access_only_created: track who created what
    created: Set[str] = field(default_factory=set)
    
    # For write_at_most_once: track who wrote what
    written: Set[str] = field(default_factory=set) 
    
    # For created_and_reviewed: track reviews
    reviewed: Set[str] = field(default_factory=set)
    
    def record_create(self, principal_id: str, resource_id: str):
        self.created.add(f"{principal_id}:{resource_id}")
    
    def record_write(self, principal_id: str, resource_id: str):
        self.written.add(f"{principal_id}:{resource_id}")
    
    def record_review(self, principal_id: str, resource_id: str):
        self.reviewed.add(f"{principal_id}:{resource_id}")


class CedarAuthorizationEngine:    
    def __init__(self, server_state: ServerState):
        self.server_state = server_state
        self.access_only_created_auth = build_access_only_created()
        self.write_at_most_once_auth = build_write_at_most_once()
        self.created_and_reviewed_auth = build_created_and_reviewed()
    
    def authorize(
        self, 
        principal_id: str, 
        action: str, 
        resource_id: str,
        policy_type: Optional[PolicyType] = None
    ) -> Tuple[bool, List[str], float]:
        
        if policy_type is None:
            policy_type = self._infer_policy_type(action)
        
        self._sync_state(policy_type)
        
        if policy_type == PolicyType.ACCESS_ONLY_CREATED:
            return self.access_only_created_auth.authorize(
                principal_id, action, resource_id
            )
        elif policy_type == PolicyType.WRITE_AT_MOST_ONCE:
            return self.write_at_most_once_auth.authorize(
                principal_id, action, resource_id
            )
        elif policy_type == PolicyType.CREATED_AND_REVIEWED:
            return self.created_and_reviewed_auth.authorize(
                principal_id, action, resource_id
            )
        else:
            return False, ["Unknown policy type"], 0.0
    
    def _sync_state(self, policy_type: PolicyType):
        if policy_type == PolicyType.ACCESS_ONLY_CREATED:
            self.access_only_created_auth.state = AccessOnlyCreatedState(
                allowed=self.server_state.created.copy()
            )
        elif policy_type == PolicyType.WRITE_AT_MOST_ONCE:
            self.write_at_most_once_auth.state = WriteAtMostOnceState(
                written=self.server_state.written.copy()
            )
        elif policy_type == PolicyType.CREATED_AND_REVIEWED:
            self.created_and_reviewed_auth.state = CreatedAndReviewedState(
                created=self.server_state.created.copy(),
                reviewed=self.server_state.reviewed.copy()
            )
    
    def _infer_policy_type(self, action: str) -> PolicyType:
        if action in ["read_file", "edit_file", "delete_file", "read_pr"]:
            return PolicyType.ACCESS_ONLY_CREATED
        elif action in ["write_file"]:
            return PolicyType.WRITE_AT_MOST_ONCE
        elif action in ["merge_pr"]:
            return PolicyType.CREATED_AND_REVIEWED
        return PolicyType.ACCESS_ONLY_CREATED

def create_github_mcp_server():
    mcp = FastMCP("GitHub MCP with Cedar Authorization")
    server_state = ServerState()
    auth_engine = CedarAuthorizationEngine(server_state)
    
    @mcp.tool()
    def create_file(principal_id: str, filepath: str, content: str) -> dict:
        server_state.record_create(principal_id, filepath)
        return {"success": True, "message": f"Created {filepath}"}
    
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
        
        return {
            "success": True,
            "content": f"[Contents of {filepath}]",
            "eval_time_ms": eval_time
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
        
        return {"success": True, "message": f"Edited {filepath}", "eval_time_ms": eval_time}
    
    @mcp.tool()
    def write_file(principal_id: str, filepath: str, content: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "write_file", filepath, PolicyType.WRITE_AT_MOST_ONCE
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied - already written",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        server_state.record_write(principal_id, filepath)
        return {"success": True, "message": f"Wrote to {filepath}", "eval_time_ms": eval_time}
    
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
        
        return {"success": True, "message": f"Deleted {filepath}", "eval_time_ms": eval_time}
    
    @mcp.tool()
    def create_pr(principal_id: str, pr_id: str, title: str, description: str) -> dict:
        server_state.record_create(principal_id, pr_id)
        return {"success": True, "message": f"Created PR {pr_id}"}
    
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
            "pr_data": {"id": pr_id, "status": "open"},
            "eval_time_ms": eval_time
        }
    
    @mcp.tool()
    def review_pr(principal_id: str, pr_id: str, approved: bool, comments: str) -> dict:
        server_state.record_review(principal_id, pr_id)
        return {"success": True, "message": f"Reviewed PR {pr_id}"}
    
    @mcp.tool()
    def merge_pr(principal_id: str, pr_id: str) -> dict:
        permit, reasons, eval_time = auth_engine.authorize(
            principal_id, "merge_pr", pr_id, PolicyType.CREATED_AND_REVIEWED
        )
        
        if not permit:
            return {
                "success": False,
                "error": "Authorization denied - needs review from another user",
                "reasons": reasons,
                "eval_time_ms": eval_time
            }
        
        return {"success": True, "message": f"Merged PR {pr_id}", "eval_time_ms": eval_time}
    
    return mcp, server_state, auth_engine


class MCPServerEvaluationAdapter:    
    def __init__(self, server_state: ServerState, auth_engine: CedarAuthorizationEngine):
        self.server_state = server_state
        self.auth_engine = auth_engine
    
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
        # Reset state
        self.server_state.created.clear()
        self.server_state.written.clear()
        self.server_state.reviewed.clear()
        
        # Inject created resources
        created_resources = request.principal_state.get("created_resources", [])
        for resource in created_resources:
            self.server_state.created.add(f"{request.principal}:{resource}")
        
        # Inject written resources
        written_resources = request.principal_state.get("written_resources", [])
        for resource in written_resources:
            self.server_state.written.add(f"{request.principal}:{resource}")
        
        # Inject reviews
        reviewers = request.resource_state.get("reviewed_by", [])
        for reviewer in reviewers:
            self.server_state.reviewed.add(f"{reviewer}:{request.resource}")


def run_mcp_server_evaluation():    
    mcp_server, server_state, auth_engine = create_github_mcp_server()
    adapter = MCPServerEvaluationAdapter(server_state, auth_engine)
    
    dataset = GitHubTestDataset()
    test_requests = dataset.generate_all_tests()
    
    print(f"Running {len(test_requests)} test requests against MCP server...\n")
    
    evaluator = GitHubMCPEvaluator(adapter)
    metrics = evaluator.run_evaluation(test_requests)
    
    print("\nResults:\n")
    
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
    
    print("\nPer-Policy Breakdown:")
    
    policy_data = []
    for policy_type in PolicyType:
        results = metrics.results_by_policy[policy_type]
        if not results:
            continue
        
        total = len(results)
        correct = sum(1 for r in results if r.correct)
        accuracy = (correct / total * 100) if total > 0 else 0
        
        tp = sum(1 for r in results if r.is_true_positive)
        fp = sum(1 for r in results if r.is_false_positive)
        fn = sum(1 for r in results if r.is_false_negative)
        
        policy_data.append([
            policy_type.value, total, f"{accuracy:.1f}%", tp, fp, fn
        ])
    
    print(tabulate(
        policy_data,
        headers=["Policy", "Tests", "Accuracy", "TP", "FP", "FN"],
        tablefmt="grid"
    ))
    
    evaluator.save_results("mcp_server_eval_results.json")

if __name__ == "__main__":
    run_mcp_server_evaluation()