from typing import Tuple, List
import time
from tabulate import tabulate

from eval_framework import (
    TestRequest, PolicyType, RequestType,
    GitHubMCPEvaluator, GitHubTestDataset
)

from mcp_server import SimpleAuthorizationEngine, ServerState


class NoAuthorizationEngine:
    def __init__(self, state: ServerState):
        self.state = state
    
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        start_time = time.perf_counter()
        decision = "PERMIT"
        reasons = ["No authorization"]
        eval_time = (time.perf_counter() - start_time) * 1000
        return decision, reasons, eval_time


class StatelessAuthorizationEngine:
    def __init__(self, state: ServerState):
        self.state = state
        self.user_permissions = {
            "alice": ["read_file", "edit_file", "write_file", "delete_file", "merge_pr"],
            "bob": ["read_file", "edit_file", "write_file", "delete_file", "merge_pr"],
            "charlie": ["read_file", "edit_file", "write_file", "delete_file"],
            "dave": ["read_file", "merge_pr"],
            "mallory": ["read_file"],
            "eve": ["read_file", "merge_pr"],
        }
    
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        start_time = time.perf_counter()
        
        principal = request.principal
        action = request.action
        allowed_actions = self.user_permissions.get(principal, [])
        
        if action in allowed_actions:
            decision = "PERMIT"
            reasons = [f"{principal} has permission for {action}"]
        else:
            decision = "DENY"
            reasons = [f"{principal} lacks permission for {action}"]
        
        eval_time = (time.perf_counter() - start_time) * 1000
        return decision, reasons, eval_time


class StatefulAuthorizationEngineAdapter:
    def __init__(self, state: ServerState):
        self.engine = SimpleAuthorizationEngine(state)
        self.state = state
    
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        principal_state = self.state.get_principal_state(request.principal)
        principal_state.update(request.principal_state or {})
        
        resource_state = self.state.get_resource_state(request.resource)
        resource_state.update(request.resource_state or {})
        
        permit, reasons, eval_time = self.engine.authorize(
            request.principal,
            request.action,
            request.resource,
            request.policy_type
        )
        
        decision = "PERMIT" if permit else "DENY"
        return decision, reasons, eval_time


def run_baseline_comparison():
    dataset = GitHubTestDataset()
    test_requests = dataset.generate_all_tests()
    
    results = {}
    
    for name, engine_class in [
        ("No Auth", NoAuthorizationEngine),
        ("Stateless", StatelessAuthorizationEngine),
        ("Stateful", StatefulAuthorizationEngineAdapter)
    ]:
        state = ServerState()
        engine = engine_class(state)
        evaluator = GitHubMCPEvaluator(engine)
        metrics = evaluator.run_evaluation(test_requests)
        results[name] = metrics
        
    comparison_data = [
        ["Block Rate", 
         f"{results['No Auth'].block_rate:.2f}%",
         f"{results['Stateless'].block_rate:.2f}%",
         f"{results['Stateful'].block_rate:.2f}%"],
        ["False Negatives",
         results['No Auth'].false_negatives,
         results['Stateless'].false_negatives,
         results['Stateful'].false_negatives],
        ["False Positives",
         results['No Auth'].false_positives,
         results['Stateless'].false_positives,
         results['Stateful'].false_positives],
        ["Dangerous Allowed",
         f"{results['No Auth'].false_negatives}/{results['No Auth'].dangerous_requests}",
         f"{results['Stateless'].false_negatives}/{results['Stateless'].dangerous_requests}",
         f"{results['Stateful'].false_negatives}/{results['Stateful'].dangerous_requests}"],
        ["Accuracy",
         f"{results['No Auth'].accuracy:.2f}%",
         f"{results['Stateless'].accuracy:.2f}%",
         f"{results['Stateful'].accuracy:.2f}%"]
    ]
    
    print(tabulate(comparison_data, 
                   headers=["Metric", "No Auth", "Stateless", "Stateful"],
                   tablefmt="grid"))

if __name__ == "__main__":
    run_baseline_comparison()