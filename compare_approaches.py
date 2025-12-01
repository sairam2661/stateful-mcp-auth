from typing import Tuple, List
import time
from tabulate import tabulate

from eval_framework import (
    TestRequest, PolicyType, RequestType,
    GitHubMCPEvaluator, GitHubTestDataset
)

from cedar_adapter import CedarEvaluationAdapter

class NoAuthEngine:    
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        start_time = time.perf_counter()
        decision = "PERMIT"
        reasons = ["No authorization - all requests permitted"]
        eval_time = (time.perf_counter() - start_time) * 1000
        return decision, reasons, eval_time


class StatelessAuthEngine:
    def __init__(self):
        self.role_permissions = {
            "developer": ["read_file", "edit_file", "write_file", "delete_file", 
                         "create_file", "create_pr", "read_pr", "review_pr", "merge_pr"],
            "limited": ["read_file", "read_pr"],  # Restricted role for suspicious users
            "reviewer": ["read_file", "read_pr", "review_pr"],
        }
        
        self.user_roles = {
            "alice": "developer",
            "bob": "developer",
            "charlie": "developer",
            "dave": "developer",
            "mallory": "limited",    # Known bad actor - restricted
            "eve": "limited",        # Known bad actor - restricted
            "reviewer1": "reviewer",
            "reviewer2": "reviewer",
            "reviewer3": "reviewer",
        }
    
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        start_time = time.perf_counter()
        
        principal = request.principal
        action = request.action
        
        role = self.user_roles.get(principal, "limited")
        allowed_actions = self.role_permissions.get(role, [])
        
        if action in allowed_actions:
            decision = "PERMIT"
            reasons = [f"{principal} (role: {role}) has permission for {action}"]
        else:
            decision = "DENY"
            reasons = [f"{principal} (role: {role}) lacks permission for {action}"]
        
        eval_time = (time.perf_counter() - start_time) * 1000
        return decision, reasons, eval_time


def run_baseline_comparison():
    print("MCP Authorization Strategy Comparison")
    print()
    print("\n" + "-" * 80 + "\n")
    
    dataset = GitHubTestDataset()
    test_requests = dataset.generate_all_tests()
    
    print(f"Test dataset: {len(test_requests)} requests")
    print(f"Legitimate: {sum(1 for r in test_requests if r.request_type == RequestType.LEGITIMATE)}")
    print(f"Dangerous:  {sum(1 for r in test_requests if r.request_type == RequestType.DANGEROUS)}")
    
    print("\n" + "-" * 80 + "\n")
    
    results = {}
    
    engines = [
        ("No Auth", NoAuthEngine()),
        ("Stateless Auth", StatelessAuthEngine()),
        ("Stateful Cedar", CedarEvaluationAdapter()),
    ]
    
    for name, engine in engines:
        print(f"Evaluating: {name}...")
        evaluator = GitHubMCPEvaluator(engine)
        metrics = evaluator.run_evaluation(test_requests)
        results[name] = metrics
        print()
    
    print("Results Summary")
    
    comparison_data = [
        ["Metric", "No Auth", "Stateless Auth", "Stateful Cedar"],
        ["─" * 20, "─" * 12, "─" * 14, "─" * 14],
        ["Block Rate", 
         f"{results['No Auth'].block_rate:.1f}%",
         f"{results['Stateless Auth'].block_rate:.1f}%",
         f"{results['Stateful Cedar'].block_rate:.1f}%"],
        ["False Positive Rate",
         f"{results['No Auth'].false_positive_rate:.1f}%",
         f"{results['Stateless Auth'].false_positive_rate:.1f}%",
         f"{results['Stateful Cedar'].false_positive_rate:.1f}%"],
        ["False Negative Rate",
         f"{results['No Auth'].false_negative_rate:.1f}%",
         f"{results['Stateless Auth'].false_negative_rate:.1f}%",
         f"{results['Stateful Cedar'].false_negative_rate:.1f}%"],
        ["", "", "", ""],
        ["Accuracy",
         f"{results['No Auth'].accuracy:.1f}%",
         f"{results['Stateless Auth'].accuracy:.1f}%",
         f"{results['Stateful Cedar'].accuracy:.1f}%"],
        ["", "", "", ""],
        ["True Positives",
         f"{results['No Auth'].true_positives}",
         f"{results['Stateless Auth'].true_positives}",
         f"{results['Stateful Cedar'].true_positives}"],
        ["True Negatives",
         f"{results['No Auth'].true_negatives}",
         f"{results['Stateless Auth'].true_negatives}",
         f"{results['Stateful Cedar'].true_negatives}"],
        ["False Positives",
         f"{results['No Auth'].false_positives}",
         f"{results['Stateless Auth'].false_positives}",
         f"{results['Stateful Cedar'].false_positives}"],
        ["False Negatives",
         f"{results['No Auth'].false_negatives}",
         f"{results['Stateless Auth'].false_negatives}",
         f"{results['Stateful Cedar'].false_negatives}"],
        ["", "", "", ""],
        ["Avg Latency",
         f"{results['No Auth'].avg_latency_ms:.2f}ms",
         f"{results['Stateless Auth'].avg_latency_ms:.2f}ms",
         f"{results['Stateful Cedar'].avg_latency_ms:.2f}ms"],
    ]
    
    print(tabulate(comparison_data, tablefmt="simple"))
    
    print("Policy Breakdown:")
    print("-" * 40)
    
    for policy_type in PolicyType:
        print(f"\n{policy_type.value}:")
        
        for name in ["No Auth", "Stateless Auth", "Stateful Cedar"]:
            policy_results = results[name].results_by_policy[policy_type]
            if not policy_results:
                continue
            
            total = len(policy_results)
            correct = sum(1 for r in policy_results if r.correct)
            accuracy = (correct / total * 100) if total > 0 else 0
            
            tp = sum(1 for r in policy_results if r.is_true_positive)
            fp = sum(1 for r in policy_results if r.is_false_positive)
            fn = sum(1 for r in policy_results if r.is_false_negative)
            
            print(f"{name:20} - Accuracy: {accuracy:5.1f}% | TP: {tp:2} | FP: {fp:2} | FN: {fn:2}")

if __name__ == "__main__":
    run_baseline_comparison()