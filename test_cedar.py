from eval_framework import GitHubTestDataset, GitHubMCPEvaluator, PolicyType
from cedar_adapter import CedarEvaluationAdapter
from tabulate import tabulate


def test_cedar_integration():
    adapter = CedarEvaluationAdapter()

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
            policy_type.value,
            total,
            f"{accuracy:.1f}%",
            tp,
            fp,
            fn
        ])

    print(tabulate(
        policy_data,
        headers=["Policy", "Tests", "Accuracy", "TP", "FP", "FN"],
        tablefmt="grid"
    ))

    evaluator.save_results("cedar_eval_results.json")

if __name__ == "__main__":
    test_cedar_integration()