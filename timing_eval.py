from dataclasses import dataclass, field
from typing import List, Dict
import json
from collections import defaultdict

from eval_framework import GitHubTestDataset, PolicyType, TestRequest
from policies.access_only_created import build_access_only_created, AccessOnlyCreatedState
from policies.write_at_most_once import build_write_at_most_once, WriteAtMostOnceState
from policies.created_and_reviewed import build_created_and_reviewed, CreatedAndReviewedState
from policy_auth import TimingBreakdown


@dataclass
class TimingStats:
    samples: List[TimingBreakdown] = field(default_factory=list)

    def add(self, timing: TimingBreakdown):
        self.samples.append(timing)

    def avg(self, field_name: str) -> float:
        if not self.samples:
            return 0.0
        values = [getattr(t, field_name) for t in self.samples]
        return sum(values) / len(values)

    def avg_ms(self, field_name: str) -> float:
        return self.avg(field_name) / 1000.0

    def summary_ms(self) -> Dict[str, float]:
        return {
            "context_build": self.avg_ms("context_build_us"),
            "subprocess_overhead": self.avg_ms("subprocess_overhead_us"),
            "cedar_parse_policy": self.avg_ms("cedar_parse_policy_us"),
            "cedar_parse_context": self.avg_ms("cedar_parse_context_us"),
            "cedar_parse_entities": self.avg_ms("cedar_parse_entities_us"),
            "cedar_build_request": self.avg_ms("cedar_build_request_us"),
            "cedar_authorization": self.avg_ms("cedar_authorization_us"),
            "cedar_total": self.avg_ms("cedar_total_us"),
            "state_update": self.avg_ms("state_update_us"),
            "total": self.avg_ms("total_us"),
        }


class TimingEvaluationAdapter:
    def __init__(self):
        self.access_only_created_auth = build_access_only_created()
        self.write_at_most_once_auth = build_write_at_most_once()
        self.created_and_reviewed_auth = build_created_and_reviewed()

    def authorize_with_timing(self, request: TestRequest) -> TimingBreakdown:
        policy_type = request.policy_type

        if policy_type == PolicyType.ACCESS_ONLY_CREATED:
            return self._eval_access_only_created(request)
        elif policy_type == PolicyType.WRITE_AT_MOST_ONCE:
            return self._eval_write_at_most_once(request)
        elif policy_type == PolicyType.CREATED_AND_REVIEWED:
            return self._eval_created_and_reviewed(request)
        else:
            return TimingBreakdown()

    def _eval_access_only_created(self, request: TestRequest) -> TimingBreakdown:
        allowed = set()
        created_resources = request.principal_state.get("created_resources", [])
        for resource in created_resources:
            allowed.add(f"{request.principal}:{resource}")

        self.access_only_created_auth.state = AccessOnlyCreatedState(allowed=allowed)

        _, _, timing = self.access_only_created_auth.authorize_with_timing(
            request.principal,
            request.action,
            request.resource
        )
        return timing

    def _eval_write_at_most_once(self, request: TestRequest) -> TimingBreakdown:
        written = set()
        written_resources = request.principal_state.get("written_resources", [])
        for resource in written_resources:
            written.add(f"{request.principal}:{resource}")

        self.write_at_most_once_auth.state = WriteAtMostOnceState(written=written)

        _, _, timing = self.write_at_most_once_auth.authorize_with_timing(
            request.principal,
            request.action,
            request.resource
        )
        return timing

    def _eval_created_and_reviewed(self, request: TestRequest) -> TimingBreakdown:
        created = set()
        reviewed = set()

        created_resources = request.principal_state.get("created_resources", [])
        for resource in created_resources:
            created.add(f"{request.principal}:{resource}")

        reviewers = request.resource_state.get("reviewed_by", [])
        for reviewer in reviewers:
            reviewed.add(f"{reviewer}:{request.resource}")

        self.created_and_reviewed_auth.state = CreatedAndReviewedState(
            created=created, reviewed=reviewed
        )

        _, _, timing = self.created_and_reviewed_auth.authorize_with_timing(
            request.principal,
            request.action,
            request.resource
        )
        return timing


def run_timing_evaluation():
    dataset = GitHubTestDataset()
    test_requests = dataset.generate_all_tests()

    timing_by_policy: Dict[PolicyType, TimingStats] = defaultdict(TimingStats)
    overall_timing = TimingStats()

    adapter = TimingEvaluationAdapter()

    print(f"Running {len(test_requests)} requests with timing...\n")

    for i, request in enumerate(test_requests):
        if (i + 1) % 50 == 0:
            print(f"Progress: {i + 1}/{len(test_requests)}")

        timing = adapter.authorize_with_timing(request)

        timing_by_policy[request.policy_type].add(timing)
        overall_timing.add(timing)


    print("Overall Average:")
    overall = overall_timing.summary_ms()
    for key, value in overall.items():
        print(f"  {key:25} {value:8.3f} ms")


    for policy_type in PolicyType:
        stats = timing_by_policy[policy_type]
        if not stats.samples:
            continue

        print(f"{policy_type.value} ({len(stats.samples)} samples):")
        summary = stats.summary_ms()
        for key, value in summary.items():
            print(f"  {key:25} {value:8.3f} ms")
        print()

    plot_data = {
        "overall": overall_timing.summary_ms(),
        "by_policy": {
            pt.value: timing_by_policy[pt].summary_ms()
            for pt in PolicyType
            if timing_by_policy[pt].samples
        }
    }

    with open("timing_results.json", "w") as f:
        json.dump(plot_data, f, indent=2)

    print(f"Timing data saved to timing_results.json")

    return plot_data


if __name__ == "__main__":
    run_timing_evaluation()