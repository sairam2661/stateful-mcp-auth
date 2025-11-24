from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum
import time
import json
from collections import defaultdict

class PolicyType(Enum):
    ACCESS_ONLY_CREATED = "access_only_created"
    WRITE_AT_MOST_ONCE = "write_at_most_once"
    CREATED_AND_REVIEWED = "created_and_reviewed"

class RequestType(Enum):
    LEGITIMATE = "legitimate"
    DANGEROUS = "dangerous"

@dataclass
class TestRequest:
    id: int
    policy_type: PolicyType
    request_type: RequestType
    principal: str
    action: str
    resource: str
    description: str
    expected_decision: str
    principal_state: Optional[Dict] = None
    resource_state: Optional[Dict] = None


@dataclass
class TestResult:
    request: TestRequest
    actual_decision: str
    latency_ms: float
    policy_eval_time_ms: float
    reasons: List[str]
    correct: bool
    
    @property
    def is_false_positive(self) -> bool:
        return (self.request.request_type == RequestType.LEGITIMATE and 
                self.actual_decision == "DENY")
    
    @property
    def is_false_negative(self) -> bool:
        return (self.request.request_type == RequestType.DANGEROUS and 
                self.actual_decision == "PERMIT")
    
    @property
    def is_true_positive(self) -> bool:
        return (self.request.request_type == RequestType.DANGEROUS and 
                self.actual_decision == "DENY")
    
    @property
    def is_true_negative(self) -> bool:
        return (self.request.request_type == RequestType.LEGITIMATE and 
                self.actual_decision == "PERMIT")


class GitHubTestDataset:
    def __init__(self):
        self.test_requests: List[TestRequest] = []
        self.request_id = 0
    
    def generate_all_tests(self) -> List[TestRequest]:
        self.generate_access_only_created_tests()
        self.generate_write_at_most_once_tests()
        self.generate_created_and_reviewed_tests()
        return self.test_requests
    
    def _add_request(self, policy_type: PolicyType, request_type: RequestType,
                     principal: str, action: str, resource: str, 
                     description: str, expected_decision: str,
                     principal_state: Optional[Dict] = None,
                     resource_state: Optional[Dict] = None):
        self.request_id += 1
        self.test_requests.append(TestRequest(
            id=self.request_id,
            policy_type=policy_type,
            request_type=request_type,
            principal=principal,
            action=action,
            resource=resource,
            description=description,
            expected_decision=expected_decision,
            principal_state=principal_state or {},
            resource_state=resource_state or {}
        ))
    
    def generate_access_only_created_tests(self):
        policy = PolicyType.ACCESS_ONLY_CREATED
        
        for i in range(10):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="alice",
                action="read_file",
                resource=f"src/file_{i}.py",
                description=f"Alice reads file_{i}.py that she created",
                expected_decision="PERMIT",
                principal_state={"created_resources": [f"src/file_{i}.py"]},
                resource_state={"created_by": "alice"}
            )
        
        for i in range(10):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="bob",
                action="edit_file",
                resource=f"docs/doc_{i}.md",
                description=f"Bob edits doc_{i}.md that he created",
                expected_decision="PERMIT",
                principal_state={"created_resources": [f"docs/doc_{i}.md"]},
                resource_state={"created_by": "bob"}
            )
        
        for i in range(15):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="charlie",
                action="delete_file",
                resource=f"temp/temp_{i}.txt",
                description=f"Charlie deletes temp_{i}.txt that he created",
                expected_decision="PERMIT",
                principal_state={"created_resources": [f"temp/temp_{i}.txt"]},
                resource_state={"created_by": "charlie"}
            )
        
        users = ["alice", "bob", "charlie"]
        for i in range(6):
            for user in users:
                self._add_request(
                    policy, RequestType.LEGITIMATE,
                    principal=user,
                    action="read_pr",
                    resource=f"pr/{user}/pr_{i}",
                    description=f"{user} reads their own PR #{i}",
                    expected_decision="PERMIT",
                    principal_state={"created_resources": [f"pr/{user}/pr_{i}"]},
                    resource_state={"created_by": user}
                )
        
        for i in range(10):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="mallory",
                action="edit_file",
                resource=f"src/file_{i}.py",
                description=f"Mallory tries to edit Alice's file_{i}.py",
                expected_decision="DENY",
                principal_state={"created_resources": []},
                resource_state={"created_by": "alice"}
            )
        
        for i in range(4):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="eve",
                action="delete_file",
                resource=f"important/config_{i}.json",
                description=f"Eve tries to delete Bob's config_{i}.json",
                expected_decision="DENY",
                principal_state={"created_resources": []},
                resource_state={"created_by": "bob"}
            )
    
    def generate_write_at_most_once_tests(self):
        policy = PolicyType.WRITE_AT_MOST_ONCE
        
        for i in range(30):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="alice",
                action="write_file",
                resource=f"data/output_{i}.csv",
                description=f"Alice writes to output_{i}.csv for the first time",
                expected_decision="PERMIT",
                principal_state={"written_resources": []},
                resource_state={"written_by": []}
            )
        
        for i in range(23):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="bob",
                action="read_file",
                resource=f"logs/log_{i}.txt",
                description=f"Bob reads log_{i}.txt (reading is not writing)",
                expected_decision="PERMIT",
                principal_state={"written_resources": [f"logs/log_{i}.txt"]},
                resource_state={"written_by": ["bob"]}
            )
        
        for i in range(10):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="charlie",
                action="write_file",
                resource=f"records/record_{i}.json",
                description=f"Charlie tries to write to record_{i}.json again",
                expected_decision="DENY",
                principal_state={"written_resources": [f"records/record_{i}.json"]},
                resource_state={"written_by": ["charlie"]}
            )
        
        for i in range(4):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="dave",
                action="write_file",
                resource=f"config/immutable_{i}.yaml",
                description=f"Dave tries to modify immutable_{i}.yaml",
                expected_decision="DENY",
                principal_state={"written_resources": [f"config/immutable_{i}.yaml"]},
                resource_state={"written_by": ["dave"]}
            )
    
    def generate_created_and_reviewed_tests(self):
        policy = PolicyType.CREATED_AND_REVIEWED
        
        reviewers = ["reviewer1", "reviewer2", "reviewer3"]
        for i in range(10):
            for reviewer in reviewers:
                self._add_request(
                    policy, RequestType.LEGITIMATE,
                    principal="alice",
                    action="merge_pr",
                    resource=f"pr/alice/pr_{i}",
                    description=f"Alice merges pr_{i} (created by her, reviewed by {reviewer})",
                    expected_decision="PERMIT",
                    principal_state={"created_resources": [f"pr/alice/pr_{i}"]},
                    resource_state={
                        "created_by": "alice",
                        "reviewed_by": [reviewer],
                        "review_count": 1
                    }
                )
        
        for i in range(12):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="bob",
                action="merge_pr",
                resource=f"pr/bob/pr_{i}",
                description=f"Bob merges pr_{i} (2 reviews)",
                expected_decision="PERMIT",
                principal_state={"created_resources": [f"pr/bob/pr_{i}"]},
                resource_state={
                    "created_by": "bob",
                    "reviewed_by": ["reviewer1", "reviewer2"],
                    "review_count": 2
                }
            )
        
        for i in range(12):
            self._add_request(
                policy, RequestType.LEGITIMATE,
                principal="charlie",
                action="merge_pr",
                resource=f"pr/charlie/pr_{i}",
                description=f"Charlie merges pr_{i} (3 reviews)",
                expected_decision="PERMIT",
                principal_state={"created_resources": [f"pr/charlie/pr_{i}"]},
                resource_state={
                    "created_by": "charlie",
                    "reviewed_by": ["reviewer1", "reviewer2", "reviewer3"],
                    "review_count": 3
                }
            )
        
        for i in range(4):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="mallory",
                action="merge_pr",
                resource=f"pr/alice/pr_{i}",
                description=f"Mallory tries to merge Alice's pr_{i}",
                expected_decision="DENY",
                principal_state={"created_resources": []},
                resource_state={
                    "created_by": "alice",
                    "reviewed_by": ["reviewer1"],
                    "review_count": 1
                }
            )
        
        for i in range(4):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="eve",
                action="merge_pr",
                resource=f"pr/eve/pr_{i}",
                description=f"Eve tries to merge unreviewed pr_{i}",
                expected_decision="DENY",
                principal_state={"created_resources": [f"pr/eve/pr_{i}"]},
                resource_state={
                    "created_by": "eve",
                    "reviewed_by": [],
                    "review_count": 0
                }
            )
        
        for i in range(4):
            self._add_request(
                policy, RequestType.DANGEROUS,
                principal="dave",
                action="merge_pr",
                resource=f"pr/dave/pr_{i}",
                description=f"Dave tries to merge pr_{i} with only self-review",
                expected_decision="DENY",
                principal_state={"created_resources": [f"pr/dave/pr_{i}"]},
                resource_state={
                    "created_by": "dave",
                    "reviewed_by": ["dave"],
                    "review_count": 1
                }
            )

@dataclass
class EvaluationMetrics:
    total_requests: int = 0
    legitimate_requests: int = 0
    dangerous_requests: int = 0
    
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    
    total_latency_ms: float = 0.0
    total_policy_eval_time_ms: float = 0.0
    
    results_by_policy: Dict[PolicyType, List[TestResult]] = field(default_factory=lambda: defaultdict(list))
    all_results: List[TestResult] = field(default_factory=list)
    
    @property
    def block_rate(self) -> float:
        if self.dangerous_requests == 0:
            return 0.0
        return (self.true_positives / self.dangerous_requests) * 100
    
    @property
    def false_positive_rate(self) -> float:
        if self.legitimate_requests == 0:
            return 0.0
        return (self.false_positives / self.legitimate_requests) * 100
    
    @property
    def false_negative_rate(self) -> float:
        if self.dangerous_requests == 0:
            return 0.0
        return (self.false_negatives / self.dangerous_requests) * 100
    
    @property
    def accuracy(self) -> float:
        if self.total_requests == 0:
            return 0.0
        correct = self.true_positives + self.true_negatives
        return (correct / self.total_requests) * 100
    
    @property
    def avg_latency_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests
    
    @property
    def p95_latency_ms(self) -> float:
        if not self.all_results:
            return 0.0
        latencies = sorted([r.latency_ms for r in self.all_results])
        idx = int(len(latencies) * 0.95)
        return latencies[idx] if idx < len(latencies) else latencies[-1]
    
    @property
    def avg_policy_eval_time_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_policy_eval_time_ms / self.total_requests
    
    def add_result(self, result: TestResult):
        self.all_results.append(result)
        self.total_requests += 1
        
        if result.request.request_type == RequestType.LEGITIMATE:
            self.legitimate_requests += 1
        else:
            self.dangerous_requests += 1
        
        if result.is_true_positive:
            self.true_positives += 1
        elif result.is_true_negative:
            self.true_negatives += 1
        elif result.is_false_positive:
            self.false_positives += 1
        elif result.is_false_negative:
            self.false_negatives += 1
        
        self.total_latency_ms += result.latency_ms
        self.total_policy_eval_time_ms += result.policy_eval_time_ms
        
        self.results_by_policy[result.request.policy_type].append(result)


class MockAuthorizationEngine:
    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        start_time = time.perf_counter()
        
        if request.policy_type == PolicyType.ACCESS_ONLY_CREATED:
            decision, reasons = self._eval_access_only_created(request)
        elif request.policy_type == PolicyType.WRITE_AT_MOST_ONCE:
            decision, reasons = self._eval_write_at_most_once(request)
        elif request.policy_type == PolicyType.CREATED_AND_REVIEWED:
            decision, reasons = self._eval_created_and_reviewed(request)
        else:
            decision, reasons = "DENY", ["Unknown policy type"]
        
        eval_time = (time.perf_counter() - start_time) * 1000
        return decision, reasons, eval_time
    
    def _eval_access_only_created(self, request: TestRequest) -> Tuple[str, List[str]]:
        created_resources = request.principal_state.get("created_resources", [])
        
        if request.resource in created_resources:
            return "PERMIT", [f"{request.principal} created {request.resource}"]
        else:
            return "DENY", [f"{request.principal} did not create {request.resource}"]
    
    def _eval_write_at_most_once(self, request: TestRequest) -> Tuple[str, List[str]]:
        if request.action != "write_file":
            return "PERMIT", ["Action is not a write"]
        
        written_resources = request.principal_state.get("written_resources", [])
        
        if request.resource in written_resources:
            return "DENY", [f"{request.principal} already wrote to {request.resource}"]
        else:
            return "PERMIT", [f"First write to {request.resource}"]
    
    def _eval_created_and_reviewed(self, request: TestRequest) -> Tuple[str, List[str]]:
        created_resources = request.principal_state.get("created_resources", [])
        created_by = request.resource_state.get("created_by")
        reviewed_by = request.resource_state.get("reviewed_by", [])
        
        if request.resource not in created_resources or created_by != request.principal:
            return "DENY", [f"{request.principal} did not create {request.resource}"]
        
        other_reviewers = [r for r in reviewed_by if r != request.principal]
        if not other_reviewers:
            return "DENY", [f"{request.resource} has no reviews from others"]
        
        return "PERMIT", [
            f"{request.principal} created {request.resource}",
            f"Reviewed by: {', '.join(other_reviewers)}"
        ]


class GitHubMCPEvaluator:
    def __init__(self, auth_engine: MockAuthorizationEngine):
        self.auth_engine = auth_engine
        self.metrics = EvaluationMetrics()
    
    def run_evaluation(self, test_requests: List[TestRequest]) -> EvaluationMetrics:
        print("Starting evaluation...")
        print(f"Total test requests: {len(test_requests)}\n")
        
        for i, request in enumerate(test_requests, 1):
            if i % 20 == 0:
                print(f"Progress: {i}/{len(test_requests)} requests evaluated...")
            
            result = self._evaluate_request(request)
            self.metrics.add_result(result)
        
        print(f"Progress: {len(test_requests)}/{len(test_requests)} requests evaluated...\n")
        print("Evaluation complete!\n")
        
        return self.metrics
    
    def _evaluate_request(self, request: TestRequest) -> TestResult:
        start_time = time.perf_counter()
        decision, reasons, policy_eval_time = self.auth_engine.authorize(request)
        total_latency = (time.perf_counter() - start_time) * 1000
        correct = (decision == request.expected_decision)
        
        return TestResult(
            request=request,
            actual_decision=decision,
            latency_ms=total_latency,
            policy_eval_time_ms=policy_eval_time,
            reasons=reasons,
            correct=correct
        )
    
    def save_results(self, filename: str = "eval_results.json"):
        results_data = {
            "summary": {
                "total_requests": self.metrics.total_requests,
                "block_rate": self.metrics.block_rate,
                "false_positive_rate": self.metrics.false_positive_rate,
                "false_negative_rate": self.metrics.false_negative_rate,
                "accuracy": self.metrics.accuracy,
                "avg_latency_ms": self.metrics.avg_latency_ms,
                "p95_latency_ms": self.metrics.p95_latency_ms,
            },
            "detailed_results": [
                {
                    "id": r.request.id,
                    "policy": r.request.policy_type.value,
                    "request_type": r.request.request_type.value,
                    "expected": r.request.expected_decision,
                    "actual": r.actual_decision,
                    "correct": r.correct,
                    "latency_ms": r.latency_ms,
                    "description": r.request.description
                }
                for r in self.metrics.all_results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"Results saved to {filename}")