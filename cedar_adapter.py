from typing import Tuple, List
from eval_framework import TestRequest, PolicyType

from policies.access_only_created import build_access_only_created, AccessOnlyCreatedState
from policies.write_at_most_once import build_write_at_most_once, WriteAtMostOnceState
from policies.created_and_reviewed import build_created_and_reviewed, CreatedAndReviewedState


class CedarEvaluationAdapter:
    def __init__(self):
        self.access_only_created_auth = build_access_only_created()
        self.write_at_most_once_auth = build_write_at_most_once()
        self.created_and_reviewed_auth = build_created_and_reviewed()

    def authorize(self, request: TestRequest) -> Tuple[str, List[str], float]:
        policy_type = request.policy_type

        if policy_type == PolicyType.ACCESS_ONLY_CREATED:
            return self._eval_access_only_created(request)
        elif policy_type == PolicyType.WRITE_AT_MOST_ONCE:
            return self._eval_write_at_most_once(request)
        elif policy_type == PolicyType.CREATED_AND_REVIEWED:
            return self._eval_created_and_reviewed(request)
        else:
            return "DENY", ["Unknown policy type"], 0.0

    def _eval_access_only_created(self, request: TestRequest) -> Tuple[str, List[str], float]:
        allowed = set()
        created_resources = request.principal_state.get("created_resources", [])
        for resource in created_resources:
            allowed.add(f"{request.principal}:{resource}")

        test_state = AccessOnlyCreatedState(allowed=allowed)
        self.access_only_created_auth.state = test_state

        permit, reasons, eval_time = self.access_only_created_auth.authorize(
            request.principal,
            request.action,
            request.resource
        )

        decision = "PERMIT" if permit else "DENY"
        return decision, reasons, eval_time

    def _eval_write_at_most_once(self, request: TestRequest) -> Tuple[str, List[str], float]:
        written = set()
        written_resources = request.principal_state.get("written_resources", [])
        for resource in written_resources:
            written.add(f"{request.principal}:{resource}")

        test_state = WriteAtMostOnceState(written=written)
        self.write_at_most_once_auth.state = test_state

        permit, reasons, eval_time = self.write_at_most_once_auth.authorize(
            request.principal,
            request.action,
            request.resource
        )

        decision = "PERMIT" if permit else "DENY"
        return decision, reasons, eval_time

    def _eval_created_and_reviewed(self, request: TestRequest) -> Tuple[str, List[str], float]:
        created = set()
        reviewed = set()

        created_resources = request.principal_state.get("created_resources", [])
        for resource in created_resources:
            created.add(f"{request.principal}:{resource}")

        reviewers = request.resource_state.get("reviewed_by", [])
        for reviewer in reviewers:
            reviewed.add(f"{reviewer}:{request.resource}")

        test_state = CreatedAndReviewedState(created=created, reviewed=reviewed)
        self.created_and_reviewed_auth.state = test_state

        permit, reasons, eval_time = self.created_and_reviewed_auth.authorize(
            request.principal,
            request.action,
            request.resource
        )

        decision = "PERMIT" if permit else "DENY"
        return decision, reasons, eval_time