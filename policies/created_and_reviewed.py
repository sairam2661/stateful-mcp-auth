from dataclasses import dataclass, field
from typing import Set
from policy_auth import PolicyAuthorizer, StatefulPolicy


@dataclass
class CreatedAndReviewedState:
    created: Set[str] = field(default_factory=set)
    reviewed: Set[str] = field(default_factory=set)


def state_updater(
    state: CreatedAndReviewedState, principal_id: str, action: str, resource_id: str
) -> CreatedAndReviewedState:
    created = state.created.copy()
    reviewed = state.reviewed.copy()

    if action in ["create_file", "create_pr"]:
        created.add(f"{principal_id}:{resource_id}")

    if action == "review_pr":
        reviewed.add(f"{principal_id}:{resource_id}")

    return CreatedAndReviewedState(created=created, reviewed=reviewed)


def context_builder(
    state: CreatedAndReviewedState, principal_id: str, resource_id: str
) -> dict:
    return {
        "created": list(state.created),
        "reviewed": list(state.reviewed),
        "access_key": f"{principal_id}:{resource_id}",
        "has_other_reviewers": any(
            r.endswith(f":{resource_id}") and not r.startswith(f"{principal_id}:")
            for r in state.reviewed
        ),
    }

policy = """
permit(
    principal,
    action,
    resource
) when {
    context.created.contains(context.access_key) &&
    context.has_other_reviewers == true
};
"""


def build_created_and_reviewed() -> PolicyAuthorizer[CreatedAndReviewedState]:
    stateful_policy = StatefulPolicy(
        policy=policy,
        state_updater=state_updater,
        context_builder=context_builder,
    )
    return PolicyAuthorizer(
        stateful_policy,
        CreatedAndReviewedState(created=set(), reviewed=set()),
    )