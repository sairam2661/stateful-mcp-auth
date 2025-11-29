from dataclasses import dataclass
from typing import List, Dict
from policy_auth import PolicyAuthorizer, StatefulPolicy


@dataclass
class CreatedAndReviewedState:
    # Map from principal_id to list of resources they created
    created_by_principal: Dict[str, List[str]]
    # Map from resource_id to list of principals who reviewed it
    reviewed_by: Dict[str, List[str]]


def state_updater(state: CreatedAndReviewedState, principal_id: str, action: str, resource_id: str) -> CreatedAndReviewedState:
    # Track creation and reviews
    created = state.created_by_principal.copy()
    reviewed = state.reviewed_by.copy()
    
    if action in ["create_file", "create_pr"]:
        if principal_id not in created:
            created[principal_id] = []
        created[principal_id] = created[principal_id] + [resource_id]
    
    if action == "review_pr":
        if resource_id not in reviewed:
            reviewed[resource_id] = []
        reviewed[resource_id] = reviewed[resource_id] + [principal_id]
    
    return CreatedAndReviewedState(created_by_principal=created, reviewed_by=reviewed)


policy = """
permit(
    principal,
    action,
    resource
) when {
    context.created_by_principal.has(principal) &&
    context.created_by_principal[principal].contains(resource) &&
    context.reviewed_by.has(resource) &&
    context.reviewed_by[resource].containsAny([principal]) == false
};
"""


def build_created_and_reviewed() -> PolicyAuthorizer[CreatedAndReviewedState]:
    stateful_policy = StatefulPolicy(policy=policy, state_updater=state_updater)
    return PolicyAuthorizer(
        stateful_policy,
        CreatedAndReviewedState(created_by_principal={}, reviewed_by={})
    )
