from dataclasses import dataclass
from typing import List, Dict
from policy_auth import PolicyAuthorizer, StatefulPolicy


@dataclass
class AccessOnlyCreatedState:
    # Map from principal_id to list of resources they created
    created_by_principal: Dict[str, List[str]]


def state_updater(state: AccessOnlyCreatedState, principal_id: str, action: str, resource_id: str) -> AccessOnlyCreatedState:
    # Track when principals create resources
    if action in ["create_file", "create_pr"]:
        created = state.created_by_principal.copy()
        if principal_id not in created:
            created[principal_id] = []
        created[principal_id] = created[principal_id] + [resource_id]
        return AccessOnlyCreatedState(created_by_principal=created)
    return state


policy = """
permit(
    principal,
    action,
    resource
) when {
    context.created_by_principal.has(principal) &&
    context.created_by_principal[principal].contains(resource)
};
"""


def build_access_only_created() -> PolicyAuthorizer[AccessOnlyCreatedState]:
    stateful_policy = StatefulPolicy(policy=policy, state_updater=state_updater)
    return PolicyAuthorizer(
        stateful_policy, 
        AccessOnlyCreatedState(created_by_principal={})
    )
