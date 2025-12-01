from dataclasses import dataclass, field
from typing import Set
from policy_auth import PolicyAuthorizer, StatefulPolicy


@dataclass
class AccessOnlyCreatedState:
    allowed: Set[str] = field(default_factory=set)


def state_updater(
    state: AccessOnlyCreatedState, principal_id: str, action: str, resource_id: str
) -> AccessOnlyCreatedState:
    if action in ["create_file", "create_pr"]:
        new_allowed = state.allowed.copy()
        new_allowed.add(f"{principal_id}:{resource_id}")
        return AccessOnlyCreatedState(allowed=new_allowed)
    return state


def context_builder(state: AccessOnlyCreatedState, principal_id: str, resource_id: str) -> dict:
    return {
        "allowed": list(state.allowed),
        "access_key": f"{principal_id}:{resource_id}",
    }


policy = """
permit(
    principal,
    action,
    resource
) when {
    context.allowed.contains(context.access_key)
};
"""


def build_access_only_created() -> PolicyAuthorizer[AccessOnlyCreatedState]:
    stateful_policy = StatefulPolicy(
        policy=policy,
        state_updater=state_updater,
        context_builder=context_builder,
    )
    return PolicyAuthorizer(
        stateful_policy,
        AccessOnlyCreatedState(allowed=set()),
    )