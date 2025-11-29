from dataclasses import dataclass
from typing import List, Dict
from policy_auth import PolicyAuthorizer, StatefulPolicy


@dataclass
class WriteAtMostOnceState:
    # Map from principal_id to list of resources they wrote to
    written_by_principal: Dict[str, List[str]]


def state_updater(state: WriteAtMostOnceState, principal_id: str, action: str, resource_id: str) -> WriteAtMostOnceState:
    # Track when principals write or edit resources
    if action in ["write_file", "edit_file"]:
        written = state.written_by_principal.copy()
        if principal_id not in written:
            written[principal_id] = []
        written[principal_id] = written[principal_id] + [resource_id]
        return WriteAtMostOnceState(written_by_principal=written)
    return state


policy = """
permit(
    principal,
    action,
    resource
) when {
    !context.written_by_principal.has(principal) ||
    !context.written_by_principal[principal].contains(resource)
};
"""


def build_write_at_most_once() -> PolicyAuthorizer[WriteAtMostOnceState]:
    stateful_policy = StatefulPolicy(policy=policy, state_updater=state_updater)
    return PolicyAuthorizer(
        stateful_policy,
        WriteAtMostOnceState(written_by_principal={})
    )
