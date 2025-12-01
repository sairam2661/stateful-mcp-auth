from dataclasses import dataclass, field
from typing import Set
from policy_auth import PolicyAuthorizer, StatefulPolicy


@dataclass
class WriteAtMostOnceState:
    written: Set[str] = field(default_factory=set)


def state_updater(
    state: WriteAtMostOnceState, principal_id: str, action: str, resource_id: str
) -> WriteAtMostOnceState:
    if action in ["write_file", "edit_file"]:
        new_written = state.written.copy()
        new_written.add(f"{principal_id}:{resource_id}")
        return WriteAtMostOnceState(written=new_written)
    return state


def context_builder(
    state: WriteAtMostOnceState, principal_id: str, resource_id: str
) -> dict:
    return {
        "written": list(state.written),
        "access_key": f"{principal_id}:{resource_id}",
    }


policy = """
permit(
    principal,
    action,
    resource
) when {
    action != Action::"write_file" && action != Action::"edit_file"
};

permit(
    principal,
    action,
    resource
) when {
    (action == Action::"write_file" || action == Action::"edit_file") &&
    context.written.contains(context.access_key) == false
};
"""


def build_write_at_most_once() -> PolicyAuthorizer[WriteAtMostOnceState]:
    stateful_policy = StatefulPolicy(
        policy=policy,
        state_updater=state_updater,
        context_builder=context_builder,
    )
    return PolicyAuthorizer(
        stateful_policy,
        WriteAtMostOnceState(written=set()),
    )