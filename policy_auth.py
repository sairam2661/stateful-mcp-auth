from dataclasses import dataclass, asdict, field
from typing import Callable, Tuple, List, Optional, Dict
import subprocess
import json
import time

type Action = str

@dataclass
class TimingBreakdown:
    context_build_us: float = 0.0        # Python: state -> context conversion
    subprocess_overhead_us: float = 0.0  # Python: subprocess call overhead
    cedar_parse_policy_us: float = 0.0   # Rust: parse policy
    cedar_parse_context_us: float = 0.0  # Rust: parse context JSON
    cedar_parse_entities_us: float = 0.0 # Rust: parse entities
    cedar_build_request_us: float = 0.0  # Rust: build request
    cedar_authorization_us: float = 0.0  # Rust: actual authorization
    cedar_total_us: float = 0.0          # Rust: total time in Cedar
    state_update_us: float = 0.0         # Python: state updater δ
    total_us: float = 0.0                # Total end-to-end

    def to_dict(self) -> Dict[str, float]:
        return {
            "context_build_us": self.context_build_us,
            "subprocess_overhead_us": self.subprocess_overhead_us,
            "cedar_parse_policy_us": self.cedar_parse_policy_us,
            "cedar_parse_context_us": self.cedar_parse_context_us,
            "cedar_parse_entities_us": self.cedar_parse_entities_us,
            "cedar_build_request_us": self.cedar_build_request_us,
            "cedar_authorization_us": self.cedar_authorization_us,
            "cedar_total_us": self.cedar_total_us,
            "state_update_us": self.state_update_us,
            "total_us": self.total_us,
        }

    def to_ms_dict(self) -> Dict[str, float]:
        return {k: v / 1000.0 for k, v in self.to_dict().items()}


@dataclass
class StatefulPolicy[State]:
    policy: str
    state_updater: Callable[[State, str, str, str], State]
    context_builder: Optional[Callable[[State, str, str], dict]] = None


class PolicyAuthorizer[State]:
    def __init__(self, stateful_policy: StatefulPolicy[State], initial_state: State):
        self.state = initial_state
        self.stateful_policy = stateful_policy

    def authorize(
        self,
        principal_id: str,
        action: str,
        resource_id: str,
    ) -> Tuple[bool, List[str], float]:
        permit, reasons, timing = self.authorize_with_timing(principal_id, action, resource_id)
        return permit, reasons, timing.total_us / 1000.0

    def authorize_with_timing(
        self,
        principal_id: str,
        action: str,
        resource_id: str,
    ) -> Tuple[bool, List[str], TimingBreakdown]:
        timing = TimingBreakdown()
        total_start = time.perf_counter()

        principal = f'User::"{principal_id}"'
        cedar_action = f'Action::"{action}"'
        resource = f'Resource::"{resource_id}"'

        context_start = time.perf_counter()
        if self.stateful_policy.context_builder:
            context = json.dumps(self.stateful_policy.context_builder(
                self.state, principal_id, resource_id
            ))
        else:
            context = json.dumps(asdict(self.state))
        timing.context_build_us = (time.perf_counter() - context_start) * 1_000_000

        cmd = [
            'cargo', 'run', '--quiet', '--',
            '--principal', principal,
            '--action', cedar_action,
            '--resource', resource,
            '--policy', self.stateful_policy.policy,
            '--context', context,
            '--entities', '[]',
            '--timing'
        ]

        subprocess_start = time.perf_counter()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            subprocess_total = (time.perf_counter() - subprocess_start) * 1_000_000

            output = result.stdout.strip()
            cedar_timing = json.loads(output)

            permit = cedar_timing['decision'] == 'Allow'
            reasons = [cedar_timing['decision']]

            # Extract timings
            timing.cedar_parse_policy_us = cedar_timing['parse_policy_us']
            timing.cedar_parse_context_us = cedar_timing['parse_context_us']
            timing.cedar_parse_entities_us = cedar_timing['parse_entities_us']
            timing.cedar_build_request_us = cedar_timing['build_request_us']
            timing.cedar_authorization_us = cedar_timing['authorization_us']
            timing.cedar_total_us = cedar_timing['total_us']

            timing.subprocess_overhead_us = subprocess_total - timing.cedar_total_us

        except subprocess.CalledProcessError as e:
            permit = False
            reasons = [f"Cedar error: {e.stderr}"]
            timing.subprocess_overhead_us = (time.perf_counter() - subprocess_start) * 1_000_000

        if permit:
            state_start = time.perf_counter()
            self.state = self.stateful_policy.state_updater(
                self.state, principal_id, action, resource_id
            )
            timing.state_update_us = (time.perf_counter() - state_start) * 1_000_000

        timing.total_us = (time.perf_counter() - total_start) * 1_000_000

        return permit, reasons, timing