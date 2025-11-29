from dataclasses import dataclass, asdict
from typing import Callable, Tuple, List
import subprocess
import json
import time


type Action = str


@dataclass
class StatefulPolicy[State]:
    policy: str
    state_updater: Callable[[State, str, str, str], State]  # (state, principal_id, action, resource_id)


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
        start_time = time.perf_counter()

        # prepare args to cedar
        principal = f'User::"{principal_id}"'
        cedar_action = f'Action::"{action}"'
        resource = f'Resource::"{resource_id}"'
        
        # build context from state
        context = json.dumps(asdict(self.state))
        
        # call cargo run to get cedar output
        cmd = [
            'cargo', 'run', '--',
            '--principal', principal,
            '--action', cedar_action,
            '--resource', resource,
            '--policy', self.stateful_policy.policy,
            '--context', context,
            '--entities', '[]'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.strip()
            permit = 'Allow' in output
            reasons = [output]
            
        except subprocess.CalledProcessError as e:
            permit = False
            reasons = [f"Cedar error: {e.stderr}"]
        
        eval_time_ms = (time.perf_counter() - start_time) * 1000
        
        # update state if permitted
        if permit:
            self.state = self.stateful_policy.state_updater(self.state, principal_id, action, resource_id)
        
        return permit, reasons, eval_time_ms
