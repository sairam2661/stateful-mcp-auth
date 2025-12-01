from vllm import LLM, SamplingParams
import torch
import json
import re
from datetime import datetime

N = 100
MODEL = "meta-llama/Llama-3.1-8B-Instruct"

prompt_template = """You are generating a Cedar authorization policy for an MCP (Model Context Protocol) server.

The server tracks state in a context object. Your policy should use this context to make authorization decisions.

## Task: {task_name}

{task_description}

## Available Context Fields:
{context_fields}

## Examples of Cedar Policy Syntax:
```cedar
// Permit if a condition is true
permit(principal, action, resource) when {{
    context.some_field.contains(context.some_key)
}};

// Permit specific actions unconditionally  
permit(principal, action, resource) when {{
    action == Action::"read"
}};

// Deny with negation
permit(principal, action, resource) when {{
    context.blocked.contains(context.key) == false
}};
```

## Your Task:
Write a Cedar policy for: {task_name}

Output ONLY the Cedar policy, nothing else. Do not include explanations or markdown code blocks."""

tasks = {
    "access_only_created": {
        "task_name": "access_only_created",
        "task_description": "Only permit access to resources that the principal created. If the principal did not create the resource, deny access.",
        "context_fields": """- context.allowed: List of "principal:resource" pairs that have been created
- context.access_key: String "principal:resource" for current request""",
    },
    "write_at_most_once": {
        "task_name": "write_at_most_once",
        "task_description": "Permit all non-write actions. For write actions (write_file, edit_file), only permit if the principal has NOT already written to this resource.",
        "context_fields": """- context.written: List of "principal:resource" pairs that have been written
- context.access_key: String "principal:resource" for current request""",
    },
    "created_and_reviewed": {
        "task_name": "created_and_reviewed",
        "task_description": "Only permit if the principal created the resource AND someone OTHER than the principal has reviewed it.",
        "context_fields": """- context.created: List of "principal:resource" pairs that have been created
- context.access_key: String "principal:resource" for current request
- context.has_other_reviewers: Boolean, true if someone other than principal reviewed this resource""",
    }
}


def extract_cedar_policy(text: str) -> str:
    """Extract Cedar policy from LLM output, removing markdown if present."""
    text = re.sub(r'```cedar\n?', '', text)
    text = re.sub(r'```\n?', '', text)
    return text.strip()


def main():
    print("=" * 80)
    print("Q2: LLM Policy Generation")
    print("=" * 80)
    print(f"Model: {MODEL}")
    print(f"Samples per task: {N}")
    print()

    # Initialize LLM
    llm = LLM(model=MODEL)
    sampling_params = SamplingParams(
        temperature=0.7,
        max_tokens=300,
        n=N
    )

    results = {
        "metadata": {
            "model": MODEL,
            "n_samples": N,
            "temperature": 0.7,
            "timestamp": datetime.now().isoformat(),
        },
        "tasks": {}
    }

    for task_name, task_config in tasks.items():
        print(f"\nGenerating for: {task_name}")

        prompt = prompt_template.format(**task_config)

        outputs = llm.generate([prompt], sampling_params)

        policies = []
        for i, output in enumerate(outputs[0].outputs, 1):
            policy_text = extract_cedar_policy(output.text)
            policies.append({
                "id": i,
                "raw_output": output.text,
                "policy": policy_text,
            })
            print(f"  Generated policy {i}/{N}")

        results["tasks"][task_name] = {
            "prompt": prompt,
            "policies": policies,
        }

    # Save results
    output_file = f"generated_policies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n\nSaved {N * len(tasks)} policies to {output_file}")

    # Cleanup
    del llm
    torch.cuda.empty_cache()

    return output_file


if __name__ == "__main__":
    main()