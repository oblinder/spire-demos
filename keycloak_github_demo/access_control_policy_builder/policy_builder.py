#!/usr/bin/env python3
"""
Policy Builder using LangGraph
Generates access_control_policy.yaml from natural language descriptions.
"""

import re
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from operator import add
import yaml
from pathlib import Path

from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.language_models import BaseChatModel

from llm_config import llm as default_llm


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from config file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def extract_realm_roles_and_clients(config: Dict[str, Any]) -> tuple[List[str], Dict[str, List[str]], Dict[str, List[str]]]:
    """
    Extract realm roles, clients with their roles, and client call chains from config.
    
    Returns:
        Tuple of (realm_roles, client_roles_map, client_audience_targets)
        where client_roles_map is {client_name: [role1, role2, ...]}
    """
    realm_roles = config.get('realm_roles', [])
    
    # Extract client names and their roles from clients list
    clients = config.get('clients', [])
    client_roles_map = {}
    for client in clients:
        if 'client_id' in client:
            client_id = client['client_id']
            roles = client.get('roles', [])
            client_roles_map[client_id] = roles
    
    # Extract client audience targets (call chains)
    client_audience_targets = config.get('client_audience_targets', {})
    
    return realm_roles, client_roles_map, client_audience_targets


class PolicyState(TypedDict):
    """State for the policy building graph."""
    description: str
    explanation: str
    parsed_scopes: List[Dict[str, Any]]
    policy_structure: Dict[str, Any]
    yaml_output: str
    messages: Annotated[List, add]
    errors: Annotated[List[str], add]


class PolicyBuilder:
    """Build access control policies using LangGraph."""
    
    def __init__(self, config_path: Path, llm: Optional[BaseChatModel] = None):
        """
        Initialize the policy builder with an LLM.
        
        Args:
            config_path: Path to config file for extracting realm roles and scopes (required).
            llm: Optional LangChain LLM instance. If not provided, uses the global
                 LLM from llm_config.py.
        """
        # Use provided LLM or default from llm_config.py
        self.llm = llm if llm is not None else default_llm
        
        # Load config and extract realm roles, client roles map, and call chains
        self.config = load_config(config_path)
        self.realm_roles, self.client_roles_map, self.client_audience_targets = extract_realm_roles_and_clients(self.config)
        
        # Build flat list of client names for backward compatibility
        self.client_names = list(self.client_roles_map.keys())
        
        self.graph = self._build_graph()
    
    def _build_system_prompt(self) -> str:
        """
        Build the system prompt for the LLM with context from the configuration.
        
        Returns:
            Formatted system prompt string with available roles, clients, and call chains.
        """
        # Build available roles list
        available_roles = "\n".join([f"  - {role}" for role in self.realm_roles]) if self.realm_roles else "  (none defined)"
        
        # Build client roles information
        client_roles_info = []
        for client_name, roles in self.client_roles_map.items():
            if roles:
                client_roles_info.append(f"  - {client_name}: {', '.join(roles)}")
        client_roles_str = "\n".join(client_roles_info) if client_roles_info else "  (no client roles defined)"
        
        # Build call chain information
        call_chains = []
        for client, targets in self.client_audience_targets.items():
            if targets:
                call_chains.append(f"  - {client} can call: {', '.join(targets)}")
        call_chain_info = "\n".join(call_chains) if call_chains else "  (no call chains defined)"
        
        return f"""You are an expert at mapping access control policy descriptions to predefined user roles and application clients as defined in Keycloak.

CRITICAL REQUIREMENTS:
1. Use ONLY the preset names listed below - no modifications, no new names
2. Map natural language descriptions to the appropriate preset role, client, and client role names
3. Each realm role should specify which client roles from which clients users with that role need
4. Consider the client call chains when determining which clients a role needs access to
5. IMPORTANT: If a user needs access to a tool, they MUST get access to the COMPLETE call chain from the entry point
   - Example: If the call chain is UI → Agent → Tool, and a user needs the Tool, they need access to UI, Agent, AND Tool
   - Users need access to EVERY client in the complete path, starting from the first entry point (typically a UI client)
   - ALWAYS include the entry point client (e.g., demo-ui) when users need access to any downstream tool or agent
6. IMPORTANT: Assign EVERY relevant client roles that match the access requirements

Available realm roles (user roles - use ONLY these exact names):
{available_roles}

Available clients with their roles:
{client_roles_str}

Client call chains (which clients can call which other clients):
{call_chain_info}

IMPORTANT CALL CHAIN RULES:
- When mapping roles to clients, include ALL clients in the COMPLETE call chain path from the entry point to the final tool
- Trace the call chain BACKWARDS from the tool to find ALL clients that need to be included, including the entry point
- For each client in the chain, you must specify which specific client role(s) from that client the realm role should have
- If a user needs access to a tool at the end of a chain, they need access to EVERY client in the path
- This ensures the complete call chain works properly from the user's entry point through all intermediate agents to the final tool

IMPORTANT ROLE ASSIGNMENT RULES:
- Assign ALL client roles that are relevant to the described access level
- If comprehensive or broad access is described (e.g., "both X and Y", "all", "full"), include ALL applicable roles for that client
- If limited or specific access is described (e.g., "only X", "just Y"), include only the relevant subset of roles
- Each role should be explicitly assigned - don't rely on implicit role hierarchies
- IMPORTANT: When a user needs access to multiple types of resources (e.g., "both private and public"), assign ALL corresponding roles separately

IMPORTANT ROLE MAPPING RULES:
- When the policy uses broad terms like "other personnel", "other staff", "other users", or "everyone else", map to ALL realm roles not already mapped
- Do not exclude any realm roles unless explicitly stated in the policy
- Be inclusive rather than exclusive when interpreting broad category terms

TASK:
1. Carefully analyze the policy description
2. Extract and map natural language terms to preset role, client, and client role names
3. For each realm role, identify ALL clients in the complete call chain path and which specific client roles they need
4. Ensure all intermediate agents are included for anyone who needs tool access
5. Assign ALL relevant client roles based on the access level described:
   - For comprehensive access (e.g., "both X and Y"), assign ALL applicable roles
   - For limited access (e.g., "only X"), assign only the specific roles mentioned
6. When broad terms are used (like "other personnel"), ensure ALL applicable realm roles are included
7. Provide a brief explanation of your mapping logic, especially how you handled the call chain and role assignments
8. Return the JSON mappings

Return in this format:
```explanation
[Your brief explanation of how you mapped the natural language to preset names, including call chain and role assignment considerations]
```

```json
[
  {{
    "role": "exact-preset-realm-role-name",
    "client_roles": [
      {{"client": "client-name", "role": "client-role-name"}},
      {{"client": "client-name", "role": "another-client-role-name"}}
    ]
  }}
]
```
"""
    
    def _build_retry_prompt(self) -> str:
        """
        Build a retry prompt when initial parsing fails.
        
        Returns:
            Formatted retry prompt string.
        """
        client_roles_summary = []
        for client, roles in self.client_roles_map.items():
            client_roles_summary.append(f"{client}: {', '.join(roles)}")
        
        return f"""The previous response could not be parsed as valid JSON.

Please provide the mapping again using ONLY these preset names:
- Realm roles: {", ".join(self.realm_roles) if self.realm_roles else "(none)"}
- Clients with roles: {"; ".join(client_roles_summary) if client_roles_summary else "(none)"}

Remember: Each realm role should specify which client roles from which clients users need.

Return in this format:
```explanation
[Your brief explanation]
```

```json
[
  {{
    "role": "exact-preset-realm-role-name",
    "client_roles": [
      {{"client": "client-name", "role": "client-role-name"}}
    ]
  }}
]
```"""
    
    def _extract_explanation_and_json(self, content: str) -> tuple[str, list]:
        """
        Extract explanation and JSON from formatted LLM output.
        
        Handles markdown code blocks (```json ... ```) and plain JSON.
        
        Args:
            content: Raw LLM response content
            
        Returns:
            Tuple of (explanation, parsed_json_list)
        """
        import json
        
        explanation = ""
        
        # Try to extract explanation from code block
        explanation_match = re.search(r'```explanation\s*([\s\S]*?)\s*```', content)
        if explanation_match:
            explanation = explanation_match.group(1).strip()
        else:
            # Try to extract explanation from markdown heading or bold text before JSON
            # Look for text before the first JSON code block
            json_start = re.search(r'```json', content)
            if json_start:
                pre_json_text = content[:json_start.start()].strip()
                # Remove markdown formatting
                pre_json_text = re.sub(r'\*\*([^*]+)\*\*', r'\1', pre_json_text)
                if pre_json_text and len(pre_json_text) > 10:  # Only use if substantial
                    explanation = pre_json_text
        
        # Try markdown code blocks for JSON
        code_block_patterns = [
            r'```json\s*([\s\S]*?)\s*```',  # ```json ... ```
            r'```\s*([\s\S]*?)\s*```',       # ``` ... ```
        ]
        
        for pattern in code_block_patterns:
            match = re.search(pattern, content)
            if match:
                try:
                    return explanation, json.loads(match.group(1).strip())
                except json.JSONDecodeError:
                    continue
        
        # Try plain JSON as fallback
        try:
            return explanation, json.loads(content.strip())
        except json.JSONDecodeError:
            return explanation, []
    
    def _print_explanation(self, explanation: str, is_retry: bool = False):
        """
        Print the LLM explanation in a formatted box.
        
        Args:
            explanation: The explanation text to print
            is_retry: Whether this is from a retry attempt
        """
        if explanation:
            print("\n" + "=" * 80)
            print(f"LLM Explanation{' (Retry)' if is_retry else ''}:")
            print("=" * 80)
            print(explanation)
            print("=" * 80 + "\n")
    
    def _build_graph(self):
        """Build the LangGraph state machine for policy generation."""
        workflow = StateGraph(PolicyState)
        
        # Add nodes
        workflow.add_node("parse_and_extract", self._parse_and_extract_scopes)
        workflow.add_node("build_policy", self._build_policy)
        workflow.add_node("generate_yaml", self._generate_yaml)
        workflow.add_node("validate_policy", self._validate_policy)
        
        # Define edges
        workflow.set_entry_point("parse_and_extract")
        workflow.add_edge("parse_and_extract", "build_policy")
        workflow.add_edge("build_policy", "generate_yaml")
        workflow.add_edge("generate_yaml", "validate_policy")
        workflow.add_edge("validate_policy", END)
        
        return workflow.compile()
    
    def _parse_and_extract_scopes(self, state: PolicyState) -> PolicyState:
        """
        Unified function to parse description and extract scopes from formatted LLM output.
        Handles markdown code blocks (```json ... ```) and plain JSON.
        Retries once on failure, then raises an exception.
        """
        import json
        
        # Build prompts using helper functions
        system_prompt = self._build_system_prompt()
        user_prompt = f"Parse this policy description and map it to the preset role and scope names:\n\n{state['description']}"
        
        # First attempt
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        
        response = self.llm.invoke(messages)
        content = response.content if isinstance(response.content, str) else str(response.content)
        explanation, parsed_scopes = self._extract_explanation_and_json(content)
        
        # Print explanation if available
        self._print_explanation(explanation)
        
        # Retry once if parsing failed
        if not parsed_scopes:
            retry_prompt = self._build_retry_prompt()
            
            retry_messages = [
                *messages,
                response,
                HumanMessage(content=retry_prompt)
            ]
            
            retry_response = self.llm.invoke(retry_messages)
            retry_content = retry_response.content if isinstance(retry_response.content, str) else str(retry_response.content)
            explanation, parsed_scopes = self._extract_explanation_and_json(retry_content)
            
            # Print retry explanation if available
            self._print_explanation(explanation, is_retry=True)
            
            # If still failed after retry, raise exception
            if not parsed_scopes:
                raise ValueError(
                    f"Failed to parse valid JSON from LLM response after retry.\n"
                    f"Last response: {retry_content[:500]}..."
                )
        
        return {
            **state,
            "explanation": explanation,
            "parsed_scopes": parsed_scopes,
            "messages": [*state.get("messages", []), response],
            "errors": list(state.get("errors", []))
        }
    
    def _build_policy(self, state: PolicyState) -> PolicyState:
        """Build the policy structure from extracted role-to-client-role mappings."""
        policy = {}
        
        for role_info in state["parsed_scopes"]:
            role_name = role_info.get("role", "")
            client_roles = role_info.get("client_roles", [])
            
            # Use names exactly as provided - no modifications
            # Format: list of {client: "name", role: "role"}
            policy[role_name] = client_roles
        
        policy_structure = {
            "policy": policy
        }
        
        return {
            **state,
            "policy_structure": policy_structure
        }
    
    def _generate_yaml(self, state: PolicyState) -> PolicyState:
        """Generate YAML output from the policy structure."""
        # Create header comments
        header = """# Access Control Policy
# Maps user roles (realm roles) to specific client roles
# Client roles are defined as {client_name}-{role} based on config.yaml
# Format: user_role_name -> list of client role mappings
# Each entry specifies: client (client name) and role (role name from that client)
# You CAN map a realm role to multiple roles of the same client by listing them separately

"""
        
        # Add original policy description as comment
        if state.get("description"):
            description_lines = state["description"].strip().split('\n')
            header += "# Original Policy Description:\n"
            for line in description_lines:
                header += f"#   {line.strip()}\n"
            header += "#\n"
        
        # Add LLM explanation as comment
        if state.get("explanation"):
            explanation_lines = state["explanation"].strip().split('\n')
            header += "# LLM Mapping Explanation:\n"
            for line in explanation_lines:
                header += f"#   {line.strip()}\n"
            header += "\n"
        
        # Generate YAML
        yaml_content = yaml.dump(
            state["policy_structure"],
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True
        )
        
        # Add footer
        footer = "\n# Generated by PolicyBuilder using LangGraph\n"
        
        yaml_output = header + yaml_content + footer
        
        return {
            **state,
            "yaml_output": yaml_output
        }
    
    def _validate_policy(self, state: PolicyState) -> PolicyState:
        """Validate the generated policy structure."""
        errors = []
        
        policy = state["policy_structure"].get("policy", {})
        
        if not policy:
            errors.append("Policy is empty")
        
        # Validate that only preset names are used
        for realm_role, client_role_mappings in policy.items():
            if not realm_role:
                errors.append("Found empty realm role name")
            elif realm_role not in self.realm_roles:
                errors.append(f"Realm role '{realm_role}' is not in the preset realm roles. Available roles: {', '.join(self.realm_roles)}")
            
            if not client_role_mappings:
                errors.append(f"Realm role '{realm_role}' has no client role mappings assigned")
            
            for mapping in client_role_mappings:
                if not isinstance(mapping, dict):
                    errors.append(f"Invalid mapping format in realm role '{realm_role}': must be a dict with 'client' and 'role' keys")
                    continue
                
                client = mapping.get('client', '')
                role = mapping.get('role', '')
                
                if not client:
                    errors.append(f"Found empty client name in realm role '{realm_role}'")
                elif client not in self.client_names:
                    errors.append(f"Client '{client}' in realm role '{realm_role}' is not in the preset client names. Available clients: {', '.join(self.client_names)}")
                
                if not role:
                    errors.append(f"Found empty role name for client '{client}' in realm role '{realm_role}'")
                elif client in self.client_roles_map and role not in self.client_roles_map[client]:
                    available_roles = ', '.join(self.client_roles_map[client]) if self.client_roles_map[client] else '(none)'
                    errors.append(f"Role '{role}' for client '{client}' in realm role '{realm_role}' is not valid. Available roles for {client}: {available_roles}")
        
        return {
            **state,
            "errors": [*state.get("errors", []), *errors]
        }
    
    def generate_policy(self, description: str) -> Dict[str, Any]:
        """
        Generate an access control policy from a text description.
        
        Args:
            description: Natural language description of the policy
            
        Returns:
            Dictionary containing the generated policy and metadata
        """
        initial_state: PolicyState = {
            "description": description,
            "explanation": "",
            "parsed_scopes": [],
            "policy_structure": {},
            "yaml_output": "",
            "messages": [],
            "errors": []
        }
        
        final_state = self.graph.invoke(initial_state)
        
        return {
            "yaml_output": final_state["yaml_output"],
            "policy_structure": final_state["policy_structure"],
            "parsed_scopes": final_state["parsed_scopes"],
            "errors": final_state["errors"],
            "success": len(final_state["errors"]) == 0
        }
    
    def save_policy(self, yaml_output: str, filepath: str = "access_control_policy.yaml"):
        """Save the generated policy to a file."""
        with open(filepath, 'w') as f:
            f.write(yaml_output)
        print(f"Policy saved to {filepath}")


def main(policy_file: Path, config_path: Path, output_file: str):
    """
    Generate access control policy from policy text file and config file.
    
    Args:
        policy_file: Path to text file containing natural language description of the access control policy.
        config_path: Path to config file containing realm roles and client scopes.
        output_file: Path to output YAML file for the generated policy.
    """
    # Read policy text from file
    if not policy_file.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_file}")
    
    with open(policy_file, 'r') as f:
        policy_text = f.read().strip()
    
    # Initialize builder
    builder = PolicyBuilder(config_path=config_path)
    
    # Process policy text
    print("=" * 80)
    print("Generating policy from description...")
    print("=" * 80)
    print(f"\nPolicy file: {policy_file}")
    print(f"\nDescription:\n{policy_text}\n")
    
    result = builder.generate_policy(description=policy_text)
    
    if result["success"]:
        print("✓ Policy generated successfully!\n")
        print("Generated YAML:")
        print("-" * 80)
        print(result["yaml_output"])
        print("-" * 80)
        
        # Save to file
        builder.save_policy(result["yaml_output"], output_file)
    else:
        print("✗ Policy generation failed with errors:")
        for error in result["errors"]:
            print(f"  - {error}")
    
    print("\n" + "=" * 80)
    print("Parsed Role-to-Client-Role Mappings:")
    print("=" * 80)
    for role_mapping in result["parsed_scopes"]:
        realm_role = role_mapping['role']
        client_roles = role_mapping.get('client_roles', [])
        print(f"  {realm_role}:")
        for cr in client_roles:
            print(f"    - {cr['client']}: {cr['role']}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python policy_builder.py <policy_file.txt> <config.yaml> <output_file.yaml>", file=sys.stderr)
        print("Example: python policy_builder.py policy_description.txt config.yaml access_control_policy.yaml", file=sys.stderr)
        sys.exit(1)
    
    policy_file = Path(sys.argv[1])
    config_path = Path(sys.argv[2])
    output_file = sys.argv[3]
    
    if not policy_file.exists():
        print(f"Error: Policy file not found: {policy_file}", file=sys.stderr)
        sys.exit(1)
    
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    
    main(policy_file, config_path, output_file)

# Made with Bob
