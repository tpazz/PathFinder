import json
import re
import itertools
from copy import deepcopy

# The default path for storing user-taught attack path rules.
DEFAULT_RULES_FILE = "attack_rules.json"

class AttackPathSynthesizer:
    def __init__(self, rules_file_path=DEFAULT_RULES_FILE):
        """
        Initializes the synthesizer by loading rules from a specified file.

        Args:
            rules_file_path (str): The path to the JSON file containing attack rules.
        """
        self.rules_file_path = rules_file_path
        self.rules = self._load_rules()
        print(f"[*] Attack Path Synthesizer initialized with {len(self.rules)} rules from {self.rules_file_path}")

    def _load_rules(self):
        """Loads rules from the JSON file. Returns an empty list if not found or invalid."""
        try:
            with open(self.rules_file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Rules file '{self.rules_file_path}' not found. Starting with an empty ruleset.")
            return []
        except json.JSONDecodeError:
            print(f"[!] Error: Could not decode JSON from '{self.rules_file_path}'. Starting with an empty ruleset.")
            return []

    def _save_rules(self):
        """Saves the current ruleset to the JSON file."""
        try:
            with open(self.rules_file_path, 'w') as f:
                json.dump(self.rules, f, indent=4)
            print(f"[+] Rules successfully saved to '{self.rules_file_path}'.")
        except IOError as e:
            print(f"[!] Error: Could not write rules to file: {e}")

    def learn_new_path_interactive(self):
        """
        Guides the user through an interactive wizard to define and save a new attack path rule.
        """
        print("\n--- Teaching Pathfinder a New Attack Path ---")
        print("You will define 'triggers' (findings that must exist) and a 'suggestion' (what to do).")

        new_rule = {}
        try:
            # --- Rule Metadata ---
            new_rule['name'] = input("[?] What is a short, descriptive name for this attack path? (e.g., 'RCE via Writable Web-root and PHP')\n> ")
            new_rule['priority'] = int(input("[?] What priority should this have? (1-100, higher is more important)\n> "))
            
            # --- Triggers ---
            num_triggers = int(input("[?] How many trigger findings are needed for this path? (e.g., 2 for 'PHP' and 'writable upload dir')\n> "))
            triggers = []
            for i in range(num_triggers):
                print(f"\n--- Defining Trigger {i+1} ---")
                trigger = {}
                trigger['id'] = i + 1
                trigger['entity_type'] = input(f"[?] Trigger {i+1}: What is the entity_type? (e.g., software_product, web_content, misconfiguration)\n> ").strip()
                trigger['name_match'] = {}

                name_match_type = input(f"[?] Trigger {i+1}: How should the 'name' be matched? (exact, contains, regex) [default: exact]\n> ").strip().lower() or 'exact'
                name_match_value = input(f"[?] Trigger {i+1}: What 'name' value to match? (e.g., 'PHP', 'upload', 'ftp_anonymous_login_allowed')\n> ").strip()
                trigger['name_match']['type'] = name_match_type
                trigger['name_match']['value'] = name_match_value
                
                # Add more complex attribute matching here in the future
                triggers.append(trigger)
            new_rule['triggers'] = triggers
            
            # --- Suggestion ---
            print("\n--- Defining the Suggestion (what Pathfinder should output) ---")
            print("You can use placeholders like {trigger.1.host}, {trigger.1.port}, {trigger.2.name}, etc.")
            new_rule['suggestion'] = {
                'description': input("[?] Enter a one-line description for the suggested path:\n> "),
                'rationale': input("[?] Enter a rationale explaining WHY this works:\n> "),
                'commands': [],
                'references': []
            }
            while True:
                cmd = input("[?] Suggest a command to try (or press Enter to finish commands):\n> ")
                if not cmd: break
                new_rule['suggestion']['commands'].append(cmd)
            while True:
                ref = input("[?] Add a reference URL (or press Enter to finish references):\n> ")
                if not ref: break
                new_rule['suggestion']['references'].append(ref)

        except (ValueError, IndexError) as e:
            print(f"\n[!] Invalid input. Aborting. Error: {e}")
            return
        
        print("\n--- Review New Rule ---")
        print(json.dumps(new_rule, indent=2))
        confirm = input("[?] Does this look correct? (y/n)\n> ").lower()

        if confirm == 'y':
            self.rules.append(new_rule)
            self._save_rules()
        else:
            print("[!] Aborted. Rule not saved.")

    def _check_finding_against_trigger(self, finding, trigger):
        """Checks if a single finding satisfies a single trigger's conditions."""
        if finding.get('entity_type') != trigger.get('entity_type'):
            return False

        match_type = trigger['name_match']['type']
        match_value = trigger['name_match']['value']
        finding_name = finding.get('name', '')

        if match_type == 'exact' and finding_name.lower() != match_value.lower():
            return False
        if match_type == 'contains' and match_value.lower() not in finding_name.lower():
            return False
        if match_type == 'regex' and not re.search(match_value, finding_name, re.IGNORECASE):
            return False
            
        # If all checks pass
        return True

    def _format_suggestion(self, suggestion_template, matched_findings):
        """Replaces placeholders in the suggestion text with actual finding data."""
        formatted_suggestion = deepcopy(suggestion_template) # Work on a copy
        text_to_format = json.dumps(formatted_suggestion) # Format everything at once

        # Find all placeholders like {trigger.1.name}
        placeholders = re.findall(r'(\{trigger\.(\d+)\.(\w+)\})', text_to_format)
        
        for placeholder_full, trigger_id_str, attr_name in placeholders:
            trigger_id = int(trigger_id_str)
            # Find the finding that corresponds to this trigger ID
            # Assumes matched_findings is an ordered list where index = trigger_id - 1
            if 0 < trigger_id <= len(matched_findings):
                finding = matched_findings[trigger_id - 1]
                # Get the value from the finding, checking top-level keys first, then attributes
                value = finding.get(attr_name, finding.get('attributes', {}).get(attr_name, ''))
                text_to_format = text_to_format.replace(placeholder_full, str(value))

        return json.loads(text_to_format)

    def generate_attack_paths(self, prioritized_findings):
        """
        Analyzes prioritized findings against the loaded rules to generate suggested attack paths.

        Args:
            prioritized_findings (list): A list of finding dictionaries.

        Returns:
            list: A list of suggested attack path dictionaries.
        """
        suggested_paths = []

        for rule in self.rules:
            # 1. Find candidate findings for each trigger in the rule
            candidate_lists = []
            for trigger in rule['triggers']:
                candidates_for_trigger = [
                    finding for finding in prioritized_findings 
                    if self._check_finding_against_trigger(finding, trigger)
                ]
                if not candidates_for_trigger:
                    candidate_lists = [] # If any trigger has no candidates, this rule can't match
                    break
                candidate_lists.append(candidates_for_trigger)

            if not candidate_lists:
                continue

            # 2. Find all combinations of candidates that satisfy the rule's relationships
            # `itertools.product` creates all possible pairings from the candidate lists.
            for combination in itertools.product(*candidate_lists):
                # Basic relationship check: all findings must be on the same host.
                # More complex relationships (e.g., path logic) can be added here.
                first_host = combination[0].get('host')
                if all(finding.get('host') == first_host for finding in combination):
                    # We have a valid match!
                    
                    # 3. Format the suggestion with data from the matched findings
                    final_suggestion = self._format_suggestion(rule['suggestion'], combination)
                    
                    # 4. Assemble the final attack path object
                    attack_path = {
                        "name": rule['name'],
                        "priority": rule['priority'],
                        "host": first_host,
                        "suggestion": final_suggestion,
                        "evidence": [f"Trigger {i+1} matched by: {f.get('name')} ({f.get('entity_type')})" for i, f in enumerate(combination)]
                    }
                    suggested_paths.append(attack_path)

        # Sort final paths by priority, highest first
        suggested_paths.sort(key=lambda x: x.get('priority', 0), reverse=True)
        return suggested_paths

# --- Example Usage (for standalone testing of this script) ---
if __name__ == '__main__':
    # 1. Initialize the synthesizer. This will load 'attack_rules.json' if it exists.
    synthesizer = AttackPathSynthesizer()
    
    # 2. To teach a new rule, you would call this from your main script based on a command-line arg.
    # For this test, we'll uncomment it to run it once.
    # synthesizer.learn_new_path_interactive()

    # 3. Create some dummy prioritized findings (this would come from VulnerabilityMapper)
    sample_prioritized_findings = [
        {
            "host": "10.10.10.5", "port": 80, "source_tool": "nmap",
            "entity_type": "software_product", "name": "PHP", "version": "8.1"
        },
        {
            "host": "10.10.10.5", "port": 80, "source_tool": "gobuster",
            "entity_type": "web_content", "name": "/main_site/uploads/",
            "attributes": {"status_code": 200, "is_writable_guess": True} # Assume mapper added this
        },
        {
            "host": "10.10.10.6", "port": 21, "source_tool": "nmap",
            "entity_type": "misconfiguration", "name": "ftp_anonymous_login_allowed"
        }
    ]

    print("\n--- Generating Attack Paths from Sample Findings ---")
    # 4. Generate attack paths based on the rules and the findings
    found_paths = synthesizer.generate_attack_paths(sample_prioritized_findings)
    
    if found_paths:
        print(f"\n[+] Found {len(found_paths)} potential attack path(s)!")
        for i, path in enumerate(found_paths):
            print(f"\n--- Suggested Path {i+1} ---")
            print(f"Name: {path['name']} [Priority: {path['priority']}]")
            print(f"Host: {path['host']}")
            print("\n  Description:")
            print(f"    {path['suggestion']['description']}")
            print("\n  Rationale:")
            print(f"    {path['suggestion']['rationale']}")
            print("\n  Suggested Commands:")
            for cmd in path['suggestion']['commands']:
                print(f"    - {cmd}")
            if path['suggestion'].get('references'):
                 print("\n  References:")
                 for ref in path['suggestion']['references']:
                    print(f"    - {ref}")
            print("\n  Evidence:")
            for ev in path['evidence']:
                print(f"    - {ev}")
    else:
        print("\n[-] No attack paths were synthesized from the current rules and findings.")