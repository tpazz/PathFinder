import json
import re
import itertools
from copy import deepcopy
import os

# Get the absolute path to the directory where this script is located.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Build a full, unambiguous path to the rules file, ensuring it's always found.
DEFAULT_RULES_FILE = os.path.join(SCRIPT_DIR, "attack_rules.json")

class C:
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class AttackPathSynthesizer:
    def __init__(self, rules_file_path=DEFAULT_RULES_FILE):
        self.rules_file_path = rules_file_path
        self.rules = self._load_rules()
        print(f"{C.BOLD}{C.CYAN}[*] Attack Path Synthesizer initialized with {len(self.rules)} rules from {self.rules_file_path}{C.END}")

    def _load_rules(self):
        try:
            with open(self.rules_file_path, 'r') as f:
                content = f.read()
                # Handle case where the JSON file is empty.
                if not content: return []
                return json.loads(content)
        except FileNotFoundError:
            print(f"{C.BOLD}{C.YELLOW}[!] Rules file '{self.rules_file_path}' not found. Starting with an empty ruleset.{C.END}")
            return []
        except json.JSONDecodeError:
            print(f"{C.BOLD}{C.YELLOW}[!] Warning: Could not decode JSON from '{self.rules_file_path}'. Starting with an empty ruleset.{C.END}")
            return []

    def _save_rules(self):
        try:
            with open(self.rules_file_path, 'w') as f:
                json.dump(self.rules, f, indent=4)
            print(f"{C.BOLD}{C.CYAN}[+]{C.END} Rules successfully saved to '{self.rules_file_path}'.")
        except IOError as e:
            print(f"{C.BOLD}{C.YELLOW}[!] Error: Could not write rules to file: {e}{C.END}")

    def learn_new_path_interactive(self):
        print("\n--- Teaching Pathfinder a New Attack Path ---")
        new_rule = {}
        try:
            new_rule['name'] = input("[?] Name for this attack path? > ")
            new_rule['priority'] = int(input("[?] Priority? (1-100) > "))
            num_triggers = int(input("[?] How many trigger findings? > "))
            triggers = []
            for i in range(num_triggers):
                print(f"\n--- Defining Trigger {i+1} ---")
                trigger = {'id': i + 1, 'name_match': {}}
                trigger['entity_type'] = input(f" > Trigger {i+1} entity_type? (e.g., software_product) > ").strip()
                trigger['name_match']['type'] = input(f" > Trigger {i+1} name match type? (exact, contains, regex) [exact] > ").strip().lower() or 'exact'
                trigger['name_match']['value'] = input(f" > Trigger {i+1} name match value? (e.g., PHP) > ").strip()
                triggers.append(trigger)
            new_rule['triggers'] = triggers
            print("\n--- Defining the Suggestion ---")
            new_rule['suggestion'] = {
                'description': input("> Description? > "),
                'rationale': input("> Rationale? > "), 'commands': [], 'references': [] }
            while True:
                cmd = input("> Suggested command (or Enter to finish)? > ")
                if not cmd: break
                new_rule['suggestion']['commands'].append(cmd)
            while True:
                ref = input("> Reference URL (or Enter to finish)? > ")
                if not ref: break
                new_rule['suggestion']['references'].append(ref)
        except (ValueError, IndexError) as e:
            print(f"\n{C.BOLD}{C.YELLOW}[!] Invalid input. Aborting. Error: {e}{C.END}")
            return
        
        print("\n--- Review New Rule ---\n", json.dumps(new_rule, indent=2))
        if input("[?] Save this rule? (y/n) > ").lower() == 'y':
            self.rules.append(new_rule)
            self._save_rules()
        else:
            print(f"{C.BOLD}{C.YELLOW}[!] Aborted. Rule not saved.{C.END}")

    def _check_finding_against_trigger(self, finding, trigger):
        if finding.get('entity_type') != trigger.get('entity_type'): return False
        name_match_rule = trigger.get('name_match', {})
        match_type = name_match_rule.get('type', 'exact')
        match_value = name_match_rule.get('value')
        finding_name = finding.get('name', '')
        # Only perform match if a value is specified in the rule.
        if match_value:
            if match_type == 'exact' and finding_name.lower() != match_value.lower(): return False
            if match_type == 'contains' and match_value.lower() not in finding_name.lower(): return False
            if match_type == 'regex' and not re.search(match_value, finding_name, re.IGNORECASE): return False
        return True

    def _format_suggestion(self, suggestion_template, matched_findings):
        """
        Replaces placeholders in the suggestion text with actual finding data,
        with support for nested attributes like 'attributes.password'.
        """
        formatted_suggestion = deepcopy(suggestion_template)
        text_to_format = json.dumps(formatted_suggestion)
        
        # Regex finds all valid placeholders, e.g., {trigger.1.name}, {trigger.2.attributes.password}
        for placeholder in re.findall(r'(\{trigger\.\d+\.[\w\.]+\})', text_to_format):
            # Strip braces: '{trigger.1.attributes.password}' -> 'trigger.1.attributes.password'
            path_str = placeholder.strip('{}')
            parts = path_str.split('.')
            
            try:
                # parts[0] is 'trigger', parts[1] is the trigger ID (e.g., '1')
                trigger_id = int(parts[1])
                # The corresponding finding is at index trigger_id - 1
                finding = matched_findings[trigger_id - 1]
                
                # Start with the finding object and "walk down" the key path.
                current_value = finding
                for key in parts[2:]: # e.g., walk through ['attributes', 'password']
                    current_value = current_value[key]
                
                # Replace the placeholder with the final value found.
                text_to_format = text_to_format.replace(placeholder, str(current_value))

            except (IndexError, KeyError, TypeError):
                # If a key is not found (e.g., rule asks for a nonexistent attribute), warn the user.
                print(f"{C.BOLD}{C.YELLOW}[!] Warning: Could not resolve placeholder '{placeholder}'. Check your rule syntax.{C.END}")

        return json.loads(text_to_format)

    def generate_attack_paths(self, prioritized_findings):
        """
        Analyzes findings against rules to generate suggested attack paths,
        handling host-agnostic credentials correctly.
        """
        suggested_paths = []

        for rule in self.rules:
            triggers = rule['triggers']
            candidate_lists = []
            # For each trigger in the rule, find all matching findings from the main list.
            for trigger in triggers:
                candidates = [f for f in prioritized_findings if self._check_finding_against_trigger(f, trigger)]
                # If any trigger has zero matching candidates, this rule cannot be satisfied.
                if not candidates:
                    candidate_lists = []
                    break
                candidate_lists.append(candidates)
            
            if not candidate_lists: continue

            # Create every possible combination of candidates for the triggers.
            # e.g., if trigger 1 has 2 candidates (A,B) and trigger 2 has 3 (C,D,E),
            # this creates combinations (A,C), (A,D), (A,E), (B,C), (B,D), (B,E).
            for combination in itertools.product(*candidate_lists):
                # This special logic makes credentials host-agnostic.
                
                # 1. Separate findings that must be on a specific host from those that don't (like creds).
                host_specific_findings = [f for f in combination if f.get('entity_type') != 'credential']
                
                # 2. If there are any host-specific findings, they must all be on the SAME host.
                if host_specific_findings:
                    first_host = host_specific_findings[0].get('host')
                    # If findings are on different hosts (e.g., a web page on host A and a service on host B), this combination is invalid.
                    if not all(f.get('host') == first_host for f in host_specific_findings):
                        continue 
                    target_host = first_host
                else:
                    # This handles rules that might only use credentials or other global findings.
                    target_host = "GLOBAL"

                # 3. If the combination is valid, generate the final suggestion.
                if 'suggestion' in rule:
                    suggestion = self._format_suggestion(rule['suggestion'], combination)
                    suggested_paths.append({
                        "name": rule['name'],
                        "priority": rule['priority'],
                        "host": target_host,
                        "suggestion": suggestion,
                        "evidence": [f"Trigger {i+1}: {f.get('name')} ({f.get('entity_type')})" for i, f in enumerate(combination)]
                    })

        # Sort final paths by priority, so the most critical ones appear first.
        suggested_paths.sort(key=lambda x: x.get('priority', 0), reverse=True)
        return suggested_paths