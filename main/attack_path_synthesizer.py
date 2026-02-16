import json
import re
import itertools
from copy import deepcopy
import os

# Get the absolute path to the directory where this script is located.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Build a full, unambiguous path to the rules file, ensuring it's always found.
DEFAULT_RULES_FILE = os.path.join(SCRIPT_DIR, "attack_rules.json")

VALID_HOST_SCOPES = {"same_host", "any_host"}
VALID_TRIGGER_HOST_SCOPES = {"same_host", "any_host"}

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

    def _extract_placeholders(self, suggestion):
        if not suggestion:
            return []
        serialized = json.dumps(suggestion)
        return re.findall(r'(\{trigger\.\d+\.[\w\.]+\})', serialized)

    def _validate_rule_structure(self, rule):
        if not isinstance(rule, dict):
            return False, "Rule entry is not an object"

        required = ["name", "priority", "triggers", "suggestion"]
        missing = [field for field in required if field not in rule]
        if missing:
            return False, f"Missing required rule field(s): {', '.join(missing)}"

        triggers = rule.get("triggers", [])
        if not isinstance(triggers, list) or not triggers:
            return False, "Rule 'triggers' must be a non-empty list"

        trigger_ids = set()
        for trigger in triggers:
            trigger_id = trigger.get("id")
            entity_type = trigger.get("entity_type")
            if not isinstance(trigger_id, int):
                return False, f"Trigger has invalid 'id': {trigger_id}"
            if trigger_id in trigger_ids:
                return False, f"Duplicate trigger id found: {trigger_id}"
            trigger_ids.add(trigger_id)

            if not isinstance(entity_type, str) or not entity_type.strip():
                return False, f"Trigger {trigger_id} has invalid 'entity_type'"

            trigger_scope = trigger.get("host_scope", "same_host")
            if trigger_scope not in VALID_TRIGGER_HOST_SCOPES:
                return False, f"Trigger {trigger_id} has invalid host_scope '{trigger_scope}'"

        rule_scope = rule.get("host_scope", "same_host")
        if rule_scope not in VALID_HOST_SCOPES:
            return False, f"Rule has invalid host_scope '{rule_scope}'"

        placeholders = self._extract_placeholders(rule.get("suggestion"))
        for placeholder in placeholders:
            parts = placeholder.strip('{}').split('.')
            trigger_id = int(parts[1])
            if trigger_id not in trigger_ids:
                return False, f"Placeholder references undefined trigger id: {trigger_id}"

        return True, None

    def _validate_rules(self, rules):
        valid_rules = []
        for idx, rule in enumerate(rules, start=1):
            is_valid, reason = self._validate_rule_structure(rule)
            if not is_valid:
                print(f"{C.BOLD}{C.YELLOW}[!] Warning: Skipping invalid rule #{idx}: {reason}{C.END}")
                continue
            valid_rules.append(rule)
        return valid_rules

    def _load_rules(self):
        try:
            with open(self.rules_file_path, 'r') as f:
                content = f.read()
                # Handle case where the JSON file is empty.
                if not content: return []
                loaded_rules = json.loads(content)
                if not isinstance(loaded_rules, list):
                    print(f"{C.BOLD}{C.YELLOW}[!] Warning: Rules file must contain a JSON list. Starting with an empty ruleset.{C.END}")
                    return []
                return self._validate_rules(loaded_rules)
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
            new_rule['host_scope'] = input("[?] Host scope? (same_host/any_host) [same_host] > ").strip() or "same_host"
            num_triggers = int(input("[?] How many trigger findings? > "))
            triggers = []
            for i in range(num_triggers):
                print(f"\n--- Defining Trigger {i+1} ---")
                trigger = {'id': i + 1, 'name_match': {}}
                trigger['entity_type'] = input(f" > Trigger {i+1} entity_type? (e.g., software_product) > ").strip()
                trigger['host_scope'] = input(f" > Trigger {i+1} host scope? (same_host/any_host) [same_host] > ").strip() or "same_host"
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

        is_valid, reason = self._validate_rule_structure(new_rule)
        if not is_valid:
            print(f"{C.BOLD}{C.YELLOW}[!] Rule validation failed: {reason}{C.END}")
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

    def _format_suggestion(self, suggestion_template, matched_findings_by_id):
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
                finding = matched_findings_by_id[trigger_id]

                # Start with the finding object and "walk down" the key path.
                current_value = finding
                for key in parts[2:]: # e.g., walk through ['attributes', 'password']
                    current_value = current_value[key]

                # Replace the placeholder with the final value found.
                text_to_format = text_to_format.replace(placeholder, str(current_value))

            except (KeyError, TypeError):
                # If a key is not found (e.g., rule asks for a nonexistent attribute), warn the user.
                print(f"{C.BOLD}{C.YELLOW}[!] Warning: Could not resolve placeholder '{placeholder}'. Check your rule syntax.{C.END}")

        return json.loads(text_to_format)

    def _combination_satisfies_host_scope(self, rule, triggers, combination):
        rule_scope = rule.get("host_scope", "same_host")
        if rule_scope == "any_host":
            return True

        same_host_findings = []
        for trigger, finding in zip(triggers, combination):
            trigger_scope = trigger.get("host_scope", "same_host")
            if trigger_scope == "same_host" and finding.get("entity_type") != "credential":
                same_host_findings.append(finding)

        if not same_host_findings:
            return True

        first_host = same_host_findings[0].get('host')
        return all(f.get('host') == first_host for f in same_host_findings)

    def _target_host_for_combination(self, combination):
        host_specific_findings = [f for f in combination if f.get('entity_type') != 'credential']
        if host_specific_findings:
            return host_specific_findings[0].get('host')
        return "GLOBAL"

    def generate_attack_paths(self, prioritized_findings):
        """
        Analyzes findings against rules to generate suggested attack paths,
        handling host-agnostic credentials and host-scope controls.
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

            if not candidate_lists:
                continue

            for combination in itertools.product(*candidate_lists):
                if not self._combination_satisfies_host_scope(rule, triggers, combination):
                    continue

                if 'suggestion' in rule:
                    matched_findings_by_id = {
                        trigger.get("id", idx + 1): finding
                        for idx, (trigger, finding) in enumerate(zip(triggers, combination))
                    }
                    suggestion = self._format_suggestion(rule['suggestion'], matched_findings_by_id)
                    suggested_paths.append({
                        "name": rule['name'],
                        "priority": rule['priority'],
                        "host": self._target_host_for_combination(combination),
                        "suggestion": suggestion,
                        "evidence": [f"Trigger {trigger.get('id', i+1)}: {f.get('name')} ({f.get('entity_type')})" for i, (trigger, f) in enumerate(zip(triggers, combination))]
                    })

        # Sort final paths by priority, so the most critical ones appear first.
        suggested_paths.sort(key=lambda x: x.get('priority', 0), reverse=True)
        return suggested_paths
