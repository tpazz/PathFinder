import json
import re
import itertools
from copy import deepcopy
import os

from parsers.ansi import C
from parsers.credential_routing import credential_usages
from .bloodhound_correlator import correlate_bloodhound_ownership

# Get the absolute path to the directory where this script is located.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Build a full, unambiguous path to the rules file, ensuring it's always found.
DEFAULT_RULES_FILE = os.path.join(SCRIPT_DIR, "attack_rules.json")

VALID_HOST_SCOPES = {"same_host", "any_host"}
VALID_TRIGGER_HOST_SCOPES = {"same_host", "any_host"}

# Bounds to stop a single rule with many matching candidates from flooding the
# output via itertools.product (e.g. credentials x every login service).
MAX_PATHS_PER_RULE = 25
MAX_COMBINATIONS_PER_RULE = 5000

# Ranking penalties: a path's rank should reflect both the rule's priority (value
# of the move) and how trustworthy the triggering evidence is. We dock a rule's
# static priority by the weakest link's confidence/severity so a confirmed lead
# outranks a low-confidence guess of equal priority. Penalty-only and bounded, so
# evidence quality only nudges within a band - it never overrides the author's
# priority. Findings carrying neither key (confirmed/structural results such as
# sqlmap, SharpHound, secretsdump) get 0 and keep the full priority.
CONFIDENCE_PENALTY = {"high": 0, "medium": -6, "low": -12}
SEVERITY_PENALTY = {"critical": 0, "high": 0, "medium": -6, "low": -12, "info": -12}
MAX_PRIORITY_PENALTY = -15

# Credential "names" that mean a secret was recovered without a usable account
# identity. They are valuable loot, but should not be sprayed as usernames.
ANONYMOUS_CREDENTIAL_NAMES = {"snmp_disclosed_credential", "cracked_disclosed_credential"}


def _finding_confidence_penalty(finding):
    """Priority penalty for one finding's evidence quality (severity preferred)."""
    attrs = finding.get("attributes") or {}
    severity = str(attrs.get("severity", "")).strip().lower()
    confidence = str(attrs.get("confidence", "")).strip().lower()
    if severity in SEVERITY_PENALTY:
        return SEVERITY_PENALTY[severity]
    if confidence in CONFIDENCE_PENALTY:
        return CONFIDENCE_PENALTY[confidence]
    return 0


def _credential_has_actionable_identity(finding):
    if finding.get("entity_type") != "credential":
        return True

    attrs = finding.get("attributes") or {}
    candidates = [
        attrs.get("username"),
        attrs.get("user"),
        attrs.get("principal"),
        finding.get("name"),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        value = str(candidate).strip()
        if value and value.lower() not in ANONYMOUS_CREDENTIAL_NAMES:
            return True
    return False

# MITRE ATLAS technique tags for the AI/LLM attack rules, keyed by rule name.
# ATLAS is the adversarial-ML counterpart to ATT&CK; tagging AI paths with it makes
# findings map to a shared taxonomy for AI-focused reporting (see the AI-Red-Team
# notes' ATLAS mapping). A rule with no entry here simply carries no ATLAS tag.
ATLAS_TAGS = {
    "Exposed LLM API - Prompt Injection & Guardrail Testing": [
        "AML.T0051 LLM Prompt Injection", "AML.T0054 LLM Jailbreak", "AML.T0040 ML Model Inference API Access"],
    "Exposed Ollama API - Unauthenticated Model Access": [
        "AML.T0040 ML Model Inference API Access", "AML.T0044 Full ML Model Access"],
    "Agent/MCP Surface - Excessive Agency & Tool Abuse": [
        "AML.T0053 LLM Plugin Compromise", "AML.T0051 LLM Prompt Injection"],
    "RAG / Vector Store - Indirect Injection & Data Extraction": [
        "AML.T0070 RAG Poisoning", "AML.T0051 LLM Prompt Injection", "AML.T0025 Exfiltration via Cyber Means"],
    "MLflow Exposed - Artifact Write to Code Execution": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0044 Full ML Model Access"],
    "Exposed Jupyter - Unauthenticated Kernel = RCE": [
        "AML.T0044 Full ML Model Access", "AML.T0010 ML Supply Chain Compromise"],
    "Gradio App - File Upload / SSRF / Prompt Injection": [
        "AML.T0051 LLM Prompt Injection", "AML.T0040 ML Model Inference API Access"],
    "LangServe API - Schema Recovery to Chain Abuse": [
        "AML.T0051 LLM Prompt Injection", "AML.T0040 ML Model Inference API Access"],
    "vLLM/TGI/Model Server - Model Metadata, Tokenizer, and Adapter Recon": [
        "AML.T0040 ML Model Inference API Access", "AML.T0044 Full ML Model Access"],
    "AI Workflow Builder - Flow, Credential, and Tool Graph Enumeration": [
        "AML.T0053 LLM Plugin Compromise", "AML.T0025 Exfiltration via Cyber Means"],
    "Image Generation API - Model, Plugin, and File Path Abuse": [
        "AML.T0040 ML Model Inference API Access", "AML.T0010 ML Supply Chain Compromise"],
    "Tool-Enabled RAG Chain - Retrieved Context to Agent/MCP Action": [
        "AML.T0070 RAG Poisoning", "AML.T0053 LLM Plugin Compromise", "AML.T0051 LLM Prompt Injection"],
    "LLM + RAG Surface - Retrieval Context Extraction and Poisoning Candidate": [
        "AML.T0070 RAG Poisoning", "AML.T0057 LLM Data Leakage"],
    "MLflow + Model Server - Artifact Consumer Path": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0044 Full ML Model Access"],
    "Notebook + ML Platform - Credential and Artifact Pivot": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0025 Exfiltration via Cyber Means"],
    "AI Agent - Capability & Tool Abuse": [
        "AML.T0051 LLM Prompt Injection", "AML.T0053 LLM Plugin Compromise"],
    "A2A / Multi-Agent System - Rogue Registration & Workflow Abuse": [
        "AML.T0051 LLM Prompt Injection", "AML.T0053 LLM Plugin Compromise", "AML.T0025 Exfiltration via Cyber Means"],
    "LLM-to-SQL Agent - Generated Query to Database Command Execution": [
        "AML.T0051 LLM Prompt Injection", "AML.T0040 ML Model Inference API Access"],
    "Unauthenticated Vector Store - Knowledge Base Extraction": [
        "AML.T0025 Exfiltration via Cyber Means", "AML.T0070 RAG Poisoning"],
    "Confirmed MCP Tool Inventory - Targeted Capability Abuse": [
        "AML.T0053 LLM Plugin Compromise", "AML.T0051 LLM Prompt Injection"],
    "Exposed Object Store (MinIO/S3) - Artifact & Credential Loot": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0025 Exfiltration via Cyber Means", "AML.T0044 Full ML Model Access"],
    "MLflow + Object Store - Writable Artifact to Code Execution": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0044 Full ML Model Access"],
    "AI Loot - Platform Secrets and Tokens Found": [
        "AML.T0025 Exfiltration via Cyber Means", "AML.T0040 ML Model Inference API Access"],
    "AI Loot - Vector/RAG Configuration Pivot": [
        "AML.T0070 RAG Poisoning", "AML.T0057 LLM Data Leakage", "AML.T0025 Exfiltration via Cyber Means"],
    "AI Loot - Agent/MCP Tool Manifest Found": [
        "AML.T0053 LLM Plugin Compromise", "AML.T0051 LLM Prompt Injection"],
    "AI Loot - MLflow and Object Store Artifact Chain": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0044 Full ML Model Access"],
    "AI Loot - Notebook Runtime Pivot": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0025 Exfiltration via Cyber Means"],
    "AI Loot - Prompt and System Instruction Templates": [
        "AML.T0051 LLM Prompt Injection", "AML.T0057 LLM Data Leakage"],
    "AI Loot - Unsafe Model Loader Found": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0044 Full ML Model Access"],
    "AI Loot - Writable Model or RAG Artifact": [
        "AML.T0010 ML Supply Chain Compromise", "AML.T0070 RAG Poisoning"],
    "AI Loot - Model Artifact Inventory": [
        "AML.T0010 ML Supply Chain Compromise"],
}


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

            # Reject an unknown match type at load. Matching only special-cases
            # exact/contains/regex and otherwise falls through to "match everything
            # of this entity_type", so a typo like "contain" would silently broad-
            # match instead of erroring.
            name_match = trigger.get("name_match") or {}
            match_type = name_match.get("type", "exact")
            if match_type not in ("exact", "contains", "regex"):
                return False, f"Trigger {trigger_id} has invalid name_match type '{match_type}' (use exact, contains, or regex)"
            # Compile-check regex triggers at load so a malformed pattern (from the
            # rules file or --learn) skips just this rule instead of raising an
            # uncaught re.error mid-synthesis and aborting the whole run.
            if match_type == "regex" and name_match.get("value"):
                try:
                    re.compile(name_match["value"])
                except re.error as exc:
                    return False, f"Trigger {trigger_id} has invalid regex '{name_match['value']}': {exc}"

            attributes_match = trigger.get("attributes_match", {})
            if not isinstance(attributes_match, dict):
                return False, f"Trigger {trigger_id} has invalid 'attributes_match' (expected an object)"
            for attribute, expected in attributes_match.items():
                if not isinstance(attribute, str) or not attribute.strip():
                    return False, f"Trigger {trigger_id} has an invalid attribute matcher name"
                if isinstance(expected, (dict, list)) or expected is None:
                    return False, f"Trigger {trigger_id} has an invalid expected value for '{attribute}'"

        rule_scope = rule.get("host_scope", "same_host")
        if rule_scope not in VALID_HOST_SCOPES:
            return False, f"Rule has invalid host_scope '{rule_scope}'"

        max_paths = rule.get("max_paths_per_host")
        if max_paths is not None and (not isinstance(max_paths, int) or isinstance(max_paths, bool)
                                      or not 1 <= max_paths <= 5000):
            return False, "Rule 'max_paths_per_host' must be an integer from 1 to 5000"

        suppress_conditions = rule.get("suppress_if_host_has", [])
        if not isinstance(suppress_conditions, list):
            return False, "Rule 'suppress_if_host_has' must be a list"
        for condition in suppress_conditions:
            if not isinstance(condition, dict):
                return False, "Each suppress_if_host_has condition must be an object"
            if not any(condition.get(key) for key in ("entity_type", "source_tool_regex", "name_regex")):
                return False, "A suppress_if_host_has condition must specify a matcher"
            for key in ("source_tool_regex", "name_regex"):
                if condition.get(key):
                    try:
                        re.compile(condition[key])
                    except (re.error, TypeError) as exc:
                        return False, f"Invalid {key} in suppress_if_host_has: {exc}"

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
        if trigger.get('entity_type') == "credential" \
                and not trigger.get("allow_anonymous_credential", False) \
                and not _credential_has_actionable_identity(finding):
            return False
        name_match_rule = trigger.get('name_match', {})
        match_type = name_match_rule.get('type', 'exact')
        match_value = name_match_rule.get('value')
        finding_name = finding.get('name', '')
        # Only perform match if a value is specified in the rule.
        if match_value:
            if match_type == 'exact' and finding_name.lower() != match_value.lower(): return False
            if match_type == 'contains' and match_value.lower() not in finding_name.lower(): return False
            if match_type == 'regex' and not re.search(match_value, finding_name, re.IGNORECASE): return False
        attributes = finding.get("attributes") or {}
        for attribute, expected in trigger.get("attributes_match", {}).items():
            if attribute == "credential_usage":
                if str(expected).lower() not in credential_usages(attributes):
                    return False
                continue
            actual = attributes.get(attribute)
            if isinstance(expected, str):
                if str(actual or "").lower() != expected.lower():
                    return False
            elif actual != expected:
                return False
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
                # JSON-escape the value so backslashes (e.g. Windows paths) don't break parsing.
                escaped_value = json.dumps(str(current_value))[1:-1]  # strip surrounding quotes
                text_to_format = text_to_format.replace(placeholder, escaped_value)

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

    @staticmethod
    def _rule_suppressed_for_host(rule, host, findings):
        """Suppress a fallback lead when richer evidence already exists on its host."""
        conditions = rule.get("suppress_if_host_has") or []
        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            entity_type = condition.get("entity_type")
            source_pattern = condition.get("source_tool_regex")
            name_pattern = condition.get("name_regex")
            for finding in findings:
                if finding.get("host") != host:
                    continue
                if entity_type and finding.get("entity_type") != entity_type:
                    continue
                if source_pattern and not re.search(source_pattern, finding.get("source_tool") or "",
                                                    re.IGNORECASE):
                    continue
                if name_pattern and not re.search(name_pattern, finding.get("name") or "",
                                                  re.IGNORECASE):
                    continue
                return True
        return False

    def generate_attack_paths(self, prioritized_findings):
        """
        Analyzes findings against rules to generate suggested attack paths,
        handling host-agnostic credentials and host-scope controls.
        """
        prioritized_findings = correlate_bloodhound_ownership(prioritized_findings)
        suggested_paths = []
        seen = set()  # dedup by (rule name, host, resolved description + commands)

        for rule in self.rules:
            triggers = rule['triggers']
            max_paths_per_host = rule.get("max_paths_per_host", MAX_PATHS_PER_RULE)
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

            # Cap paths PER destination host so one noisy host on a multi-host
            # engagement can't crowd out attack paths on the others.
            host_path_counts = {}
            combinations_examined = 0
            capped_hosts = set()

            for combination in itertools.product(*candidate_lists):
                if combinations_examined >= MAX_COMBINATIONS_PER_RULE:
                    capped_hosts.add("*")
                    break
                combinations_examined += 1

                if not self._combination_satisfies_host_scope(rule, triggers, combination):
                    continue
                if 'suggestion' not in rule:
                    continue

                host = self._target_host_for_combination(combination)
                if self._rule_suppressed_for_host(rule, host, prioritized_findings):
                    continue
                if host_path_counts.get(host, 0) >= max_paths_per_host:
                    capped_hosts.add(host)
                    continue

                matched_findings_by_id = {
                    trigger.get("id", idx + 1): finding
                    for idx, (trigger, finding) in enumerate(zip(triggers, combination))
                }
                suggestion = self._format_suggestion(rule['suggestion'], matched_findings_by_id)

                # Weakest-link evidence quality: a path is only as trustworthy as
                # its shakiest premise, so take the largest penalty across triggers
                # (bounded) and dock the rule's priority by it. evidence_score is the
                # summed finding scores, used as the tiebreak so corroborated leads
                # rise within a priority band.
                penalty = max(
                    min((_finding_confidence_penalty(f) for f in combination), default=0),
                    MAX_PRIORITY_PENALTY,
                )
                effective_priority = rule['priority'] + penalty
                evidence_score = sum(
                    int((f.get("attributes") or {}).get("score", 0) or 0) for f in combination
                )

                # Dedup near-identical paths (same rule + host + resolved commands),
                # which itertools.product can otherwise emit many times.
                dedup_key = (rule['name'], host, suggestion.get('description'),
                             tuple(suggestion.get('commands') or []))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                suggested_paths.append({
                    "name": rule['name'],
                    "priority": rule['priority'],
                    "effective_priority": effective_priority,
                    "evidence_score": evidence_score,
                    "host": host,
                    "suggestion": suggestion,
                    "atlas": ATLAS_TAGS.get(rule['name'], []),
                    "evidence": [f"Trigger {trigger.get('id', i+1)}: {f.get('name')} ({f.get('entity_type')})" for i, (trigger, f) in enumerate(zip(triggers, combination))],
                    # Keep the normalized trigger findings alongside the compact
                    # evidence strings. Grouped triage needs this structure to
                    # aggregate every resolved variant and its provenance instead
                    # of rendering an arbitrary first match from the group.
                    "matched_findings": [
                        {
                            "trigger_id": trigger.get("id", i + 1),
                            "finding": deepcopy(finding),
                        }
                        for i, (trigger, finding) in enumerate(zip(triggers, combination))
                    ],
                })
                host_path_counts[host] = host_path_counts.get(host, 0) + 1

            if capped_hosts:
                # Never silently truncate: tell the user a rule was bounded.
                print(f"{C.YELLOW}[!] Rule '{rule['name']}' had many matches; capped at "
                      f"{max_paths_per_host} paths per host.{C.END}")

        # Rank by confidence-adjusted priority first (value of the move, docked for
        # shaky evidence), then by summed evidence score, then host/name for a
        # deterministic, run-to-run stable order.
        suggested_paths.sort(key=lambda p: (
            -p.get('effective_priority', p.get('priority', 0)),
            -p.get('evidence_score', 0),
            p.get('host') or "",
            p.get('name') or "",
        ))
        return suggested_paths
