"""Bounded ownership correlation for SharpHound and AD CS findings.

This module deliberately does not implement graph traversal. It joins credentials
to direct edges, optionally annotates the direct target with one high-value hint,
and stops there.
"""

import re

from parsers.ansi import warn
from parsers.credential_routing import credential_usages


MAX_OWNED_PRINCIPALS = 5000
MAX_CORRELATED_FINDINGS = 250
_OWNERSHIP_USAGES = {"password_reuse", "pass_the_hash", "ticket_key"}
_ANONYMOUS_NAMES = {"cracked_disclosed_credential", "snmp_disclosed_credential"}
_BROAD_USER_GROUPS = {"authenticated users", "domain users", "everyone"}
_BROAD_COMPUTER_GROUPS = {"domain computers"}


def _principal_parts(value):
    text = str(value or "").strip().strip("'\"")
    if not text or text.lower() in _ANONYMOUS_NAMES or text.upper().startswith("S-1-"):
        return None
    domain = None
    account = text
    if "\\" in text:
        domain, account = text.rsplit("\\", 1)
    elif "@" in text:
        account, domain = text.rsplit("@", 1)
    elif "/" in text and not re.match(r"^[a-z]+://", text, re.IGNORECASE):
        domain, account = text.split("/", 1)
    account = account.strip().lower()
    domain = domain.strip().lower() if domain else None
    if not account:
        return None
    return domain, account


def _preferred_identity(finding):
    attrs = finding.get("attributes") or {}
    raw = attrs.get("username") or attrs.get("user") or attrs.get("principal") or finding.get("name")
    parts = _principal_parts(raw)
    if parts is None:
        return None
    domain, account = parts
    domain = domain or (str(attrs.get("domain") or "").strip().lower() or None)
    return domain, account


def _build_owned_index(findings):
    records = {}
    truncated = False
    for finding in findings:
        if finding.get("entity_type") != "credential":
            continue
        attrs = finding.get("attributes") or {}
        usages = credential_usages(attrs) & _OWNERSHIP_USAGES
        if not usages:
            continue
        identity = _preferred_identity(finding)
        if identity is None:
            continue
        if identity not in records and len(records) >= MAX_OWNED_PRINCIPALS:
            truncated = True
            continue
        domain, account = identity
        display = (
            attrs.get("username") or attrs.get("user") or attrs.get("principal")
            or finding.get("name") or account
        )
        record = records.setdefault(identity, {
            "domain": domain,
            "account": account,
            "display": str(display),
            "sources": set(),
            "usages": set(),
        })
        if finding.get("source_tool"):
            record["sources"].add(finding["source_tool"])
        record["usages"].update(usages)

    by_account = {}
    for identity, record in records.items():
        by_account.setdefault(record["account"], []).append((identity, record))
    return records, by_account, truncated


def _merge_owned_records(matches, graph_name):
    if not matches:
        return None
    concrete_domains = {identity[0] for identity, _ in matches if identity[0]}
    if len(concrete_domains) > 1:
        return None
    sources = set()
    usages = set()
    for _identity, record in matches:
        sources.update(record["sources"])
        usages.update(record["usages"])
    return {
        "owned_principal": str(graph_name),
        "credential_sources": sorted(sources),
        "credential_usages": sorted(usages),
    }


def _match_owned(values, records, by_account):
    for value in values:
        parts = _principal_parts(value)
        if parts is None:
            continue
        domain, account = parts
        if domain and (domain, account) in records:
            return _merge_owned_records([((domain, account), records[(domain, account)])], value)
        candidates = by_account.get(account, [])
        merged = _merge_owned_records(candidates, value)
        if merged:
            return merged
    return None


def _template_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _derived(name, source, owned, *, right, target, description, score, contexts=None):
    source_attrs = source.get("attributes") or {}
    attrs = {
        **owned,
        "right": right,
        "target": target,
        "target_high_value_contexts": list(contexts or []),
        "correlation_basis": source.get("name"),
        "description": description,
        "score": score,
    }
    provenance = source_attrs.get("discovery_provenance")
    if isinstance(provenance, list):
        attrs["discovery_provenance"] = provenance
    return {
        "host": source.get("host"),
        "port": source.get("port"),
        "source_tool": "bloodhound-correlation",
        "entity_type": "privilege_escalation",
        "name": name,
        "version": None,
        "attributes": attrs,
    }


def correlate_bloodhound_ownership(findings):
    """Append bounded direct-edge ownership correlations to normalized findings."""
    if not isinstance(findings, list):
        return findings
    records, by_account, owned_truncated = _build_owned_index(findings)
    if not records:
        return list(findings)
    if owned_truncated:
        warn(
            f"[!] Warning: BloodHound ownership index capped at "
            f"{MAX_OWNED_PRINCIPALS} principals."
        )

    vulnerable_templates = {
        _template_key((finding.get("attributes") or {}).get("template"))
        for finding in findings
        if finding.get("name", "").startswith("adcs_esc")
    }
    derived = []
    seen = set()
    truncated = False

    def append(item):
        nonlocal truncated
        attrs = item.get("attributes") or {}
        marker = (
            item.get("name"), item.get("host"), attrs.get("owned_principal"),
            attrs.get("right"), attrs.get("target"),
            tuple(attrs.get("target_high_value_contexts") or []),
        )
        if marker in seen:
            return
        if len(derived) >= MAX_CORRELATED_FINDINGS:
            truncated = True
            return
        seen.add(marker)
        derived.append(item)

    for finding in findings:
        attrs = finding.get("attributes") or {}
        name = finding.get("name") or ""

        if finding.get("source_tool") == "sharphound" and name == "dcsync_rights_found":
            owned = _match_owned([attrs.get("user")], records, by_account)
            if owned:
                principal = owned["owned_principal"]
                append(_derived(
                    "bloodhound_owned_zero_hop_dcsync", finding, owned,
                    right="DCSync", target=attrs.get("target") or finding.get("host"),
                    description=(
                        f"You own '{principal}', which already has DCSync over "
                        f"'{attrs.get('target') or finding.get('host')}'."
                    ), score=100,
                ))
            continue

        sharphound_edge = (
            finding.get("source_tool") == "sharphound"
            and name in {
                "genericwrite_on_sensitive_group", "acl_abuse_right_on_object",
                "gmsa_password_read_right_found", "adcs_enrollment_right_found",
                "delegation_abuse_edge",
            }
        )
        if sharphound_edge:
            values = [attrs.get("attacker")]
            aliases = attrs.get("attacker_aliases")
            if isinstance(aliases, list):
                values.extend(aliases)
            owned = _match_owned(values, records, by_account)
            if not owned:
                continue
            principal = owned["owned_principal"]
            right = attrs.get("right") or "direct control"
            target = attrs.get("target") or "target object"
            contexts = attrs.get("target_high_value_contexts") or []
            if not contexts and name == "genericwrite_on_sensitive_group":
                contexts = ["high-value administrative group"]

            if name == "gmsa_password_read_right_found" or str(right).lower() == "readgmsapassword":
                append(_derived(
                    "bloodhound_owned_zero_hop_gmsa_read", finding, owned,
                    right="ReadGMSAPassword", target=target,
                    description=(
                        f"You own '{principal}', which can immediately read the gMSA "
                        f"password for '{target}'."
                    ), score=100,
                ))
                continue

            template_is_vulnerable = (
                bool(attrs.get("template_vulnerable"))
                or _template_key(target) in vulnerable_templates
            )
            if name == "adcs_enrollment_right_found" and template_is_vulnerable:
                append(_derived(
                    "bloodhound_owned_zero_hop_adcs", finding, owned,
                    right=right, target=target,
                    description=(
                        f"You own '{principal}', which can enroll in vulnerable AD CS "
                        f"template '{target}'."
                    ), score=100,
                ))
                continue

            correlation_name = (
                "bloodhound_owned_delegation_edge"
                if name == "delegation_abuse_edge" else "bloodhound_owned_acl_edge"
            )
            append(_derived(
                correlation_name, finding, owned,
                right=right, target=target,
                description=(
                    f"You own '{principal}', which has '{right}' over '{target}'."
                ), score=97, contexts=contexts,
            ))
            if contexts:
                append(_derived(
                    "bloodhound_owned_one_hop_high_value", finding, owned,
                    right=right, target=target,
                    description=(
                        f"You own '{principal}' and can take over '{target}' via '{right}'; "
                        f"the target is {', '.join(str(item) for item in contexts)}."
                    ), score=99, contexts=contexts,
                ))
            continue

        if finding.get("source_tool") == "certipy" and name.startswith("adcs_esc"):
            principals = attrs.get("enrollment_principals") or []
            if not isinstance(principals, list):
                continue
            direct_matches = []
            broad_user = False
            broad_computer = False
            for principal in principals:
                parts = _principal_parts(principal)
                account = parts[1] if parts else str(principal or "").strip().lower()
                broad_user = broad_user or account in _BROAD_USER_GROUPS
                broad_computer = broad_computer or account in _BROAD_COMPUTER_GROUPS
                matched = _match_owned([principal], records, by_account)
                if matched:
                    direct_matches.append(matched)
            if broad_user or broad_computer:
                for record in records.values():
                    is_computer = record["account"].endswith("$")
                    if (broad_user and not is_computer) or (broad_computer and is_computer):
                        direct_matches.append({
                            "owned_principal": record["display"],
                            "credential_sources": sorted(record["sources"]),
                            "credential_usages": sorted(record["usages"]),
                        })
            for owned in direct_matches:
                principal = owned["owned_principal"]
                template = attrs.get("template") or "vulnerable template"
                append(_derived(
                    "bloodhound_owned_zero_hop_adcs", finding, owned,
                    right="Enroll", target=template,
                    description=(
                        f"You own '{principal}', which can enroll in vulnerable AD CS "
                        f"template '{template}' ({attrs.get('esc') or 'ESC'})."
                    ), score=100,
                ))

    if truncated:
        warn(
            f"[!] Warning: BloodHound ownership correlation capped at "
            f"{MAX_CORRELATED_FINDINGS} direct results; no transitive search was attempted."
        )
    return list(findings) + derived
