import os
import json
import zipfile
from pathlib import Path

from parsers.ansi import warn

# Well-known Security Identifiers (SIDs) for high-value default groups.
# The "DOMAIN" placeholder will be dynamically replaced with the actual domain SID later.
HIGH_VALUE_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
    "DOMAIN-512": "Domain Admins",
    "DOMAIN-519": "Enterprise Admins",
}

# The specific extended rights required to perform a DCSync attack.
DCSYNC_RIGHTS = {
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All"
}
ACL_ABUSE_RIGHTS = {
    "WriteDacl", "WriteOwner", "AddMember", "ForceChangePassword",
    "GenericAll", "GenericWrite", "ReadGMSAPassword", "Enroll", "AutoEnroll",
}
MAX_SHARPHOUND_MEMBER_BYTES = 256 * 1024 * 1024
MAX_DELEGATION_EDGES = 500
_RIGHT_NAMES = {right.lower(): right for right in ACL_ABUSE_RIGHTS | DCSYNC_RIGHTS}


def _matches_collection_file(filename, collection):
    basename = os.path.basename(str(filename)).lower()
    expected = f"{collection.lower()}.json"
    return basename == expected or basename.endswith(f"_{expected}")


def _newest_directory_file(directory, collection):
    candidates = []
    try:
        for entry in Path(directory).iterdir():
            if entry.is_file() and _matches_collection_file(entry.name, collection):
                candidates.append(entry)
    except (OSError, ValueError):
        return None
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item.stat().st_mtime_ns, item.name.lower()))


def _newest_zip_member(archive, collection):
    candidates = [
        info for info in archive.infolist()
        if not info.is_dir() and _matches_collection_file(info.filename, collection)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item.date_time, item.filename.lower()))


def _payload_data(payload):
    if isinstance(payload, dict):
        data = payload.get('data', [])
        return data if isinstance(data, list) else []
    return payload if isinstance(payload, list) else []


def _load_sharphound_json(source, collection):
    """Load the newest exact or timestamp-prefixed SharpHound collection."""
    source_path = Path(source)
    try:
        if source_path.is_file() and zipfile.is_zipfile(source_path):
            with zipfile.ZipFile(source_path) as archive:
                member = _newest_zip_member(archive, collection)
                if member is None:
                    return []
                if member.file_size > MAX_SHARPHOUND_MEMBER_BYTES:
                    warn(f"[!] Warning: Skipping oversized SharpHound member '{member.filename}'.")
                    return []
                with archive.open(member) as stream:
                    payload = json.loads(stream.read().decode('utf-8-sig'))
        else:
            selected = _newest_directory_file(source_path, collection)
            if selected is None:
                return []
            if selected.stat().st_size > MAX_SHARPHOUND_MEMBER_BYTES:
                warn(f"[!] Warning: Skipping oversized SharpHound file '{selected.name}'.")
                return []
            with selected.open('r', encoding='utf-8-sig') as stream:
                payload = json.load(stream)
        return _payload_data(payload)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, zipfile.BadZipFile):
        warn(f"[!] Warning: Could not load or parse SharpHound '{collection}' data from '{source}'.")
        return []


def is_sharphound_directory(path):
    """Return whether a directory contains the core SharpHound collections."""
    return (_newest_directory_file(path, 'users') is not None
            and _newest_directory_file(path, 'domains') is not None)


def is_sharphound_archive(path):
    """Return whether a ZIP contains the core SharpHound collections."""
    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as archive:
            return (_newest_zip_member(archive, 'users') is not None
                    and _newest_zip_member(archive, 'domains') is not None)
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def _ci_get(obj, *keys, default=None):
    """Case-insensitive key lookup across multiple possible field names."""
    lower_map = {k.lower(): v for k, v in obj.items()} if isinstance(obj, dict) else {}
    for key in keys:
        val = lower_map.get(key.lower())
        if val is not None:
            return val
    return default


def _relationship_entries(value):
    """Return relationship records across legacy and CE result envelopes."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("Results", "results", "Members", "members", "Data", "data"):
        nested = value.get(key)
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
    return []


def _relationship_sid(entry):
    return _ci_get(
        entry, "ObjectIdentifier", "ObjectID", "MemberId", "MemberSID",
        "PrincipalSID", "PrincipalSId", "Sid", "SID",
    )


def _computer_account_alias(name):
    value = str(name or "").split("@", 1)[0].split(".", 1)[0].strip()
    return f"{value}$" if value and not value.endswith("$") else value


def _template_vulnerability_metadata(obj):
    props = _ci_get(obj, "Properties", "properties", default={})
    values = []
    for source in (obj, props if isinstance(props, dict) else {}):
        for key, value in source.items():
            low_key = str(key).lower()
            if "vulnerab" in low_key or low_key in {"esc", "escs", "risk"}:
                values.append(value)
    return any(value not in (None, False, "", [], {}) for value in values)


def _canonical_right(value):
    text = str(value or "").strip()
    return _RIGHT_NAMES.get(text.lower(), text)


def _normalize_sharphound_object(obj):
    """Normalizes object keys for schema variance tolerance (BloodHound v4 and v5/CE)."""
    if not isinstance(obj, dict):
        return {}

    normalized = dict(obj)
    normalized.setdefault('ObjectIdentifier',
                          _ci_get(obj, 'ObjectIdentifier', 'ObjectID', 'ObjectSid', 'objectid'))
    normalized.setdefault('Name',
                          _ci_get(obj, 'Name', 'name', 'DisplayName', 'samaccountname', default='UNKNOWN'))
    normalized.setdefault('Aces',
                          _ci_get(obj, 'Aces', 'aces', default=[]))
    normalized.setdefault('ObjectType',
                          _ci_get(obj, 'ObjectType', 'objectType', 'objecttype'))
    normalized.setdefault('Members', _ci_get(obj, 'Members', 'members', default=[]))
    normalized.setdefault('LocalAdmins', _ci_get(obj, 'LocalAdmins', 'localadmins', default=[]))
    # BloodHound v5/CE uses 'Properties' sub-object for many fields.
    props = _ci_get(obj, 'Properties', 'properties', default={})
    if isinstance(props, dict):
        for key in ['DontReqPreAuth', 'HasSPN', 'IsAdmin', 'UnconstrainedDelegation',
                     'AllowedToAct', 'AllowedToDelegate', 'Members', 'LocalAdmins']:
            if key not in normalized:
                normalized.setdefault(key, _ci_get(props, key, default=None))
    return normalized


def parse_sharphound_dir(dir_path):
    """
    Parses SharpHound JSON files to find AD attack paths, including ACL-based attacks.

    Args:
        dir_path (str): Path to the directory containing the unzipped SharpHound files.

    Returns:
        list: A list of 'privilege_escalation' and other finding dictionaries.
    """
    findings = []

    users = [_normalize_sharphound_object(u) for u in _load_sharphound_json(dir_path, 'users')]
    groups = [_normalize_sharphound_object(g) for g in _load_sharphound_json(dir_path, 'groups')]
    computers = [_normalize_sharphound_object(c) for c in _load_sharphound_json(dir_path, 'computers')]
    domains = [_normalize_sharphound_object(d) for d in _load_sharphound_json(dir_path, 'domains')]
    certtemplates = [
        _normalize_sharphound_object(t)
        for t in _load_sharphound_json(dir_path, 'certtemplates')
    ]
    sessions = _load_sharphound_json(dir_path, 'sessions')

    if not users and not domains:
        return findings

    sid_to_name_map = {}
    sid_to_type_map = {}
    typed_collections = (
        (users, "User"), (groups, "Group"), (computers, "Computer"),
        (domains, "Domain"), (certtemplates, "CertTemplate"),
    )
    for collection, object_type in typed_collections:
        for obj in collection:
            obj.setdefault("CollectionType", object_type)
            sid = obj.get('ObjectIdentifier')
            if sid:
                sid_to_name_map[sid] = obj.get('Name', 'UNKNOWN')
                sid_to_type_map[sid] = obj.get('ObjectType') or object_type

    domain_sid = domains[0].get('ObjectIdentifier') if domains else None
    domain_name = domains[0].get('Name') if domains else "UNKNOWN_DOMAIN"

    # Create a set of high-value group SIDs specific to the discovered domain.
    domain_high_value_sids = {sid.replace("DOMAIN", domain_sid) for sid in HIGH_VALUE_GROUP_SIDS} if domain_sid else set()
    high_value_targets = {group.get('ObjectIdentifier') for group in groups if group.get('ObjectIdentifier') in domain_high_value_sids}

    high_value_contexts = {}
    for group in groups:
        group_sid = group.get('ObjectIdentifier')
        if group_sid not in high_value_targets:
            continue
        group_name = group.get('Name', 'high-value group')
        for member in _relationship_entries(group.get('Members')):
            member_sid = _relationship_sid(member)
            if member_sid:
                high_value_contexts.setdefault(member_sid, set()).add(
                    f"direct member of {group_name}"
                )
    for user in users:
        if user.get('IsAdmin') and user.get('ObjectIdentifier'):
            high_value_contexts.setdefault(user['ObjectIdentifier'], set()).add(
                "AdminCount/high-privilege account"
            )
    for computer in computers:
        computer_name = computer.get('Name', 'UNKNOWN_COMPUTER')
        for member in _relationship_entries(computer.get('LocalAdmins')):
            member_sid = _relationship_sid(member)
            if member_sid:
                high_value_contexts.setdefault(member_sid, set()).add(
                    f"local administrator on {computer_name}"
                )

    def target_context(obj_sid):
        contexts = set(high_value_contexts.get(obj_sid, set()))
        if obj_sid in high_value_targets:
            contexts.add("high-value administrative group")
        return sorted(contexts)

    high_value_user_sids = set()
    for user in users:
        user_fqdn = user.get('Name', 'UNKNOWN_USER')
        user_sid = user.get('ObjectIdentifier')

        if user.get('DontReqPreAuth', False):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "asreproastable_user", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} does not require Kerberos pre-authentication."}
            })

        if user.get('HasSPN', False) and not user_fqdn.lower().endswith('krbtgt'):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "kerberoastable_user", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has a Service Principal Name and is likely Kerberoastable."}
            })

        if user.get('IsAdmin', False) and user_sid:
            high_value_user_sids.add(user_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "attractive_user_high_privileges", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has AdminCount=true, indicating high privileges."}
            })

    # Domain collection objects frequently omit ObjectType.  The collection itself
    # is authoritative, so do not gate DCSync extraction on that optional field.
    for obj in domains:
        user_dcsync_rights = {}
        for ace in obj.get('Aces', []):
            if not isinstance(ace, dict):
                continue
            principal_sid = _ci_get(ace, 'PrincipalSID', 'PrincipalSId', 'principalsid')
            right = _canonical_right(_ci_get(ace, 'RightName', 'rightname', 'Right'))
            if principal_sid and right in DCSYNC_RIGHTS:
                user_dcsync_rights.setdefault(principal_sid, set()).add(right)

        for principal_sid, rights in user_dcsync_rights.items():
            if rights.issuperset(DCSYNC_RIGHTS):
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                findings.append({
                    "host": domain_name, "port": None, "source_tool": "sharphound",
                    "entity_type": "privilege_escalation", "name": "dcsync_rights_found", "version": None,
                    "attributes": {
                        "user": principal_name,
                        "principal_sid": principal_sid,
                        "target": domain_name,
                        "right": "DCSync",
                        "description": f"'{principal_name}' has DCSync rights over the domain.",
                    }
                })

    all_objects = users + groups + computers + domains + certtemplates
    for obj in all_objects:
        obj_sid = obj.get('ObjectIdentifier')
        obj_name = obj.get('Name', 'UNKNOWN_OBJECT')

        for ace in obj.get('Aces', []):
            if not isinstance(ace, dict):
                continue
            principal_sid = _ci_get(ace, 'PrincipalSID', 'PrincipalSId', 'principalsid')
            right = _canonical_right(_ci_get(ace, 'RightName', 'rightname', 'Right'))
            if not principal_sid or not right:
                continue

            # Skip self-permissions and well-known admin group permissions.
            if principal_sid == obj_sid:
                continue
            if principal_sid in high_value_targets or principal_sid in domain_high_value_sids:
                continue
            # Skip well-known built-in SIDs (SYSTEM, Administrators, etc.)
            if principal_sid in {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-9'}:
                continue

            contexts = target_context(obj_sid)
            common_attributes = {
                "attacker": sid_to_name_map.get(principal_sid, principal_sid),
                "principal_sid": principal_sid,
                "target": obj_name,
                "target_sid": obj_sid,
                "target_type": sid_to_type_map.get(obj_sid) or obj.get("CollectionType"),
                "right": right,
                "target_high_value": bool(contexts),
                "target_high_value_contexts": contexts,
            }

            if right in ["GenericWrite", "GenericAll"] and obj_sid in high_value_targets:
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                findings.append({
                    "host": domain_name, "port": None, "source_tool": "sharphound",
                    "entity_type": "privilege_escalation", "name": "genericwrite_on_sensitive_group", "version": None,
                    "attributes": {
                        **common_attributes,
                        "description": f"'{principal_name}' has {right} rights on the high-value group '{obj_name}'.",
                    }
                })
            elif right in ACL_ABUSE_RIGHTS:
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                finding_name = "acl_abuse_right_on_object"
                if right == "ReadGMSAPassword":
                    finding_name = "gmsa_password_read_right_found"
                elif right in {"Enroll", "AutoEnroll"} and obj.get("CollectionType") == "CertTemplate":
                    finding_name = "adcs_enrollment_right_found"
                findings.append({
                    "host": domain_name,
                    "port": None,
                    "source_tool": "sharphound",
                    "entity_type": "privilege_escalation",
                    "name": finding_name,
                    "version": None,
                    "attributes": {
                        **common_attributes,
                        "template_vulnerable": (
                            _template_vulnerability_metadata(obj)
                            if finding_name == "adcs_enrollment_right_found" else False
                        ),
                        "description": f"'{principal_name}' has potential abuse right '{right}' on '{obj_name}'.",
                    },
                })

    for computer in computers:
        computer_name = computer.get('Name', 'UNKNOWN_COMPUTER')
        if computer.get('UnconstrainedDelegation', False):
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "unconstrained_delegation_enabled", "version": None,
                "attributes": {"computer": computer_name, "description": f"Computer '{computer_name}' has Unconstrained Delegation enabled."}
            })

        allowed_to_act = computer.get('AllowedToAct', [])
        allowed_to_delegate = computer.get('AllowedToDelegate', [])
        if allowed_to_act:
            findings.append({
                "host": domain_name,
                "port": None,
                "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "resource_based_constrained_delegation_possible",
                "version": None,
                "attributes": {
                    "computer": computer_name,
                    "delegation_entries": allowed_to_act,
                    "description": f"Computer '{computer_name}' exposes delegation entries that may enable RBCD abuse.",
                },
            })

        delegation_count = 0
        for entry in _relationship_entries(allowed_to_act):
            if delegation_count >= MAX_DELEGATION_EDGES:
                break
            principal_sid = _relationship_sid(entry)
            principal_name = (
                sid_to_name_map.get(principal_sid)
                or _ci_get(entry, "Name", "PrincipalName", "MemberName")
                or principal_sid
            )
            if not principal_name:
                continue
            findings.append({
                "host": domain_name,
                "port": None,
                "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "delegation_abuse_edge",
                "version": None,
                "attributes": {
                    "attacker": principal_name,
                    "principal_sid": principal_sid,
                    "target": computer_name,
                    "target_sid": computer.get("ObjectIdentifier"),
                    "target_type": "Computer",
                    "right": "AllowedToAct",
                    "target_high_value": True,
                    "target_high_value_contexts": [
                        f"administrator-equivalent delegation access on {computer_name}"
                    ],
                    "description": (
                        f"'{principal_name}' is allowed to act on behalf of other identities "
                        f"to '{computer_name}'."
                    ),
                },
            })
            delegation_count += 1

        delegate_targets = allowed_to_delegate if isinstance(allowed_to_delegate, list) else []
        for entry in delegate_targets:
            if delegation_count >= MAX_DELEGATION_EDGES:
                break
            if isinstance(entry, dict):
                delegate_target = _ci_get(entry, "Name", "ObjectIdentifier", "Service", "SPN")
            else:
                delegate_target = str(entry).strip() if entry is not None else None
            if not delegate_target:
                continue
            findings.append({
                "host": domain_name,
                "port": None,
                "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "delegation_abuse_edge",
                "version": None,
                "attributes": {
                    "attacker": computer_name,
                    "attacker_aliases": [_computer_account_alias(computer_name)],
                    "principal_sid": computer.get("ObjectIdentifier"),
                    "target": delegate_target,
                    "target_sid": None,
                    "target_type": "Service",
                    "right": "AllowedToDelegate",
                    "target_high_value": False,
                    "target_high_value_contexts": [],
                    "description": (
                        f"'{computer_name}' has constrained delegation to '{delegate_target}'."
                    ),
                },
            })
            delegation_count += 1

    for session in sessions:
        user_sid = session.get('UserSID')
        computer_sid = session.get('ComputerSID')
        if user_sid in high_value_user_sids:
            user_name = sid_to_name_map.get(user_sid, user_sid)
            computer_name = sid_to_name_map.get(computer_sid, computer_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "privileged_user_session_found",
                "version": None,
                "attributes": {"user": user_name, "computer": computer_name, "description": f"High-privilege user '{user_name}' has an active session on '{computer_name}'."}
            })

    return findings
