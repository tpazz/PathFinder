import json
from pathlib import Path
from main.attack_path_synthesizer import AttackPathSynthesizer
from parsers.initial_foothold.llm_enum_parser import parse_llm_enum_json
from parsers.initial_foothold.nmap_parser import parse_nmap_xml

RULES = Path(__file__).parents[1] / 'main/attack_rules.json'


def finding(entity, name, **attrs):
    return {'host': 'app.test', 'port': 443, 'source_tool': 'test', 'entity_type': entity,
            'name': name, 'version': None, 'attributes': {'base_url': 'https://app.test', **attrs}}


def test_build_only_advisory_and_explicit_nonrisk_leads_do_not_create_http_paths():
    engine = AttackPathSynthesizer(str(RULES))
    trigger = {'entity_type': 'dependency_finding'}
    build = finding('dependency_finding', 'demo', dependency_scope='build')
    assert not engine._check_finding_against_trigger(build, trigger)
    assert engine._check_finding_against_trigger(build, {**trigger, 'allow_build_dependency': True})
    for scope in ('unknown', 'runtime'):
        assert engine._check_finding_against_trigger(finding('dependency_finding', 'demo', dependency_scope=scope), trigger)
    for role in ('observation', 'validation'):
        assert not engine._check_finding_against_trigger(finding('web_finding', 'xss', assessment_role=role), {'entity_type': 'web_finding'})
    assert engine._check_finding_against_trigger(finding('web_finding', 'xss', evidence_state='Suspected'), {'entity_type': 'web_finding'})


def test_gate_pages_remain_validation_inventory_without_named_rce_paths(tmp_path):
    loot = tmp_path / 'llm.json'
    payload = {'host': 'app.test', 'port': 443, 'base_url': 'https://app.test',
        'ai_surfaces': [{'key': 'mlflow', 'confidence': 'low'}, {'key': 'agent-mcp'}],
        'probe_hits': [{'path': '/api/2.0/mlflow/experiments/search', 'baseline_match': True,
                        'protocol_verified': True, 'preview': '<html>Closed Beta</html>'}]}
    loot.write_text(json.dumps(payload))
    rows = parse_llm_enum_json(loot)
    assert all(f['entity_type'] == 'ai_service_candidate' for f in rows)
    assert all(f['attributes']['assessment_role'] == 'validation' for f in rows)
    assert rows[0]['attributes']['probe_hits'][0]['baseline_match']
    engine = AttackPathSynthesizer(str(RULES))
    assert not engine.generate_attack_paths(rows)
    payload['probe_hits'][0].update(baseline_match=False)
    loot.write_text(json.dumps(payload))
    mlflow = next(f for f in parse_llm_enum_json(loot) if f['name'] == 'mlflow')
    assert mlflow['entity_type'] == 'ai_service'
    assert 'MLflow Exposed - Artifact Write to Code Execution' not in [p['name'] for p in engine.generate_attack_paths([mlflow])]
    mlflow['attributes']['artifact_write_verified'] = True
    assert 'MLflow Exposed - Artifact Write to Code Execution' in [p['name'] for p in engine.generate_attack_paths([mlflow])]


def test_nse_dotted_noise_is_observation_but_certificate_internal_name_is_retained(tmp_path):
    xml = tmp_path / 'nmap.xml'
    xml.write_text('''<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/>
      <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
      <script id="http-fingerprint" output="6eity.txt ams1.qkjh"/>
      <script id="ssl-cert" output="Subject Alternative Name: DNS:portal.internal"/>
      </port></ports></host></nmaprun>''')
    rows = {f['name']: f for f in parse_nmap_xml(xml)}
    assert rows['6eity.txt']['entity_type'] == rows['ams1.qkjh']['entity_type'] == 'hostname_observation'
    assert rows['portal.internal']['entity_type'] == 'hostname_candidate'
