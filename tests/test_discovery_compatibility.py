import json
from pathlib import Path
from main.attack_path_synthesizer import AttackPathSynthesizer
from main.pathfinder import auto_detect_loot
from parsers.initial_foothold.llm_enum_parser import parse_llm_enum_json
from parsers.initial_foothold.nmap_parser import parse_nmap_xml

RULES = Path(__file__).parents[1]/'main/attack_rules.json'


def test_real_redirect_survives_but_arbitrary_dotted_text_does_not_seed_paths(tmp_path):
    path = tmp_path/'nmap.xml'
    path.write_text('<nmaprun><host><address addr="10.10.10.10" addrtype="ipv4"/><ports><port portid="80" protocol="tcp"><state state="open"/><service name="http"/><script id="http-title" output="Did not follow redirect to http://portal.box/ ; noise.file"/></port></ports></host></nmaprun>')
    rows = {r['name']: r for r in parse_nmap_xml(path)}
    assert rows['portal.box']['entity_type'] == 'hostname_candidate'
    assert rows['portal.box']['attributes']['provenance'] == 'http_redirect'
    assert rows['noise.file']['entity_type'] == 'hostname_observation'
    (tmp_path/'tcp_services.xml.raw').write_bytes(path.read_bytes())
    assert len(auto_detect_loot(str(tmp_path))) == 1


def test_ai_inventory_produces_investigation_without_claiming_capabilities(tmp_path):
    engine = AttackPathSynthesizer(str(RULES))
    path = tmp_path/'llm.json'
    for key, product, name in [('mlflow','mlflow','MLflow service - investigate artifact access'),
                               ('notebook','Jupyter','Jupyter service - investigate authentication and kernel access')]:
        payload = {'host':'10.0.0.5','port':5000,'base_url':'http://10.0.0.5:5000',
                   'ai_surfaces':[{'key':key}], 'service':{'product':product}}
        path.write_text(json.dumps(payload))
        rows = parse_llm_enum_json(path)
        names = [p['name'] for p in engine.generate_attack_paths(rows)]
        assert name in names
        assert not any('= RCE' in n or 'Write to Code Execution' in n for n in names)
        flag = 'artifact_write_verified' if key == 'mlflow' else 'kernel_creation_verified'
        payload['capability_evidence'] = {flag:{'verified':True,'evidence':'Explicit authorized assessment fixture'}}
        path.write_text(json.dumps(payload))
        assert parse_llm_enum_json(path)[0]['attributes'][flag] is True


def test_secret_rules_are_hypotheses_and_do_not_construct_login_actions():
    finding = {'host':'app.test','port':None,'entity_type':'secret_finding','name':'source-secret',
               'source_tool':'omega-credentials','attributes':{'rule_id':'generic-api-key','file':'app/config','line':3}}
    paths = AttackPathSynthesizer(str(RULES)).generate_attack_paths([finding])
    assert len(paths) == 1
    assert paths[0]['relationship'] == 'inferred'
    assert not paths[0].get('credential_validation')
    service = {'host':'app.test','port':22,'entity_type':'service','name':'ssh','source_tool':'nmap','attributes':{}}
    generic = AttackPathSynthesizer(str(RULES)).generate_attack_paths([finding,service])
    assert not any('Source SSH private key' in p['name'] for p in generic)
    finding['attributes']['credential_type'] = 'ssh-private-key'
    assert any('Source SSH private key' in p['name'] for p in AttackPathSynthesizer(str(RULES)).generate_attack_paths([finding,service]))
