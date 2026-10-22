import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from main.vulnerability_mapper import VulnerabilityMapper
from main.attack_path_synthesizer import AttackPathSynthesizer


def result(rows=()):
    return SimpleNamespace(returncode=0,stdout=json.dumps({'RESULTS_EXPLOIT':list(rows),'RESULTS_SHELLCODE':[]}))


def test_repeated_searches_use_a_per_instance_cache_with_independent_results():
    mapper = VulnerabilityMapper(use_github=False,github_cache_file=None)
    with patch('main.vulnerability_mapper.subprocess.run',return_value=result([{'Title':'Example','EDB-ID':'1'}])) as run:
        first = mapper._run_searchsploit('example','1.2 distribution build')
        first[0]['Title']='Caller mutation'
        for _ in range(100):
            assert mapper._run_searchsploit('example','1.2')[0]['Title']=='Example'
        assert run.call_count==1
        assert '_pathfinder_query' not in mapper.searchsploit_cache['example 1.2'][0]


def test_empty_successful_search_and_version_fallback_are_cached():
    mapper = VulnerabilityMapper(use_github=False,github_cache_file=None)
    with patch('main.vulnerability_mapper.subprocess.run',return_value=result()) as run:
        assert mapper._run_searchsploit('example','1')==[]
        assert mapper._run_searchsploit('example','1')==[]
        assert run.call_count==2


def test_failed_and_malformed_queries_are_not_cached_as_empty_success():
    mapper = VulnerabilityMapper(use_github=False,github_cache_file=None)
    with patch('main.vulnerability_mapper.subprocess.run',side_effect=[
        subprocess.TimeoutExpired('searchsploit',30), SimpleNamespace(returncode=0,stdout='{broken'),
        result([{'Title':'Recovered'}])]) as run:
        assert mapper._searchsploit_query('example')==[]
        assert mapper._searchsploit_query('example')==[]
        assert mapper._searchsploit_query('example')[0]['Title']=='Recovered'
        assert run.call_count==3


@pytest.mark.parametrize('payload', [{}, {'error':'unavailable'}, [],
                                     {'RESULTS_EXPLOIT':{},'RESULTS_SHELLCODE':[]}])
def test_valid_json_without_searchsploit_result_lists_is_not_cached(payload):
    mapper = VulnerabilityMapper(use_github=False,github_cache_file=None)
    with patch('main.vulnerability_mapper.subprocess.run', side_effect=[
        SimpleNamespace(returncode=0, stdout=json.dumps(payload)), result([{'Title':'Recovered'}])]) as run:
        assert mapper._searchsploit_query('example')==[]
        assert mapper._searchsploit_query('example')[0]['Title']=='Recovered'
        assert run.call_count==2


def source(entity='code_finding', **attrs):
    return {'host':'app.test','port':None,'name':'xss','entity_type':entity,
            'source_tool':'fixture','attributes':{'file':'src/widgets.js','line':40,**attrs}}


def web(route):
    return {'host':'app.test','port':443,'name':'xss','entity_type':'web_finding',
            'source_tool':'fixture','attributes':{'route':route,'url':'https://app.test'+route}}


def test_same_host_and_class_produce_one_unscored_question_with_all_route_evidence():
    engine = AttackPathSynthesizer()
    paths = engine.generate_attack_paths([source(),web('/account'),web('/employer/embed')])
    relevant = [p for p in paths if p.get('rule_name','').startswith('Reachable cross-site')]
    assert len(relevant)==1
    path = relevant[0]
    assert path['assessment_role']=='validation' and path['relationship']=='unverified'
    assert path['occurrence_count']==2 and len(path['matched_findings'])==3
    assert 'runtime relationship has not been established' in path['suggestion']['description']


def test_explicit_binding_must_match_host_route_and_source_instance():
    proof = {'verified':True,'evidence':'Authorized route-to-handler trace fixture',
             'host':'app.test','route':'/account','file':'src/widgets.js','line':40}
    for changes, expected in [({},True),({'route':'/other'},False),({'line':99},False),
                              ({'evidence':''},False),({'host':'other.test'},False)]:
        finding = source(runtime_relationship={**proof,**changes})
        assert AttackPathSynthesizer._verified_runtime_link([finding,web('/account')]) is expected
    paths = AttackPathSynthesizer().generate_attack_paths([source(runtime_relationship=proof),web('/account')])
    linked = next(p for p in paths if p.get('rule_name','').startswith('Reachable cross-site'))
    assert linked['assessment_role']=='finding' and linked['evidence_state']=='Suspected'


def test_distinct_advisories_are_retained_without_repeating_each_web_pair():
    inputs = [source('dependency_finding',high_impact='true',package='demo',installed_version='1',
                     advisory_ids=[advisory],dependency_scope='unknown') for advisory in ('CVE-fixture-a','CVE-fixture-b')]
    paths = AttackPathSynthesizer().generate_attack_paths(inputs+[web('/a'),web('/b')])
    relevant = [p for p in paths if p.get('rule_name')=='High-impact vulnerable dependency behind a reachable web surface']
    assert len(relevant)==2 and all(p['assessment_role']=='validation' for p in relevant)
    assert all(len(p['matched_findings'])==3 for p in relevant)


def test_distinct_source_instances_at_the_same_location_retain_their_questions():
    inputs = [source(source_finding_id=identity) for identity in ('first','second')]
    paths = AttackPathSynthesizer().generate_attack_paths(inputs+[web('/a'),web('/b')])
    relevant = [p for p in paths if p.get('rule_name','').startswith('Reachable cross-site')]
    assert len(relevant)==2 and all(p['occurrence_count']==2 for p in relevant)
    assert all(len(p['matched_findings'])==3 for p in relevant)
