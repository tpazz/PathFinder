"""Large recon must retain evidence without quadratic provenance merging."""
from copy import deepcopy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from main.pathfinder import coalesce_mapping_inputs, deduplicate_findings
from main.vulnerability_mapper import VulnerabilityMapper


def finding(index, **attrs):
    return {
        'host': 'fixture.test', 'port': 443, 'source_tool': 'fixture',
        'entity_type': 'hostname_candidate', 'name': 'internal.fixture.test', 'version': None,
        'attributes': {
            'source_file': f'body-{index}', 'source_page': f'https://fixture.test/page-{index}',
            'discovery_provenance': [{'tool': 'ffuf', 'command': 'fixture', 'source_file': f'body-{index}'}],
            **attrs,
        },
    }


def test_provenance_merge_has_linear_membership_work():
    class CountedString(str):
        comparisons = 0
        __hash__ = str.__hash__

        def __eq__(self, other):
            type(self).comparisons += 1
            return super().__eq__(other)

    count = 2000
    rows = [finding(i, source_file=CountedString(f'body-{i}')) for i in range(count)]
    result = deduplicate_findings(rows)
    assert len(result) == 1
    attrs = result[0]['attributes']
    assert attrs['source_files'] == [f'body-{i}' for i in range(count)]
    assert attrs['source_pages'] == [f'https://fixture.test/page-{i}' for i in range(count)]
    assert len(attrs['discovery_provenance']) == count
    assert CountedString.comparisons < count * 10
    assert not any(key.startswith('_') for key in attrs)
    json.dumps(result)  # Internal sets must not leak into report artifacts.


def test_merging_previously_merged_findings_retains_every_file_tool_page_and_command():
    left = deduplicate_findings([finding(1), finding(2)])[0]
    right_rows = [finding(3), finding(4)]
    right_rows[1]['source_tool'] = 'other-tool'
    right = deduplicate_findings(right_rows)[0]
    merged = deduplicate_findings([left, right])[0]['attributes']
    assert merged['source_files'] == ['body-1', 'body-2', 'body-3', 'body-4']
    assert len(merged['source_pages']) == 4
    assert len(merged['discovery_provenance']) == 4
    assert merged['corroborating_sources'] == ['fixture', 'other-tool']


def test_only_semantically_identical_inputs_are_consolidated_before_mapping():
    rows = [finding(i, source_page='https://fixture.test/same') for i in range(50)]
    result = coalesce_mapping_inputs(rows)
    assert len(result) == 1
    assert len(result[0]['attributes']['source_files']) == 50
    assert len(result[0]['attributes']['discovery_provenance']) == 50


@pytest.mark.parametrize('change', [
    {'source_page': 'https://fixture.test/different'}, {'url': 'https://fixture.test/a'},
    {'password': 'second-secret'}, {'evidence': 'different content'}, {'score': 90},
    {'parameters': ['different']}, {'method': 'POST'},
])
def test_distinct_url_secret_evidence_score_and_request_context_are_not_consolidated(change):
    assert len(coalesce_mapping_inputs([finding(0), finding(1, **change)])) == 2


def test_duplicate_products_map_once_and_enrichment_keeps_all_provenance(monkeypatch):
    rows = [finding(i, source_page='https://fixture.test/same') for i in range(100)]
    for row in rows:
        row.update(entity_type='software_product', name='Fixture Server', version='1.2')
    original = deepcopy(rows)
    mapper = VulnerabilityMapper(use_github=False, github_cache_file=None)
    calls = []

    def lookup(product, version):
        calls.append((product, version))
        return [{'Title': 'Fixture advisory', 'EDB-ID': '123', 'Codes': 'CVE-2026-1234'}]

    monkeypatch.setattr(mapper, '_run_searchsploit', lookup)
    mapped = mapper.map_and_prioritize(coalesce_mapping_inputs(rows))
    assert calls == [('Fixture Server', '1.2')]
    exploit = next(row for row in mapped if row['entity_type'] == 'vulnerability')
    assert len(exploit['attributes']['discovery_provenance']) == 101
    assert len(original) == 100  # All 100 producer files are represented, with no input cap.


@pytest.mark.parametrize('field,value', [('host', 'other.test'), ('port', 80),
                                         ('version', '2.0'), ('source_tool', 'other-parser')])
def test_distinct_host_port_version_and_tool_are_mapped_independently(field, value):
    first, second = finding(0), finding(0)
    second[field] = value
    assert len(coalesce_mapping_inputs([first, second])) == 2


def test_same_body_on_distinct_ffuf_urls_retains_routes_and_rare_last_capture(tmp_path):
    loot = tmp_path / 'loot' / 'fixture.test'
    bodies = loot / 'ffuf_pages_https_443'
    bodies.mkdir(parents=True)
    results = []
    count = 70
    for index in range(count):
        body = '<html><body>db.internal.test username: svc_fixture <a href="https://fixture.test/shared?id=1">link</a>'
        if index == count - 1:
            body += ' api_key="UNIQUE-EXPOSED-FIXTURE-KEY-987654321"'
        body += '</body></html>'
        (bodies / f'body{index}').write_text(body, encoding='utf-8')
        results.append(dict(resultfile=f'ffuf_pages_https_443/body{index}',
                            url=f'https://fixture.test/path{index}/', status=200, length=len(body)))
    (loot / 'ffuf_443.json').write_text(json.dumps(dict(commandline='ffuf fixture', results=results)), encoding='utf-8')
    output = tmp_path / 'findings.json'
    result = subprocess.run([
        sys.executable, '-m', 'main.pathfinder', 'scan', str(loot.parent), '--offline',
        '--no-color', '--hide-findings', '--output-json', str(output),
    ], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1], timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    document = json.loads(output.read_text(encoding='utf-8'))
    rows = document if isinstance(document, list) else document['findings']
    candidates = [row for row in rows if row['entity_type'] == 'username_candidate' and row['name'] == 'svc_fixture']
    assert {row['attributes']['url'] for row in candidates} == {
        f'https://fixture.test/path{index}/' for index in range(count)}
    references = next(row for row in rows if row['entity_type'] == 'hostname_candidate' and row['name'] == 'db.internal.test')
    assert len(references['attributes']['source_pages']) == count
    requests = [row for row in rows if row['entity_type'] == 'web_parameterized_url']
    assert {row['attributes']['url'] for row in requests} == {'https://fixture.test/shared?id=1'}
    assert len(requests[0]['attributes']['source_pages']) == count
    assert any('UNIQUE-EXPOSED-FIXTURE-KEY-987654321' in json.dumps(row) for row in rows)


def test_large_scan_logs_progress_and_retains_all_source_provenance(tmp_path):
    loot = tmp_path / 'loot' / 'fixture.test'
    loot.mkdir(parents=True)
    for index in range(75):
        (loot / f'webpage_https_443-{index}.html').write_text(
            '<html>username: svc_fixture</html>', encoding='utf-8')
    output = tmp_path / 'findings.json'
    result = subprocess.run([
        sys.executable, '-m', 'main.pathfinder', 'scan', str(loot.parent), '--offline',
        '--no-color', '--output-json', str(output),
    ], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1], timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Parsed 75/75 sources' in result.stdout
    assert '75 source(s)' in result.stdout
    assert 'exact repeats merged with provenance' in result.stdout
    assert 'Finding merge completed' in result.stdout
    assert len(result.stdout.splitlines()) < 100
    document = json.loads(output.read_text(encoding='utf-8'))
    rows = document if isinstance(document, list) else document['findings']
    candidate = next(row for row in rows if row['name'] == 'svc_fixture')
    assert len(candidate['attributes']['source_files']) == 75
    assert len(candidate['attributes']['discovery_provenance']) == 75
