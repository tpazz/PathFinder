import json
import os
from unittest.mock import patch

from parsers.initial_foothold import webpage_identity_parser as parser


def source(tmp_path, results):
    path = tmp_path/'ffuf_2095.json'
    path.write_text(json.dumps({'results': results}), encoding='utf-8')
    bodies = tmp_path/'ffuf_pages_http_2095'
    bodies.mkdir(exist_ok=True)
    return path, bodies


def test_index_reads_once_without_dropping_response_urls_or_host_checks(tmp_path):
    parser._ffuf_result_index.cache_clear()
    results = [dict(resultfile=f'pages/body{i}', url=f'http://app.test:2095/path{i}')
               for i in range(100)]
    results.append(dict(resultfile='pages/body0', url='http://other.test:2095/alternate'))
    _, bodies = source(tmp_path, results)
    with patch.object(parser.json, 'load', wraps=json.load) as load:
        for i in range(100):
            assert parser._ffuf_result_source(str(bodies/f'body{i}'), 'app.test') == (
                2095, f'http://app.test:2095/path{i}')
        assert parser._ffuf_result_source(str(bodies/'body0'), 'other.test') == (
            2095, 'http://other.test:2095/alternate')
        assert parser._ffuf_result_source(str(bodies/'body0'), 'unrelated.test') is None
        assert load.call_count == 1


def test_changed_result_file_invalidates_cached_index_even_at_same_size(tmp_path):
    parser._ffuf_result_index.cache_clear()
    path, bodies = source(tmp_path, [dict(resultfile='body', url='http://app.test:2095/old')])
    assert parser._ffuf_result_source(str(bodies/'body'), 'app.test')[1].endswith('/old')
    previous = path.stat()
    path.write_text(path.read_text().replace('/old', '/new'))
    os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000_000))
    assert path.stat().st_size == previous.st_size
    assert parser._ffuf_result_source(str(bodies/'body'), 'app.test')[1].endswith('/new')


def test_missing_or_incomplete_results_can_be_retried(tmp_path):
    parser._ffuf_result_index.cache_clear()
    path, bodies = source(tmp_path, [])
    path.unlink()
    assert parser._ffuf_result_source(str(bodies/'body'), 'app.test') is None
    path.write_text('{incomplete')
    assert parser._ffuf_result_source(str(bodies/'body'), 'app.test') is None
    path.write_text(json.dumps({'results': [dict(resultfile='body', url='http://app.test:2095/found')]}))
    assert parser._ffuf_result_source(str(bodies/'body'), 'app.test') == (
        2095, 'http://app.test:2095/found')
