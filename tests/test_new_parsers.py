import json
import tempfile
import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.active_directory.certipy_parser import parse_certipy_json
from parsers.active_directory.kerberos_parser import parse_getuserspns_output
from parsers.active_directory.secretsdump_parser import parse_secretsdump
from parsers.initial_foothold.ffuf_parser import parse_ffuf_json
from parsers.initial_foothold.dns_parser import parse_dns_output
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.netexec_parser import parse_netexec_output
from parsers.initial_foothold.nmap_parser import parse_nmap_xml
from parsers.initial_foothold.nuclei_parser import parse_nuclei_jsonl
from parsers.initial_foothold.openapi_parser import parse_openapi_json
from parsers.initial_foothold.smbmap_parser import parse_smbmap_output
from parsers.initial_foothold.web_url_helpers import classify_parameter_names, parameterized_url_finding
from parsers.initial_foothold.whatweb_parser import parse_whatweb_json
from parsers.initial_foothold.wpscan_parser import parse_wpscan_json
from parsers.initial_foothold.webpage_identity_parser import (
    MAX_HTML_ANALYSIS_CHARS,
    _ffuf_result_source,
    extract_parameter_candidates,
    extract_response_evidence,
    parse_webpage_html,
)
from main.pathfinder import _sniff_file_type


class NewParserTests(unittest.TestCase):
    def _write(self, content, suffix=".txt"):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_parameterized_url_rejects_out_of_range_port(self):
        self.assertIsNone(parameterized_url_finding(
            "10.0.0.5", 80, "test", "http://10.0.0.5:99999/?q=x",
        ))

    def test_ffuf_source_rejects_out_of_range_port(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pages = root / "ffuf_pages_http_80"
            pages.mkdir()
            response = pages / "hash"
            response.write_text("body", encoding="utf-8")
            (root / "ffuf_80.json").write_text(json.dumps({"results": [{
                "resultfile": "hash", "url": "http://10.0.0.5:99999/?q=x",
            }]}), encoding="utf-8")
            self.assertIsNone(_ffuf_result_source(str(response), "10.0.0.5"))

    def test_webpage_regex_analysis_is_size_bounded(self):
        content = "x" * (MAX_HTML_ANALYSIS_CHARS + 10) + "/late?q=value"
        findings = extract_parameter_candidates(
            content, "10.0.0.5", 80, "http://10.0.0.5",
        )
        self.assertEqual(findings, [])

    def test_generic_response_extracts_credentials_material_hosts_and_paths(self):
        body = json.dumps({
            "username": "svc_web",
            "password": "CorrectHorse!",
            "api_key": "token-value-123456",
            "database_url": "postgresql://db_user:DbPass!@db.internal:5432/app",
            "callback": "http://admin.lab.htb:8080/hook",
            "document_root": "/srv/www/app",
        })
        findings = extract_response_evidence(body, "10.0.0.5", 80, "http://10.0.0.5/config")
        validate_findings(findings)
        credentials = {(f["name"], f["attributes"].get("password"))
                       for f in findings if f["entity_type"] == "credential"}
        self.assertIn(("svc_web", "CorrectHorse!"), credentials)
        self.assertIn(("db_user", "DbPass!"), credentials)
        self.assertTrue(any(f["entity_type"] == "credential_material"
                            and f["name"] == "api_key" for f in findings))
        self.assertTrue(any(f["entity_type"] == "hostname_candidate"
                            and f["name"] == "db.internal" for f in findings))
        self.assertTrue(any(f["entity_type"] == "filesystem_path_candidate"
                            and f["name"] == "/srv/www/app" for f in findings))

    def test_context_aware_parameter_classification(self):
        categories = set(classify_parameter_names([
            "file", "callback_url", "ping_host", "xml_payload", "search_query",
            "account_id", "template",
        ]))
        self.assertIn(("file", "path_traversal_lfi"), categories)
        self.assertIn(("callback_url", "ssrf"), categories)
        self.assertIn(("ping_host", "command_injection"), categories)
        self.assertIn(("xml_payload", "xxe"), categories)
        self.assertIn(("search_query", "sqli"), categories)
        self.assertIn(("account_id", "idor"), categories)
        self.assertIn(("template", "ssti"), categories)

    def test_openapi_envelope_promotes_bounded_endpoints_and_parameter_triage(self):
        payload = {
            "tool": "one-shot-enum",
            "type": "openapi_enum",
            "host": "10.0.0.5",
            "port": 8080,
            "base_url": "http://10.0.0.5:8080",
            "openapi_url": "http://10.0.0.5:8080/openapi.json",
            "openapi_title": "Lab API",
            "openapi_version": "3.0.3",
            "discovery_command": "python one-shot-enum.py 10.0.0.5 --power --pathfinder",
            "endpoints": [{
                "method": "POST",
                "path": "/api/files/{account_id}",
                "operation_id": "uploadFile",
                "security_declared": True,
                "parameters": [
                    {"name": "account_id", "location": "path", "required": True, "type": "string"},
                    {"name": "file", "location": "body", "required": True, "type": "string"},
                    {"name": "callback_url", "location": "body", "required": False, "type": "string"},
                ],
            }],
        }
        path = self._write(json.dumps(payload), ".json")
        self.assertEqual(_sniff_file_type(path), "openapi_json")
        findings = parse_openapi_json(path)
        validate_findings(findings)
        self.assertEqual(findings[0]["entity_type"], "api_surface")
        endpoint = next(item for item in findings if item["entity_type"] == "api_endpoint")
        self.assertEqual(endpoint["name"], "POST /api/files/{account_id}")
        self.assertEqual(endpoint["attributes"]["parameters"],
                         ["account_id", "file", "callback_url"])
        candidates = {item["name"] for item in findings
                      if item["entity_type"] == "web_parameter_candidate"}
        self.assertIn("idor:account_id", candidates)
        self.assertIn("path_traversal_lfi:file", candidates)
        self.assertIn("ssrf:callback_url", candidates)

    def test_raw_openapi_document_is_supported_without_calling_operations(self):
        payload = {
            "openapi": "3.0.0",
            "info": {"title": "Raw API"},
            "servers": [{"url": "https://api.corp.htb"}],
            "paths": {
                "/users/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "integer"}}],
                    "get": {"operationId": "getUser", "responses": {"200": {}}},
                },
            },
        }
        path = self._write(json.dumps(payload), ".json")
        self.assertEqual(_sniff_file_type(path), "openapi_json")
        findings = parse_openapi_json(path)
        endpoint = next(item for item in findings if item["name"] == "GET /users/{id}")
        self.assertEqual(endpoint["host"], "api.corp.htb")
        self.assertEqual(endpoint["port"], 443)
        self.assertTrue(any(item["name"] == "idor:id" for item in findings))

    def test_raw_openapi_resolves_refs_and_operation_parameter_overrides(self):
        payload = {
            "openapi": "3.0.3",
            "servers": [{"url": "https://{tenant}.corp.htb/v1",
                         "variables": {"tenant": {"default": "api"}}}],
            "components": {
                "parameters": {
                    "Filter": {"name": "filter", "in": "query", "required": False,
                               "schema": {"type": "string"}},
                },
                "schemas": {
                    "Update": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "integer"},
                            "callback_url": {"type": "string"},
                        },
                    },
                },
            },
            "paths": {
                "/users/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                        {"$ref": "#/components/parameters/Filter"},
                    ],
                    "patch": {
                        "parameters": [
                            {"name": "filter", "in": "query", "required": True,
                             "schema": {"type": "integer"}},
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Update"},
                                },
                            },
                        },
                    },
                },
            },
        }
        findings = parse_openapi_json(self._write(json.dumps(payload), ".json"))
        endpoint = next(item for item in findings if item["entity_type"] == "api_endpoint")
        details = {(item["name"], item["location"]): item
                   for item in endpoint["attributes"]["parameter_details"]}
        self.assertEqual(endpoint["attributes"]["url"],
                         "https://api.corp.htb/v1/users/{id}")
        self.assertEqual(details[("filter", "query")]["type"], "integer")
        self.assertTrue(details[("filter", "query")]["required"])
        self.assertIn(("id", "path"), details)
        self.assertIn(("id", "body"), details)
        self.assertIn(("callback_url", "body"), details)

    def test_raw_swagger_uses_scheme_host_port_and_base_path(self):
        payload = {
            "swagger": "2.0",
            "info": {"title": "Legacy API"},
            "schemes": ["https"],
            "host": "legacy.corp.htb:8443",
            "basePath": "/api/v2",
            "paths": {"/users": {"get": {"responses": {"200": {}}}}},
        }
        findings = parse_openapi_json(self._write(json.dumps(payload), ".json"))
        endpoint = next(item for item in findings if item["entity_type"] == "api_endpoint")
        self.assertEqual(endpoint["host"], "legacy.corp.htb")
        self.assertEqual(endpoint["port"], 8443)
        self.assertEqual(endpoint["attributes"]["url"],
                         "https://legacy.corp.htb:8443/api/v2/users")

    def test_dns_parser_emits_records_and_hostname_candidates(self):
        content = (
            "corp.htb. 3600 IN NS dc01.corp.htb.\n"
            "dc01.corp.htb. 300 IN A 10.10.10.10\n"
            "_ldap._tcp.dc._msdcs.corp.htb. 300 IN SRV 0 100 389 dc01.corp.htb.\n"
        )
        findings = parse_dns_output(self._write(content, "_dns_corp.txt"), "10.10.10.10")
        validate_findings(findings)
        self.assertEqual(len([f for f in findings if f["entity_type"] == "dns_record"]), 3)
        names = {f["name"] for f in findings if f["entity_type"] == "hostname_candidate"}
        self.assertIn("dc01.corp.htb", names)
        self.assertIn("corp.htb", names)

    def test_nmap_hostnames_redirects_and_tls_names_feed_hostname_candidates(self):
        xml = """<?xml version='1.0'?>
        <nmaprun args='nmap -sC -sV 10.0.0.5'><host>
          <address addr='10.0.0.5' addrtype='ipv4'/>
          <hostnames><hostname name='web.corp.htb' type='PTR'/></hostnames>
          <ports><port protocol='tcp' portid='443'><state state='open'/>
            <service name='https'/>
            <script id='ssl-cert' output='Subject: CN=admin.corp.htb&#10;Subject Alternative Name: DNS:api.corp.htb'/>
          </port></ports>
        </host></nmaprun>"""
        findings = parse_nmap_xml(self._write(xml, ".xml"))
        validate_findings(findings)
        names = {f["name"] for f in findings if f["entity_type"] == "hostname_candidate"}
        self.assertEqual(names, {"web.corp.htb", "admin.corp.htb", "api.corp.htb"})

    def test_ffuf(self):
        payload = {
            "commandline": "ffuf -u http://10.10.10.10/FUZZ -w wl",
            "time": "now",
            "results": [
                {"input": {"FUZZ": "admin"}, "status": 200, "length": 100, "url": "http://10.10.10.10/admin", "host": "10.10.10.10:80"},
                {"input": {"FUZZ": "index.html"}, "status": 200, "length": 50, "url": "http://10.10.10.10/index.html", "host": "10.10.10.10:80"},
            ],
            "config": {},
        }
        findings = parse_ffuf_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["entity_type"] == "web_content" for f in findings))
        admin = next(f for f in findings if f["name"] == "/admin")
        self.assertEqual(admin["port"], 80)
        self.assertTrue(admin["attributes"]["is_directory_guess"])
        self.assertEqual(admin["attributes"]["discovery_command"], payload["commandline"])
        self.assertFalse(next(f for f in findings if f["name"] == "/index.html")["attributes"]["is_directory_guess"])

    def test_ffuf_vhost_results_become_virtual_hosts(self):
        payload = {
            "commandline": "ffuf -u http://10.0.0.5/ -H 'Host: FUZZ.corp.htb' -w wl",
            "results": [{
                "input": {"FUZZ": "admin"}, "status": 200, "length": 321,
                "url": "http://10.0.0.5/", "host": "10.0.0.5:80",
            }],
        }
        findings = parse_ffuf_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["entity_type"], "virtual_host")
        self.assertEqual(findings[0]["name"], "admin.corp.htb")

    def test_webpage_extracts_candidates_without_promoting_them_to_users(self):
        page = """
        <html><body>
          <p>Terminal Services account: ts_svc</p>
          <p>Contact jane.doe@example.test for access.</p>
          <script>const fake = 'ignored_svc';</script>
        </body></html>
        """
        path = self._write(page, "_webpage_http_8080.html")
        findings = parse_webpage_html(path, "10.0.0.5")
        validate_findings(findings)
        names = {finding["name"] for finding in findings}
        self.assertIn("ts_svc", names)
        self.assertIn("jane.doe", names)
        self.assertNotIn("ignored_svc", names)
        identity_findings = [f for f in findings if f["entity_type"] == "username_candidate"]
        self.assertTrue(all(finding["entity_type"] == "username_candidate"
                            for finding in identity_findings))
        candidate = next(finding for finding in findings if finding["name"] == "ts_svc")
        self.assertEqual(candidate["port"], 8080)
        self.assertEqual(candidate["attributes"]["confidence"], "high")
        self.assertTrue(candidate["attributes"]["requires_manual_validation"])

    def test_webpage_extracts_every_identity_from_labelled_table_column(self):
        page = """
        <table>
          <tr><th>Date</th><th>Activity</th><th>User</th></tr>
          <tr><td>2026-03-12</td><td>Publication indexed</td><td>r.chen</td></tr>
          <tr><td>2026-03-08</td><td>Dataset updated</td><td>m.silva</td></tr>
          <tr><td>2026-03-05</td><td>Benchmark added</td><td>j.park</td></tr>
          <tr><td>2026-03-01</td><td>Pipeline updated</td><td>ts_svc</td></tr>
        </table>
        """
        findings = parse_webpage_html(
            self._write(page, "_webpage_http_8080_dashboard.html"), "192.168.129.14",
        )
        validate_findings(findings)

        candidates = {f["name"]: f for f in findings if f["entity_type"] == "username_candidate"}
        self.assertEqual(set(candidates), {"r.chen", "m.silva", "j.park", "ts_svc"})
        self.assertTrue(all(f["attributes"]["confidence"] == "high" for f in candidates.values()))
        self.assertTrue(all("table column labelled user" in f["attributes"]["extraction_reason"]
                            for name, f in candidates.items() if name != "ts_svc"))
        self.assertTrue(all(f["attributes"]["requires_manual_validation"]
                            for f in candidates.values()))

    def test_ffuf_stored_response_resolves_the_discovered_page_url(self):
        with tempfile.TemporaryDirectory() as directory:
            host_dir = Path(directory) / "192.168.129.14"
            body_dir = host_dir / "ffuf_pages_http_8080"
            body_dir.mkdir(parents=True)
            body = body_dir / "a1b2c3"
            body.write_text(
                "GET /dashboard HTTP/1.1\r\nHost: 192.168.129.14:8080\r\n\r\n"
                "---- ↑ Request ---- Response ↓ ----\n\n"
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                "<table><tr><th>User</th></tr><tr><td>r.chen</td></tr></table>",
                encoding="utf-8",
            )
            (host_dir / "ffuf_8080.json").write_text(json.dumps({
                "results": [{
                    "status": 200,
                    "url": "http://192.168.129.14:8080/dashboard",
                    "resultfile": "ffuf_pages_http_8080/a1b2c3",
                }],
            }), encoding="utf-8")

            findings = parse_webpage_html(str(body), "192.168.129.14")

        candidate = next(f for f in findings if f["name"] == "r.chen")
        self.assertEqual(candidate["port"], 8080)
        self.assertEqual(candidate["attributes"]["url"],
                         "http://192.168.129.14:8080/dashboard")

    def test_ffuf_request_headers_are_not_treated_as_response_evidence(self):
        capture = (
            "GET / HTTP/1.1\r\nPassword: request-only-secret\r\n\r\n"
            "---- ↑ Request ---- Response ↓ ----\n\n"
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            '{"status":"ok"}'
        )
        findings = parse_webpage_html(
            self._write(capture, "_webpage_http_80.html"), "10.0.0.5",
        )
        self.assertFalse(any(
            (f.get("attributes") or {}).get("password") == "request-only-secret"
            for f in findings
        ))

    def test_webpage_extracts_same_target_parameter_candidates(self):
        page = """
        <html><body>
          <a href="/items.php?id=4&amp;sort=name">Item</a>
          <a href="https://external.test/item.php?id=9">External</a>
          <a href="/?utm_source=lab">Tracked home</a>
          <script>
            fetch('/api/item?id=7');
            fetch('?view=compact#client-only');
            const staticAsset = '/assets/app.js?v=2';
          </script>
          <form method="get" action="/search">
            <input name="q" value="test">
            <input name="page">
          </form>
          <form method="post" action="/login">
            <input name="username">
            <input name="password" type="password">
            <input name="csrf" type="hidden" value="token">
            <input name="submit" type="submit" value="Login">
          </form>
        </body></html>
        """
        path = self._write(page, "_webpage_http_8080.html")
        findings = parse_webpage_html(path, "10.0.0.5")
        validate_findings(findings)

        get_candidates = [f for f in findings if f["entity_type"] == "web_parameterized_url"]
        urls = {f["attributes"]["url"] for f in get_candidates}
        self.assertIn("http://10.0.0.5:8080/items.php?id=4&sort=name", urls)
        self.assertIn("http://10.0.0.5:8080/api/item?id=7", urls)
        self.assertIn("http://10.0.0.5:8080/?view=compact", urls)
        self.assertIn("http://10.0.0.5:8080/search?q=test&page=1", urls)
        self.assertFalse(any("external.test" in url for url in urls))
        self.assertFalse(any("app.js" in url for url in urls))
        self.assertFalse(any("utm_source" in url for url in urls))
        self.assertTrue(all(f["attributes"]["candidate_only"] for f in get_candidates))
        self.assertTrue(all(f["attributes"]["source_page"] == "http://10.0.0.5:8080"
                            for f in get_candidates))

        posts = [f for f in findings if f["entity_type"] == "web_parameterized_request"]
        self.assertEqual(len(posts), 1)
        post = posts[0]
        self.assertEqual(post["attributes"]["url"], "http://10.0.0.5:8080/login")
        self.assertEqual(post["attributes"]["method"], "POST")
        self.assertEqual(post["attributes"]["data"], "username=1&password=1&csrf=token")
        self.assertEqual(post["attributes"]["parameters"], ["csrf", "password", "username"])
        self.assertTrue(post["attributes"]["requires_manual_validation"])

    def test_ffuf_emits_sqlmap_candidate_for_parameterized_url(self):
        payload = {
            "commandline": "ffuf -u http://10.10.10.10/FUZZ -w wl",
            "results": [
                {"input": {"FUZZ": "item.php?id=1"}, "status": 200, "length": 100,
                 "url": "http://10.10.10.10/item.php?id=1", "host": "10.10.10.10:80"},
            ],
            "config": {},
        }
        findings = parse_ffuf_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        candidate = next(f for f in findings if f["entity_type"] == "web_parameterized_url")
        self.assertEqual(candidate["attributes"]["url"], "http://10.10.10.10/item.php?id=1")
        self.assertEqual(candidate["attributes"]["parameters"], ["id"])
        self.assertEqual(candidate["attributes"]["discovery_command"], payload["commandline"])

    def test_gobuster_and_nikto_emit_sqlmap_candidates_for_parameterized_urls(self):
        gobuster_findings = parse_gobuster_output(
            self._write("/search.php?q=test (Status: 200) [Size: 10]\n"),
            "10.10.10.10",
            80,
        )
        nikto_payload = {
            "host": "10.10.10.11",
            "port": "8080",
            "vulnerabilities": [{"id": "001", "msg": "/view.php?page=home might be interesting",
                                 "url": "/view.php?page=home", "method": "GET"}],
        }
        nikto_findings = parse_nikto_json(self._write(json.dumps(nikto_payload), ".json"))
        validate_findings(gobuster_findings + nikto_findings)

        urls = {f["attributes"]["url"] for f in gobuster_findings + nikto_findings
                if f["entity_type"] == "web_parameterized_url"}
        self.assertIn("http://10.10.10.10:80/search.php?q=test", urls)
        self.assertIn("http://10.10.10.11:8080/view.php?page=home", urls)

    def test_parameterized_url_helper_uses_https_for_common_alt_tls_ports(self):
        finding = parameterized_url_finding("10.10.10.10", 8443, "test", "/search.php?q=test")

        self.assertIsNotNone(finding)
        self.assertEqual(finding["attributes"]["url"], "https://10.10.10.10:8443/search.php?q=test")

    def test_nuclei(self):
        lines = [
            json.dumps({"template-id": "CVE-2021-41773", "info": {"name": "Apache Path Traversal", "severity": "high",
                        "classification": {"cve-id": ["CVE-2021-41773"], "cvss-score": 7.5}},
                        "matched-at": "http://10.10.10.10/cgi-bin", "host": "http://10.10.10.10"}),
            json.dumps({"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info"},
                        "matched-at": "http://10.10.10.10"}),
        ]
        findings = parse_nuclei_jsonl(self._write("\n".join(lines) + "\n", ".jsonl"))
        validate_findings(findings)
        self.assertEqual(len(findings), 2)
        vuln = next(f for f in findings if f["name"] == "CVE-2021-41773")
        self.assertEqual(vuln["entity_type"], "vulnerability")
        self.assertEqual(vuln["attributes"]["severity"], "high")
        info = next(f for f in findings if f["attributes"]["severity"] == "info")
        self.assertEqual(info["entity_type"], "information_leak")

    def test_nuclei_emits_sqlmap_candidate_for_parameterized_match(self):
        line = json.dumps({"template-id": "reflected-param", "info": {"name": "Reflected parameter", "severity": "info"},
                           "matched-at": "http://10.10.10.10/product.php?cat=2"})
        findings = parse_nuclei_jsonl(self._write(line + "\n", ".jsonl"))
        validate_findings(findings)
        candidate = next(f for f in findings if f["entity_type"] == "web_parameterized_url")
        self.assertEqual(candidate["attributes"]["parameters"], ["cat"])

    def test_wpscan(self):
        payload = {
            "target_url": "http://10.10.10.10/",
            "version": {"number": "5.8", "status": "insecure",
                        "vulnerabilities": [{"title": "WP <5.8.1 SQLi", "references": {"cve": ["2021-1234"]}}]},
            "main_theme": {"slug": "twentytwentyone", "version": {"number": "1.4"}, "vulnerabilities": []},
            "plugins": {"contact-form-7": {"slug": "contact-form-7", "version": {"number": "5.4"},
                        "vulnerabilities": [{"title": "CF7 RCE", "references": {"cve": ["2020-0001"]}}]}},
            "users": {"admin": {"id": 1}},
        }
        findings = parse_wpscan_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        core = next(f for f in findings if f["name"] == "WordPress")
        self.assertEqual(core["version"], "5.8")
        self.assertTrue(any(f["name"] == "WordPress plugin: contact-form-7" for f in findings))
        self.assertTrue(any(f["entity_type"] == "vulnerability" for f in findings))
        self.assertTrue(any(f["entity_type"] == "confirmed_username" and f["name"] == "admin" for f in findings))

    def test_smbmap(self):
        content = (
            "[+] IP: 10.10.10.10:445\tName: dc01.corp.local\n"
            "\tDisk                                                  Permissions\tComment\n"
            "\t----                                                  -----------\t-------\n"
            "\tADMIN$                                                NO ACCESS\tRemote Admin\n"
            "\tIPC$                                                  READ ONLY\tRemote IPC\n"
            "\tbackups                                               READ, WRITE\t\n"
        )
        findings = parse_smbmap_output(self._write(content), "10.10.10.10")
        validate_findings(findings)
        shares = {f["name"] for f in findings if f["entity_type"] == "share"}
        self.assertIn("backups", shares)
        self.assertIn("IPC$", shares)
        writable = [f for f in findings if f["name"] == "writable_smb_share"]
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0]["attributes"]["share"], "backups")

    def test_netexec(self):
        content = (
            "SMB   10.10.10.10   445   DC01   [*] Windows 10.0 Build 17763 (name:DC01) (domain:corp.local) (signing:False) (SMBv1:False)\n"
            "SMB   10.10.10.10   445   DC01   [+] corp.local\\admin:Password123 (Pwn3d!)\n"
            "SMB   10.10.10.10   445   DC01   [+] corp.local\\svc:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
            "SMB   10.10.10.10   445   DC01   [-] corp.local\\baduser:wrong STATUS_LOGON_FAILURE\n"
            "SMB   10.10.10.10   445   DC01   [*] Enumerated shares\n"
            "SMB   10.10.10.10   445   DC01   Share           Permissions     Remark\n"
            "SMB   10.10.10.10   445   DC01   -----           -----------     ------\n"
            "SMB   10.10.10.10   445   DC01   ADMIN$                          Remote Admin\n"
            "SMB   10.10.10.10   445   DC01   data            READ,WRITE      Data share\n"
        )
        findings = parse_netexec_output(self._write(content, ".log"), "10.10.10.10")
        validate_findings(findings)

        creds = [f for f in findings if f["entity_type"] == "credential"]
        self.assertEqual({c["name"] for c in creds}, {"admin", "svc"})
        admin = next(c for c in creds if c["name"] == "admin")
        self.assertEqual(admin["attributes"]["password"], "Password123")
        svc = next(c for c in creds if c["name"] == "svc")
        self.assertEqual(svc["attributes"]["hash_type"], "NTLM")
        self.assertIsNone(svc["attributes"]["password"])

        self.assertEqual(len([f for f in findings if f["name"] == "admin_access_validated"]), 1)
        self.assertEqual(len([f for f in findings if f["name"] == "smb_signing_disabled"]), 1)
        self.assertEqual(len([f for f in findings if f["name"] == "writable_smb_share"]), 1)

    def test_secretsdump(self):
        content = (
            "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "CORP.LOCAL\\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::\n"
            "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::\n"
        )
        findings = parse_secretsdump(self._write(content), "10.10.10.10")
        validate_findings(findings)
        names = {f["name"] for f in findings}
        self.assertEqual(names, {"Administrator", "svc_sql", "DC01$"})
        self.assertTrue(all(f["entity_type"] == "credential" for f in findings))
        svc = next(f for f in findings if f["name"] == "svc_sql")
        self.assertEqual(svc["attributes"]["hash_type"], "NTLM")
        self.assertEqual(svc["attributes"]["domain"], "CORP.LOCAL")
        self.assertTrue(next(f for f in findings if f["name"] == "DC01$")["attributes"]["machine_account"])

    def test_getuserspns(self):
        content = "$krb5tgs$23$*svc_sql$CORP.LOCAL$cifs/svc.corp.local*$abcdef0123456789\n"
        findings = parse_getuserspns_output(self._write(content), "CORP.LOCAL")
        validate_findings(findings)
        self.assertEqual(len([f for f in findings if f["name"] == "kerberoastable_user"]), 1)
        creds = [f for f in findings if f["entity_type"] == "credential"]
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["name"], "svc_sql")
        self.assertIn("13100", creds[0]["attributes"]["hash_type"])

    def test_certipy(self):
        payload = {
            "Certificate Authorities": {
                "0": {"CA Name": "CORP-DC-CA",
                      "[!] Vulnerabilities": {"ESC8": "Web Enrollment permits NTLM relay"}},
            },
            "Certificate Templates": {
                "0": {"Template Name": "VulnTemplate", "Enabled": True,
                      "Enrollment Rights": ["CORP\\Domain Users"],
                      "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject + client auth"}},
            },
        }
        findings = parse_certipy_json(self._write(json.dumps(payload), ".json"), "CORP.LOCAL")
        validate_findings(findings)
        self.assertEqual({finding["name"] for finding in findings}, {"adcs_esc1", "adcs_esc8"})
        esc1 = next(finding for finding in findings if finding["name"] == "adcs_esc1")
        self.assertEqual(esc1["attributes"]["esc"], "ESC1")
        self.assertEqual(esc1["attributes"]["template"], "VulnTemplate")
        self.assertEqual(esc1["attributes"]["enrollment_principals"], ["CORP\\Domain Users"])
        esc8 = next(finding for finding in findings if finding["name"] == "adcs_esc8")
        self.assertEqual(esc8["attributes"]["template"], "CORP-DC-CA")

    def test_post_exploitation_parser_files_use_collector_names(self):
        parser_dir = Path(__file__).parent.parent / "parsers" / "post_exploitation"
        self.assertTrue((parser_dir / "ai_peas_parser.py").is_file())
        self.assertTrue((parser_dir / "mini_peas_parser.py").is_file())
        self.assertFalse((parser_dir / "ai_loot_parser.py").exists())
        self.assertFalse((parser_dir / "manual_privesc_parser.py").exists())


    def test_nuclei_coerces_non_string_fields(self):
        line = json.dumps({
            "template-id": 42,
            "info": {"severity": 7, "classification": {"cve-id": [123, None]}},
            "matched-at": 12345,
        })
        findings = parse_nuclei_jsonl(self._write(line + "\n", ".jsonl"))
        self.assertEqual(findings[0]["name"], "123")
        self.assertEqual(findings[0]["attributes"]["severity"], "7")

    def test_whatweb_skips_non_mapping_records_and_plugins(self):
        payload = [None, {"target": 123, "plugins": []}, {
            "target": "http://10.0.0.5", "plugins": {
                "Broken": None,
                123: {"version": [7]},
            },
        }]
        findings = parse_whatweb_json(self._write(json.dumps(payload), ".json"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "123")
        self.assertEqual(findings[0]["version"], "7")


if __name__ == "__main__":
    unittest.main()
