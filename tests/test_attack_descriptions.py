"""Tests for detailed attack description enrichment."""

from web_scanner.attack_descriptions import get_attack_description, enrich_findings, ATTACK_MAP, GENERIC_ATTACK_DESC


class TestGetAttackDescription:
    def test_sql_injection(self):
        desc = get_attack_description("SQL Injection via parameter 'id'")
        assert isinstance(desc, str)
        assert "atk-impact" in desc
        assert "UNION" in desc
        assert "sqlmap" in desc.lower()

    def test_xss(self):
        desc = get_attack_description("Reflected XSS via search")
        assert "atk-impact" in desc
        assert "document.cookie" in desc
        assert "atk-section" in desc

    def test_command_injection(self):
        desc = get_attack_description("Command injection (semicolon) via 'cmd'")
        assert "reverse shell" in desc.lower() or "reverse_shell" in desc.lower().replace(" ", "_")
        assert "atk-list" in desc

    def test_cors(self):
        desc = get_attack_description("CORS misconfiguration \u2014 reflected origin")
        assert "atk-impact" in desc

    def test_csrf(self):
        desc = get_attack_description("Form without CSRF protection")
        assert "atk-impact" in desc
        assert "unintended" in desc.lower()

    def test_path_traversal(self):
        desc = get_attack_description("Path Traversal via /download")
        assert "etc/passwd" in desc

    def test_ssrf(self):
        desc = get_attack_description("SSRF via URL parameter")
        assert "metadata" in desc.lower()

    def test_xxe(self):
        desc = get_attack_description("XXE vulnerability (file_read_unix)")
        assert "file://" in desc

    def test_backup_file(self):
        desc = get_attack_description("Exposed file: .git/config")
        assert ("credentials" in desc.lower() or "secrets" in desc.lower()
                or "git" in desc.lower())

    def test_hsts(self):
        desc = get_attack_description("Missing HSTS header")
        assert "sslstrip" in desc.lower()

    def test_unknown_fallback(self):
        desc = get_attack_description("Some obscure unknown vulnerability xyz")
        assert isinstance(desc, str)
        assert "atk-impact" in desc
        assert "entry point" in desc.lower()

    def test_trace_enabled(self):
        desc = get_attack_description("HTTP TRACE enabled on /")
        assert "cross-site tracing" in desc.lower() or "xst" in desc.lower()


class TestEnrichFindings:
    def test_enrich_adds_attack_key(self):
        findings = [
            {"severity": "CRITICAL", "title": "SQL Injection via 'id'", "detail": "..."},
            {"severity": "HIGH", "title": "Reflected XSS via search", "detail": "..."},
        ]
        enriched = enrich_findings(findings)
        for f in enriched:
            assert "attack" in f
            assert isinstance(f["attack"], str)
            assert "atk-impact" in f["attack"]

    def test_enrich_preserves_original(self):
        findings = [
            {"severity": "MEDIUM", "title": "Missing HSTS", "detail": "no STS"},
        ]
        enriched = enrich_findings(findings)
        assert enriched[0]["severity"] == "MEDIUM"
        assert enriched[0]["title"] == "Missing HSTS"
        assert enriched[0]["detail"] == "no STS"
        assert "attack" in enriched[0]

    def test_enrich_empty_list(self):
        assert enrich_findings([]) == []

    def test_enrich_unknown_gets_generic(self):
        findings = [{"severity": "INFO", "title": "Weird unknown issue", "detail": "..."}]
        enriched = enrich_findings(findings)
        assert "atk-impact" in enriched[0]["attack"]
        assert "entry point" in enriched[0]["attack"].lower()


class TestAttackMapData:
    def test_all_have_required_keys(self):
        for keyword, info in ATTACK_MAP.items():
            assert "impact" in info, f"Missing impact for: {keyword}"
            assert "scenarios" in info, f"Missing scenarios for: {keyword}"
            assert "chain_with" in info, f"Missing chain_with for: {keyword}"
            assert "real_world" in info, f"Missing real_world for: {keyword}"
            assert isinstance(info["scenarios"], list), f"scenarios must ser lista para: {keyword}"

    def test_scenarios_not_empty(self):
        for keyword, info in ATTACK_MAP.items():
            assert len(info["scenarios"]) > 0, f"No attack scenarios for: {keyword}"

    def test_generic_has_required_keys(self):
        assert "impact" in GENERIC_ATTACK_DESC
        assert "scenarios" in GENERIC_ATTACK_DESC
