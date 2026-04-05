"""Unit tests for dedup.dedup_vulns."""

from __future__ import annotations

import pytest

from sbom_pipeline.dedup import dedup_vulns
from sbom_pipeline.vuln_merger import VulnFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(
    cve_id: str,
    purl: str = "pkg:pypi/lib@1.0",
    score: float = 5.0,
    scanner: str = "trivy",
    name: str = "lib",
    version: str = "1.0",
) -> VulnFinding:
    return VulnFinding(
        cve_id=cve_id,
        component_name=name,
        component_version=version,
        component_purl=purl,
        cvss_score=score,
        severity="HIGH",
        description="desc",
        scanner=scanner,
    )


# ---------------------------------------------------------------------------
# Basic contract
# ---------------------------------------------------------------------------

def test_empty_list_returns_empty():
    assert dedup_vulns([]) == []


def test_single_finding_unchanged():
    findings = [_f("CVE-2024-0001")]
    assert dedup_vulns(findings) == findings


def test_unique_findings_all_kept():
    findings = [
        _f("CVE-2024-0001", "pkg:pypi/a@1.0"),
        _f("CVE-2024-0002", "pkg:pypi/a@1.0"),
        _f("CVE-2024-0001", "pkg:pypi/b@2.0"),
    ]
    result = dedup_vulns(findings)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# Deduplication by CVE + component
# ---------------------------------------------------------------------------

class TestDedupByCveAndComponent:
    def test_same_cve_same_purl_deduped_to_one(self):
        findings = [
            _f("CVE-2024-1111", "pkg:pypi/req@2.31", 7.5, "trivy"),
            _f("CVE-2024-1111", "pkg:pypi/req@2.31", 7.5, "depcheck"),
        ]
        assert len(dedup_vulns(findings)) == 1

    def test_same_cve_different_purls_kept_separately(self):
        findings = [
            _f("CVE-2024-1111", "pkg:pypi/a@1.0"),
            _f("CVE-2024-1111", "pkg:pypi/b@2.0"),
        ]
        assert len(dedup_vulns(findings)) == 2

    def test_different_cves_same_purl_kept_separately(self):
        findings = [
            _f("CVE-2024-0001", "pkg:pypi/a@1.0"),
            _f("CVE-2024-0002", "pkg:pypi/a@1.0"),
        ]
        assert len(dedup_vulns(findings)) == 2

    def test_three_scanners_same_cve_same_purl_deduped_to_one(self):
        findings = [
            _f("CVE-2024-9999", "pkg:pypi/x@3.0", 8.0, "trivy"),
            _f("CVE-2024-9999", "pkg:pypi/x@3.0", 8.0, "depcheck"),
            _f("CVE-2024-9999", "pkg:pypi/x@3.0", 8.0, "clair"),
        ]
        assert len(dedup_vulns(findings)) == 1


# ---------------------------------------------------------------------------
# CVSS score selection
# ---------------------------------------------------------------------------

class TestCvssSelection:
    def test_higher_score_wins(self):
        findings = [
            _f("CVE-2024-1111", "pkg:pypi/a@1.0", 5.0, "trivy"),
            _f("CVE-2024-1111", "pkg:pypi/a@1.0", 9.8, "depcheck"),
        ]
        result = dedup_vulns(findings)
        assert result[0].cvss_score == 9.8
        assert result[0].scanner == "depcheck"

    def test_lower_first_higher_second_picks_second(self):
        findings = [
            _f("CVE-2024-2222", "pkg:pypi/a@1.0", 3.0, "depcheck"),
            _f("CVE-2024-2222", "pkg:pypi/a@1.0", 7.0, "trivy"),
        ]
        result = dedup_vulns(findings)
        assert result[0].cvss_score == 7.0

    def test_equal_scores_keeps_first_encountered(self):
        f1 = _f("CVE-2024-3333", "pkg:pypi/a@1.0", 5.0, "trivy")
        f2 = _f("CVE-2024-3333", "pkg:pypi/a@1.0", 5.0, "depcheck")
        result = dedup_vulns([f1, f2])
        assert result[0].scanner == "trivy"

    def test_zero_score_is_valid(self):
        findings = [
            _f("CVE-2024-4444", "pkg:pypi/a@1.0", 0.0, "trivy"),
            _f("CVE-2024-4444", "pkg:pypi/a@1.0", 0.0, "depcheck"),
        ]
        assert len(dedup_vulns(findings)) == 1


# ---------------------------------------------------------------------------
# Fallback key (no purl)
# ---------------------------------------------------------------------------

class TestFallbackKey:
    def test_no_purl_uses_name_at_version(self):
        f1 = VulnFinding(
            cve_id="CVE-2024-5555",
            component_name="lib",
            component_version="1.0",
            component_purl="",
            cvss_score=5.0,
            severity="MEDIUM",
            description="",
            scanner="trivy",
        )
        f2 = VulnFinding(
            cve_id="CVE-2024-5555",
            component_name="lib",
            component_version="1.0",
            component_purl="",
            cvss_score=5.0,
            severity="MEDIUM",
            description="",
            scanner="depcheck",
        )
        assert len(dedup_vulns([f1, f2])) == 1

    def test_no_purl_different_versions_kept_separately(self):
        f1 = VulnFinding(
            cve_id="CVE-2024-5555",
            component_name="lib",
            component_version="1.0",
            component_purl="",
            cvss_score=5.0,
            severity="MEDIUM",
            description="",
            scanner="trivy",
        )
        f2 = VulnFinding(
            cve_id="CVE-2024-5555",
            component_name="lib",
            component_version="2.0",
            component_purl="",
            cvss_score=5.0,
            severity="MEDIUM",
            description="",
            scanner="trivy",
        )
        assert len(dedup_vulns([f1, f2])) == 2

    def test_purl_and_nopurl_are_distinct_keys(self):
        """Finding with purl and one without (same name@version) are different keys."""
        f_with_purl = _f("CVE-2024-6666", "pkg:pypi/lib@1.0", name="lib", version="1.0")
        f_no_purl = VulnFinding(
            cve_id="CVE-2024-6666",
            component_name="lib",
            component_version="1.0",
            component_purl="",
            cvss_score=5.0,
            severity="HIGH",
            description="",
            scanner="clair",
        )
        # purl key ≠ name@version key → both survive
        assert len(dedup_vulns([f_with_purl, f_no_purl])) == 2


# ---------------------------------------------------------------------------
# Return type & order preservation
# ---------------------------------------------------------------------------

def test_returns_list_of_vuln_findings():
    findings = [_f("CVE-2024-0001"), _f("CVE-2024-0002")]
    result = dedup_vulns(findings)
    assert isinstance(result, list)
    assert all(isinstance(r, VulnFinding) for r in result)


def test_insertion_order_preserved_for_unique_findings():
    cves = ["CVE-2024-0003", "CVE-2024-0001", "CVE-2024-0002"]
    findings = [_f(c) for c in cves]
    result = dedup_vulns(findings)
    assert [r.cve_id for r in result] == cves
