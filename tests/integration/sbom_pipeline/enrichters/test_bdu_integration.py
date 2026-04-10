from pathlib import Path
import os
import sys

import pytest
import urllib3
from urllib3.exceptions import InsecureRequestWarning

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sbom_pipeline.enrichters import bdu


urllib3.disable_warnings(InsecureRequestWarning)

pytestmark = pytest.mark.integration


def _known_cve() -> str:
    return os.getenv("BDU_TEST_CVE", "CVE-2026-24017")


def _expected_bdu_id() -> str:
    expected_bdu_id = os.getenv("BDU_EXPECTED_ID", "BDU:2026-03213")
    if not expected_bdu_id:
        pytest.skip("Set BDU_EXPECTED_ID to run strict BDU integration assertions")
    return expected_bdu_id


@pytest.mark.skipif(
    os.getenv("BDU_INTEGRATION") != "1",
    reason="Set BDU_INTEGRATION=1 to run real BDU integration tests",
)
def test_get_bdu_ids_by_cves_returns_expected_mapping_for_known_cve():
    cve_id = _known_cve()
    expected_bdu_id = _expected_bdu_id()

    result = bdu.get_bdu_ids_by_cves([cve_id])

    assert result == {cve_id: expected_bdu_id}


@pytest.mark.skipif(
    os.getenv("BDU_INTEGRATION") != "1",
    reason="Set BDU_INTEGRATION=1 to run real BDU integration tests",
)
def test_get_bdu_ids_by_cves_skips_unknown_cve():
    known_cve_id = _known_cve()
    expected_bdu_id = _expected_bdu_id()
    unknown_cve_id = "CVE-2099-99999"

    result = bdu.get_bdu_ids_by_cves([known_cve_id, unknown_cve_id])

    assert result[known_cve_id] == expected_bdu_id
    assert unknown_cve_id not in result
    assert len(result) == 1


@pytest.mark.skipif(
    os.getenv("BDU_INTEGRATION") != "1",
    reason="Set BDU_INTEGRATION=1 to run real BDU integration tests",
)
def test_get_bdu_ids_by_cves_filters_blank_values_and_unknowns():
    known_cve_id = _known_cve()
    expected_bdu_id = _expected_bdu_id()
    unknown_cve_id = "CVE-2099-99999"

    result = bdu.get_bdu_ids_by_cves(["", "   ", known_cve_id, unknown_cve_id])

    assert result == {known_cve_id: expected_bdu_id}


@pytest.mark.skipif(
    os.getenv("BDU_INTEGRATION") != "1",
    reason="Set BDU_INTEGRATION=1 to run real BDU integration tests",
)
def test_get_bdu_ids_by_cves_skips_non_cve_format_identifiers():
    """Non-CVE identifiers (GHSA, plain strings) must be silently ignored."""
    known_cve_id = _known_cve()
    expected_bdu_id = _expected_bdu_id()

    result = bdu.get_bdu_ids_by_cves(
        ["GHSA-1234-5678-9012", "not-a-cve", "BDU:2024-00001", "12345", known_cve_id]
    )

    assert result == {known_cve_id: expected_bdu_id}
    assert "GHSA-1234-5678-9012" not in result
    assert "not-a-cve" not in result
    assert "BDU:2024-00001" not in result
    assert "12345" not in result


def test_get_bdu_ids_by_cves_returns_empty_without_network_for_all_non_cve():
    """All-non-CVE input must return {} immediately without any network call."""
    import unittest.mock as mock

    with mock.patch.object(bdu.requests, "get") as mock_get:
        result = bdu.get_bdu_ids_by_cves(
            ["GHSA-1234-5678-9012", "not-a-cve", "BDU:2024-00001", "", "   "]
        )

    assert result == {}
    mock_get.assert_not_called()