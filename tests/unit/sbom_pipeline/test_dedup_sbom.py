"""Unit tests for component-level SBOM deduplication (dedup_sbom)."""

from __future__ import annotations

import json
from pathlib import Path

from sbom_pipeline.dedup import dedup_sbom


def _run(sbom: dict, tmp_path: Path) -> dict:
    inp = tmp_path / "in.json"
    out = tmp_path / "out.json"
    inp.write_text(json.dumps(sbom), encoding="utf-8")
    dedup_sbom(inp, out)
    return json.loads(out.read_text(encoding="utf-8"))


def test_same_purl_deduped(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r1"},
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r2"},
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 1
    assert result["components"][0]["bom-ref"] == "r1"


def test_purl_with_arch_qualifier_matches_plain_purl(tmp_path):
    """Clair `?arch=` must collapse with generator purl without qualifiers."""
    sbom = {
        "components": [
            {
                "type": "library",
                "name": "curl",
                "version": "8.0",
                "purl": "pkg:deb/debian/curl@8.0",
                "bom-ref": "syft-curl",
            },
            {
                "type": "library",
                "name": "curl",
                "version": "8.0",
                "purl": "pkg:deb/debian/curl@8.0?arch=amd64",
                "bom-ref": "pkg:deb/debian/curl@8.0?arch=amd64",
                "properties": [{"name": "container_image", "value": "img:1"}],
                "cpe": "cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*",
            },
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 1
    kept = result["components"][0]
    assert kept["cpe"].startswith("cpe:")
    assert any(p["name"] == "container_image" for p in kept["properties"])


def test_nopurl_matches_purl_same_name_version(tmp_path):
    sbom = {
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "bom-ref": "with-purl",
            },
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "bom-ref": "no-purl",
                "supplier": {"name": "PSF"},
            },
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 1
    kept = result["components"][0]
    assert kept["purl"] == "pkg:pypi/requests@2.31.0"
    assert kept["supplier"] == {"name": "PSF"}


def test_different_groups_without_purl_kept_separate(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "group": "org.a", "name": "core", "version": "1", "bom-ref": "a"},
            {"type": "library", "group": "org.b", "name": "core", "version": "1", "bom-ref": "b"},
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 2


def test_anonymous_components_not_collapsed(tmp_path):
    sbom = {
        "components": [
            {"type": "file", "bom-ref": "a"},
            {"type": "file", "bom-ref": "b"},
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 2


def test_non_dict_components_preserved(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r1"},
            "not-a-component",
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 2
    assert result["components"][1] == "not-a-component"


def test_conflicting_hashes_retained(tmp_path):
    sbom = {
        "components": [
            {
                "type": "library",
                "name": "a",
                "version": "1",
                "purl": "pkg:pypi/a@1",
                "bom-ref": "r1",
                "hashes": [{"alg": "SHA-256", "content": "aaa"}],
            },
            {
                "type": "library",
                "name": "a",
                "version": "1",
                "purl": "pkg:pypi/a@1",
                "bom-ref": "r2",
                "hashes": [{"alg": "SHA-256", "content": "bbb"}],
            },
        ]
    }
    result = _run(sbom, tmp_path)
    contents = {h["content"] for h in result["components"][0]["hashes"]}
    assert contents == {"aaa", "bbb"}


def test_dependencies_provides_preserved_and_self_edge_removed(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r1"},
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r2"},
        ],
        "dependencies": [
            {"ref": "r2", "dependsOn": ["r1"], "provides": ["cap-a"]},
            {"ref": "app", "dependsOn": ["r1", "r2"]},
        ],
    }
    result = _run(sbom, tmp_path)
    deps = {d["ref"]: d for d in result["dependencies"]}
    assert "r2" not in deps
    assert deps["r1"]["provides"] == ["cap-a"]
    assert "dependsOn" not in deps["r1"]  # self-edge r2→r1 collapsed away
    assert deps["app"]["dependsOn"] == ["r1"]


def test_compositions_refs_remapped(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r1"},
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r2"},
        ],
        "compositions": [
            {"assemblies": ["r2"], "dependencies": ["r1", "r2"]},
        ],
    }
    result = _run(sbom, tmp_path)
    comp = result["compositions"][0]
    assert comp["assemblies"] == ["r1"]
    assert comp["dependencies"] == ["r1"]


def test_vulnerability_affects_remapped(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r1"},
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "bom-ref": "r2"},
        ],
        "vulnerabilities": [
            {"id": "CVE-1", "affects": [{"ref": "r2"}]},
        ],
    }
    result = _run(sbom, tmp_path)
    assert result["vulnerabilities"][0]["affects"][0]["ref"] == "r1"


def test_different_purls_same_name_version_kept_separate(tmp_path):
    sbom = {
        "components": [
            {"type": "library", "name": "foo", "version": "1.0", "purl": "pkg:pypi/foo@1.0", "bom-ref": "py"},
            {"type": "library", "name": "foo", "version": "1.0", "purl": "pkg:npm/foo@1.0", "bom-ref": "js"},
        ]
    }
    result = _run(sbom, tmp_path)
    assert len(result["components"]) == 2
